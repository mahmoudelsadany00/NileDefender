#!/usr/bin/env python3
from __future__ import annotations
import time
import re
import json
from typing import Set, List, Dict, Callable, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse, urlencode
from collections import deque

try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait, Select
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        StaleElementReferenceException, NoSuchElementException,
        TimeoutException, WebDriverException,
        ElementNotInteractableException, UnexpectedTagNameException
    )
    from webdriver_manager.firefox import GeckoDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


# ============================================================================
# Known login credentials for common vulnerable web apps
# ============================================================================
KNOWN_CREDENTIALS = [
    {'login': 'bee', 'password': 'bug'},        # bWAPP
    {'login': 'admin', 'password': 'admin'},     # Common default
    {'login': 'admin', 'password': 'password'},  # DVWA, WebGoat
    {'login': 'admin', 'password': ''},          # Some apps
    {'login': 'user', 'password': 'user'},       # Common default
]


BWAPP_SKIP_VALUES = {
    '0',   # separator/header
}


BWAPP_INFRA_FIELDS = {'security_level', 'bug'}


# DVWA pages to skip during vulnerability crawling (infrastructure, not attack surfaces)
DVWA_SKIP_PAGES = {
    'setup.php', 'security.php', 'phpinfo.php', 'about.php',
    'instructions.php', 'PDF/readme.pdf',
}


# Infrastructure form fields for DVWA that should not be treated as vuln parameters
DVWA_INFRA_FIELDS = {'security_level', 'seclev_submit', 'user_token'}


class LocalCrawler:
    
    def __init__(self, base_url: str,
                 max_depth: int = 5,
                 max_pages: int = 500,
                 page_timeout: int = 15,
                 on_endpoint_found: Callable[[Dict], None] = None,
                 on_progress: Callable[[str], None] = None,
                 cancel_check: Callable[[], bool] = None):
        if not SELENIUM_AVAILABLE:
            raise ImportError(
                "Selenium is required for local crawling. "
                "Install it with: pip install selenium"
            )
        
        # Normalize base URL
        self.base_url = base_url.rstrip('/')
        parsed = urlparse(self.base_url)
        self.base_host = parsed.netloc
        self.base_scheme = parsed.scheme or 'http'
        
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.page_timeout = page_timeout
        self.on_endpoint_found = on_endpoint_found
        self.on_progress = on_progress
        self.cancel_check = cancel_check or (lambda: False)
        
        # Tracking
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.endpoint_keys: Set[str] = set()  # Dedup: "METHOD|url|params"
        self.endpoints: List[Dict] = []
        self.forms_found: int = 0
        self.links_found: int = 0
        self.logged_in: bool = False
        self.session_cookies: Dict = {}
        
        # Static file extensions to skip
        self.skip_extensions = {
            '.js', '.mjs', '.jsx', '.ts', '.tsx',
            '.css', '.scss', '.sass', '.less',
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp', '.bmp', '.tiff',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.ogg', '.wav',
            '.zip', '.rar', '.tar', '.gz', '.7z',
            '.map',
        }
        
        # URLs/patterns to skip (logout, reset, etc.)
        self.skip_patterns = [
            r'logout', r'signout', r'sign_out', r'log_out',
            r'reset\.php', r'reset\.asp',
            r'javascript:', r'mailto:', r'tel:', r'#$',
        ]
        
        self.driver = None
        self.app_type = None  # Detected app type: 'bwapp', 'dvwa', or 'generic'
    
    def _log(self, message: str):
        print(message)
        if self.on_progress:
            try:
                self.on_progress(message)
            except:
                pass
    
    def _add_endpoint(self, endpoint: Dict) -> bool:
        # Build dedup key
        method = endpoint.get('method', 'GET')
        url = endpoint.get('url', '')
        params = endpoint.get('parameters') or endpoint.get('body_params') or {}
        param_names = sorted(params.keys()) if isinstance(params, dict) else []
        key = f"{method}|{url}|{','.join(param_names)}"
        
        if key in self.endpoint_keys:
            return False
        
        self.endpoint_keys.add(key)
        
        # Reverse Docker URL translation so stored URLs show localhost
        if 'host.docker.internal' in endpoint.get('url', ''):
            endpoint['url'] = endpoint['url'].replace(
                '://host.docker.internal', '://localhost')
        
        # Always attach session cookies
        if self.session_cookies and 'cookies' not in endpoint:
            endpoint['cookies'] = dict(self.session_cookies)
        
        self.endpoints.append(endpoint)
        
        if self.on_endpoint_found:
            try:
                self.on_endpoint_found(endpoint)
            except Exception as e:
                print(f"[!] Callback error: {e}")
        
        return True
    
    def _init_browser(self):
        self._log("[*] Initializing headless Firefox browser...")
        
        options = FirefoxOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--width=1920')
        options.add_argument('--height=1080')
        
        # Suppress browser logs
        options.log.level = 'fatal'
        
        try:
            service = FirefoxService(GeckoDriverManager().install())
            self.driver = webdriver.Firefox(service=service, options=options)
            self.driver.set_page_load_timeout(self.page_timeout)
            self.driver.implicitly_wait(3)
            self._log("[✓] Browser initialized successfully")
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Firefox browser: {e}\n"
                "Make sure Firefox is installed: sudo apt install firefox-esr"
            )
    
    def _close_browser(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
    
    def _export_cookies(self):
        cookies = {}
        try:
            for cookie in self.driver.get_cookies():
                cookies[cookie['name']] = cookie['value']
        except:
            pass
        self.session_cookies = cookies
        return cookies
    
    def _wait_for_page(self, timeout: int = 5):
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except TimeoutException:
            pass
        # Small extra wait for any JS to settle
        time.sleep(0.3)
    
    # ========================================================================
    # LOGIN HANDLING
    # ========================================================================
    
    def _detect_login_form(self) -> Optional[Dict]:
        try:
            forms = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                inputs = form.find_elements(By.TAG_NAME, 'input')
                has_password = False
                has_text = False
                text_field = None
                pass_field = None
                
                for inp in inputs:
                    input_type = (inp.get_attribute('type') or 'text').lower()
                    name = inp.get_attribute('name') or ''
                    
                    # Skip non-editable input types
                    if input_type in ('submit', 'button', 'hidden', 'image', 'reset'):
                        continue

                    if input_type == 'password':
                        has_password = True
                        pass_field = inp
                    elif input_type in ('text', 'email') or name.lower() in ('login', 'username', 'user', 'email'):
                        has_text = True
                        text_field = inp
                
                if has_password and has_text:
                    return {
                        'form': form,
                        'username_field': text_field,
                        'password_field': pass_field,
                    }
        except:
            pass
        return None

    def _try_login(self) -> bool:
        login_form = self._detect_login_form()
        if not login_form:
            return False
        
        self._log("[*] Login form detected, attempting authentication...")
        
        for creds in KNOWN_CREDENTIALS:
            try:
                # Clear and fill fields
                username_field = login_form['username_field']
                password_field = login_form['password_field']
                
                username_field.clear()
                username_field.send_keys(creds['login'])
                password_field.clear()
                password_field.send_keys(creds['password'])
                
                # Submit the form
                try:
                    submit = login_form['form'].find_element(
                        By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"], button'
                    )
                    submit.click()
                except:
                    login_form['form'].submit()
                
                self._wait_for_page(timeout=5)
                time.sleep(1)
                
                # Check if we're still on a login page
                current_url = self.driver.current_url.lower()
                
                still_on_login = (
                    'login' in current_url and
                    self._detect_login_form() is not None
                )
                
                if not still_on_login:
                    self._log(f"[✓] Login successful with {creds['login']}/{creds['password']}")
                    self.logged_in = True
                    # Export cookies right after successful login
                    self._export_cookies()
                    if self.session_cookies:
                        self._log(f"[✓] Session cookies captured: {list(self.session_cookies.keys())}")
                    return True
                else:
                    self._log(f"[!] Login failed with {creds['login']}/{creds['password']}")
                    # Go back and retry
                    self.driver.back()
                    time.sleep(1)
                    login_form = self._detect_login_form()
                    if not login_form:
                        break
                    
            except Exception as e:
                self._log(f"[!] Login attempt error: {e}")
                try:
                    self.driver.get(self.base_url)
                    time.sleep(1)
                    login_form = self._detect_login_form()
                    if not login_form:
                        break
                except:
                    break
        
        self._log("[!] Could not login automatically")
        return False
    
    # ========================================================================
    # APP DETECTION & MULTI-APP NAVIGATION
    # ========================================================================
    
    def _detect_app_type(self) -> str:
        """Detect which web application we're scanning based on page signals.
        
        Returns 'bwapp', 'dvwa', or 'generic'.
        """
        try:
            current_url = self.driver.current_url.lower()
            page_source = self.driver.page_source or ''
            page_title = (self.driver.title or '').lower()
            
            # --- Check for bWAPP ---
            if 'bwapp' in current_url or 'portal.php' in current_url:
                self._log("[✓] Detected application: bWAPP (URL match)")
                return 'bwapp'
            try:
                self.driver.find_element(By.CSS_SELECTOR, 'select[name="bug"]')
                self._log("[✓] Detected application: bWAPP (dropdown found)")
                return 'bwapp'
            except (NoSuchElementException, Exception):
                pass
            
            # --- Check for DVWA ---
            if 'dvwa' in current_url or 'dvwa' in page_title:
                self._log("[✓] Detected application: DVWA (URL/title match)")
                return 'dvwa'
            if 'damn vulnerable web application' in page_title:
                self._log("[✓] Detected application: DVWA (title match)")
                return 'dvwa'
            # Check for DVWA-specific sidebar
            try:
                sidebar = self.driver.find_element(By.ID, 'main_menu_padded')
                if sidebar:
                    self._log("[✓] Detected application: DVWA (sidebar found)")
                    return 'dvwa'
            except (NoSuchElementException, Exception):
                pass
            # Check for DVWA header/logo
            if 'dvwa' in page_source.lower()[:2000]:
                self._log("[✓] Detected application: DVWA (source match)")
                return 'dvwa'
            
            self._log("[*] Application type: generic (no specific app detected)")
            return 'generic'
        except Exception as e:
            self._log(f"[!] App detection error: {e}")
            return 'generic'
    
    def _extract_sidebar_links(self, current_url: str) -> List[str]:
        """Extract navigation links from DVWA's sidebar menu.
        
        DVWA's navigation is in a <ul> menu inside <div id="main_menu_padded">
        or a similar sidebar container.
        """
        urls = []
        try:
            self._log("[*] Extracting DVWA sidebar navigation links...")
            
            # Strategy 1: Look for DVWA's specific sidebar container
            sidebar_selectors = [
                '#main_menu_padded ul li a',
                '#main_menu ul li a',
                '.menuBlocks ul li a', 
                '#side_menu a',
                'div.body_padded ~ div ul li a',  # fallback structural
            ]
            
            links_found = []
            for selector in sidebar_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements and len(elements) >= 3:  # DVWA has at least ~10 sidebar links
                        links_found = elements
                        self._log(f"    Found sidebar with selector: {selector} ({len(elements)} links)")
                        break
                except:
                    continue
            
            # Strategy 2: Broader fallback — any sidebar-like nav
            if not links_found:
                try:
                    # DVWA wraps its menu in an <ul> inside any sidebar div
                    all_uls = self.driver.find_elements(By.CSS_SELECTOR, 'ul')
                    for ul in all_uls:
                        links_in_ul = ul.find_elements(By.TAG_NAME, 'a')
                        if len(links_in_ul) >= 5:  # Nav menus have several links
                            links_found = links_in_ul
                            self._log(f"    Found nav <ul> with {len(links_in_ul)} links (fallback)")
                            break
                except:
                    pass
            
            if not links_found:
                self._log("[!] No DVWA sidebar navigation found")
                return urls
            
            for element in links_found:
                try:
                    href = element.get_attribute('href')
                    if not href:
                        continue
                    
                    resolved = self._resolve_url(href, current_url)
                    if not resolved:
                        continue
                    
                    # Skip DVWA infrastructure pages
                    parsed_path = urlparse(resolved).path.lower()
                    page_name = parsed_path.split('/')[-1] if '/' in parsed_path else parsed_path
                    
                    # Skip logout, setup, security, about pages
                    skip = False
                    for skip_page in DVWA_SKIP_PAGES:
                        if skip_page.lower() in parsed_path:
                            skip = True
                            break
                    if self._should_skip(resolved):
                        skip = True
                    
                    if not skip and resolved not in urls:
                        urls.append(resolved)
                        
                except StaleElementReferenceException:
                    continue
                except Exception:
                    continue
            
            self._log(f"[✓] Extracted {len(urls)} vulnerability page URLs from DVWA sidebar")
            
        except Exception as e:
            self._log(f"[!] DVWA sidebar extraction error: {e}")
        
        return urls
    
    def _extract_nav_links(self, current_url: str) -> List[str]:
        """Extract navigation links from generic web apps.
        
        Looks for common navigation patterns: <nav>, sidebar divs, 
        <ul> menus with many links, etc.
        """
        urls = []
        try:
            self._log("[*] Extracting generic navigation links...")
            
            nav_selectors = [
                'nav a',
                '[role="navigation"] a',
                '.sidebar a', '.side-menu a', '.sidenav a',
                '#sidebar a', '#side-menu a', '#sidenav a',
                '.menu a', '#menu a', '.nav-menu a',
                '.navbar a', '#navbar a',
            ]
            
            links_found = []
            for selector in nav_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements and len(elements) >= 3:
                        links_found.extend(elements)
                        self._log(f"    Found nav links with selector: {selector} ({len(elements)} links)")
                except:
                    continue
            
            # Fallback: collect all page links
            if not links_found:
                self._log("    No specific nav found, using all page links as seeds")
                return self._extract_links(current_url)
            
            seen = set()
            for element in links_found:
                try:
                    href = element.get_attribute('href')
                    resolved = self._resolve_url(href, current_url)
                    if resolved and not self._should_skip(resolved) and resolved not in seen:
                        seen.add(resolved)
                        urls.append(resolved)
                except:
                    continue
            
            self._log(f"[✓] Extracted {len(urls)} navigation URLs (generic)")
            
        except Exception as e:
            self._log(f"[!] Generic nav extraction error: {e}")
        
        return urls
    
    def _set_dvwa_security_low(self):
        """Set DVWA's security level to 'low' for maximum vulnerability discovery.
        
        DVWA uses a 'security' cookie (values: low, medium, high, impossible).
        This navigates to /security.php, sets the level to 'low', and submits.
        """
        try:
            self._log("[*] Setting DVWA security level to 'low'...")
            
            security_url = f"{self.base_scheme}://{self.base_host}/security.php"
            self.driver.get(security_url)
            self._wait_for_page()
            
            # Check current security level from cookies
            current_cookies = {c['name']: c['value'] for c in self.driver.get_cookies()}
            current_level = current_cookies.get('security', 'unknown')
            self._log(f"    Current security level: {current_level}")
            
            if current_level == 'low':
                self._log("[✓] Security level already set to 'low'")
                return
            
            # Try to use the security form to set it
            try:
                # DVWA security page has a <select name="security"> and submit button
                sel_element = self.driver.find_element(By.CSS_SELECTOR, 'select[name="security"]')
                sel = Select(sel_element)
                sel.select_by_value('low')
                
                # Find and click submit
                submit = self.driver.find_element(
                    By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"]'
                )
                submit.click()
                self._wait_for_page()
                self._log("[✓] Security level set to 'low' via form")
            except Exception:
                # Fallback: set the cookie directly
                self.driver.add_cookie({
                    'name': 'security',
                    'value': 'low',
                    'path': '/',
                })
                self._log("[✓] Security level set to 'low' via cookie injection")
            
            # Refresh cookies
            self._export_cookies()
            
        except Exception as e:
            self._log(f"[!] Failed to set DVWA security level: {e}")
            # Fallback: set cookie directly even if page nav failed
            try:
                self.driver.add_cookie({
                    'name': 'security',
                    'value': 'low',
                    'path': '/',
                })
                self._export_cookies()
                self._log("[✓] Security cookie set via fallback")
            except:
                pass
    
    def _handle_dvwa_setup(self):
        """If DVWA's database hasn't been initialized, click 'Create / Reset Database'."""
        try:
            current_url = self.driver.current_url.lower()
            if 'setup.php' in current_url:
                self._log("[*] DVWA setup page detected, initializing database...")
                try:
                    create_btn = self.driver.find_element(
                        By.CSS_SELECTOR, 'input[type="submit"][value*="Create"], '
                                         'input[type="submit"][value*="Reset"]'
                    )
                    create_btn.click()
                    self._wait_for_page()
                    time.sleep(2)
                    self._log("[✓] DVWA database initialized")
                except NoSuchElementException:
                    self._log("[!] Could not find Create/Reset Database button")
        except Exception as e:
            self._log(f"[!] DVWA setup handling error: {e}")
    
    # ========================================================================
    # URL HELPERS
    # ========================================================================
    
    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip('/')
            if not path:
                path = '/'
            
            normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
            if parsed.query:
                # Sort query params — keep only param names for dedup
                params = sorted(parse_qs(parsed.query).keys())
                normalized += '?' + '&'.join(f"{k}=" for k in params)
            return normalized
        except:
            return url
    
    def _is_same_host(self, url: str) -> bool:
        """Check if URL belongs to the same host as base"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_host
        except:
            return False
    
    def _should_skip(self, url: str) -> bool:
        """Check if URL should be skipped"""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        if any(path_lower.endswith(ext) for ext in self.skip_extensions):
            return True
        
        url_lower = url.lower()
        for pattern in self.skip_patterns:
            if re.search(pattern, url_lower):
                return True
        
        return False
    
    def _resolve_url(self, href: str, current_url: str) -> Optional[str]:
        """Resolve relative URL to absolute, return None if invalid"""
        if not href or href.strip() in ('', '#', 'javascript:void(0)', 'javascript:void(0);'):
            return None
        
        href = href.strip()
        
        if href.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
            return None
        
        full_url = urljoin(current_url, href)
        
        if not self._is_same_host(full_url):
            return None
        
        # Remove fragment
        parsed = urlparse(full_url)
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, parsed.query, ''))
        
        return clean_url
    
    # ========================================================================
    # EXTRACTION METHODS
    # ========================================================================
    
    def _extract_links(self, current_url: str) -> List[str]:
        links = []
        try:
            elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for element in elements:
                try:
                    href = element.get_attribute('href')
                    resolved = self._resolve_url(href, current_url)
                    if resolved and not self._should_skip(resolved):
                        links.append(resolved)
                except StaleElementReferenceException:
                    continue
                except:
                    continue
        except:
            pass
        return links
    
    def _extract_js_links(self, current_url: str) -> List[str]:
        urls = []
        
        # Pattern to find URLs in JS code
        js_url_patterns = [
            r"(?:window|document)\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.replace\(['\"]([^'\"]+)['\"]\)",
            r"location\.assign\(['\"]([^'\"]+)['\"]\)",
            r"window\.open\(['\"]([^'\"]+)['\"]",
            r"\.href\s*=\s*['\"]([^'\"]+\.(?:php|asp|aspx|jsp|html|htm)(?:\?[^'\"]*)?)['\"]",
        ]
        
        try:
            # Check onclick attributes on all clickable elements
            clickable = self.driver.find_elements(
                By.CSS_SELECTOR, '[onclick], [onmouseover], [onsubmit]'
            )
            for el in clickable:
                try:
                    for attr in ('onclick', 'onmouseover', 'onsubmit'):
                        val = el.get_attribute(attr)
                        if val:
                            for pattern in js_url_patterns:
                                matches = re.findall(pattern, val, re.IGNORECASE)
                                for match in matches:
                                    resolved = self._resolve_url(match, current_url)
                                    if resolved and not self._should_skip(resolved):
                                        urls.append(resolved)
                except StaleElementReferenceException:
                    continue
                except:
                    continue
            
            # Check inline <script> tags
            scripts = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in scripts:
                try:
                    src = script.get_attribute('src')
                    if src:
                        continue  # Skip external scripts
                    
                    content = script.get_attribute('innerHTML') or ''
                    if not content:
                        continue
                    
                    for pattern in js_url_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            resolved = self._resolve_url(match, current_url)
                            if resolved and not self._should_skip(resolved):
                                urls.append(resolved)
                except StaleElementReferenceException:
                    continue
                except:
                    continue
        except:
            pass
        
        return urls
    
    def _extract_select_urls(self, current_url: str) -> List[str]:
        urls = []
        try:
            selects = self.driver.find_elements(By.TAG_NAME, 'select')
            for select in selects:
                try:
                    options = select.find_elements(By.TAG_NAME, 'option')
                    for opt in options:
                        val = opt.get_attribute('value') or ''
                        if not val:
                            continue
                        
                        # Direct URL reference (e.g. "/page.php")
                        if val.endswith(('.php', '.asp', '.aspx', '.jsp', '.html', '.htm')):
                            resolved = self._resolve_url(val, current_url)
                            if resolved and not self._should_skip(resolved):
                                urls.append(resolved)
                except:
                    continue
        except:
            pass
        return urls
    
    def _find_select_element(self, select_name: str, select_id: str = '') -> Optional[Select]:
        strategies = []
        if select_id:
            strategies.append((By.ID, select_id))
        if select_name:
            strategies.append((By.NAME, select_name))
            strategies.append((By.CSS_SELECTOR, f'select[name="{select_name}"]'))
        
        for by, value in strategies:
            try:
                element = WebDriverWait(self.driver, 3).until(
                    EC.presence_of_element_located((by, value))
                )
                return Select(element)
            except (TimeoutException, NoSuchElementException, UnexpectedTagNameException):
                continue
            except:
                continue
        
        return None
    
    def _extract_dropdown_pages(self, portal_url: str) -> List[str]:
        urls = []
        
        try:
            # First pass: collect all option values from the dropdown
            self.driver.get(portal_url)
            self._wait_for_page()
            
            option_values = []
            sel = self._find_select_element('bug', 'select_portal')
            if not sel:
                # Try broader search for any select with many options
                selects = self.driver.find_elements(By.TAG_NAME, 'select')
                for s in selects:
                    opts = s.find_elements(By.TAG_NAME, 'option')
                    if len(opts) > 10:  # Navigation dropdown has many options
                        try:
                            sel = Select(s)
                            break
                        except:
                            continue
            
            if not sel:
                self._log("[!] No navigation dropdown found on portal page")
                return urls
            
            # Collect option values and text
            for opt in sel.options:
                try:
                    val = opt.get_attribute('value')
                    text = opt.text.strip()
                    if val and val not in BWAPP_SKIP_VALUES and text:
                        # Skip category headers (they contain "/" like "/ A1 - Injection /")
                        if text.startswith('/') and text.endswith('/'):
                            continue
                        # Skip separator lines
                        if text.startswith('---'):
                            continue
                        option_values.append((val, text))
                except:
                    continue
            
            self._log(f"[*] Found {len(option_values)} vulnerability pages in dropdown")
            
            # Second pass: visit each option
            for i, (val, text) in enumerate(option_values):
                if self.cancel_check():
                    self._log("[!] Scan cancelled during dropdown extraction")
                    break
                try:
                    # Navigate back to portal
                    self.driver.get(portal_url)
                    self._wait_for_page()
                    
                    # Re-find the select element (fresh reference)
                    sel = self._find_select_element('bug', 'select_portal')
                    if not sel:
                        self._log(f"    [!] Lost dropdown reference at option {i+1}, retrying...")
                        time.sleep(1)
                        self.driver.get(portal_url)
                        self._wait_for_page()
                        sel = self._find_select_element('bug', 'select_portal')
                        if not sel:
                            self._log(f"    [!] Could not recover dropdown, skipping remaining")
                            break
                    
                    # Select the option by value
                    try:
                        sel.select_by_value(val)
                    except StaleElementReferenceException:
                        # Element went stale, re-find and retry
                        sel = self._find_select_element('bug', 'select_portal')
                        if sel:
                            sel.select_by_value(val)
                        else:
                            continue
                    
                    # Find and click the submit button ("Hack" button)
                    submitted = False
                    try:
                        # Try multiple button selectors
                        for btn_selector in [
                            'button[type="submit"]',
                            'input[type="submit"]',
                            'button',
                        ]:
                            try:
                                btn = self.driver.find_element(By.CSS_SELECTOR, 
                                    f'form select[name="bug"] ~ {btn_selector}, '
                                    f'form:has(select[name="bug"]) {btn_selector}')
                                btn.click()
                                submitted = True
                                break
                            except:
                                continue
                        
                        if not submitted:
                            # Fallback: find the form containing the select and submit it
                            try:
                                form = sel._el.find_element(By.XPATH, './ancestor::form')
                                form.submit()
                                submitted = True
                            except:
                                pass
                        
                        if not submitted:
                            # Last resort: find any submit on page
                            try:
                                btn = self.driver.find_element(
                                    By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"]')
                                btn.click()
                                submitted = True
                            except:
                                continue
                    except:
                        continue
                    
                    self._wait_for_page()
                    
                    # Capture the destination URL
                    result_url = self.driver.current_url
                    if (result_url != portal_url and 
                        self._is_same_host(result_url) and
                        not self._should_skip(result_url)):
                        if result_url not in urls:
                            urls.append(result_url)
                    
                    # Progress reporting
                    if (i + 1) % 20 == 0:
                        self._log(f"    [{i+1}/{len(option_values)}] Extracted {len(urls)} unique URLs so far...")
                        
                except Exception as e:
                    # Per-option error isolation
                    continue
            
            self._log(f"[✓] Extracted {len(urls)} unique URLs from {len(option_values)} dropdown options")
            
        except Exception as e:
            self._log(f"[!] Dropdown extraction error: {e}")
        
        return urls
    
    def _extract_forms(self, current_url: str) -> List[Dict]:
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            
            for form in form_elements:
                try:
                    action = form.get_attribute('action') or ''
                    method = (form.get_attribute('method') or 'GET').upper()
                    enctype = form.get_attribute('enctype') or 'application/x-www-form-urlencoded'
                    form_id = form.get_attribute('id') or ''
                    form_class = form.get_attribute('class') or ''
                    
                    # Resolve form action URL
                    if action:
                        form_url = urljoin(current_url, action)
                    else:
                        form_url = current_url
                    
                    # Skip forms that post to login/logout/reset
                    if self._should_skip(form_url):
                        continue
                    
                    # Extract input fields
                    params = {}
                    input_elements = form.find_elements(By.CSS_SELECTOR,
                        'input, textarea, select, button')
                    
                    for inp in input_elements:
                        try:
                            name = inp.get_attribute('name')
                            if not name:
                                continue
                            
                            tag = inp.tag_name.lower()
                            input_type = (inp.get_attribute('type') or 'text').lower()
                            value = inp.get_attribute('value') or ''
                            placeholder = inp.get_attribute('placeholder') or ''
                            
                            # Skip reset and image inputs
                            if input_type in ('image', 'reset'):
                                continue
                            

                            if input_type in ('submit', 'button'):
                                if not name or name.startswith('form_'):
                                    continue
                            
                            param_info = {
                                'type': input_type if tag == 'input' else tag,
                                'value': value,
                                'placeholder': placeholder
                            }
                            
                            # For select elements, capture available options
                            if tag == 'select':
                                try:
                                    options = inp.find_elements(By.TAG_NAME, 'option')
                                    option_values = []
                                    for opt in options:
                                        opt_val = opt.get_attribute('value')
                                        if opt_val:
                                            option_values.append(opt_val)
                                    if option_values:
                                        param_info['options'] = option_values
                                        param_info['value'] = option_values[0] if not value else value
                                except:
                                    pass
                            
                            # For file inputs, mark as file upload
                            if input_type == 'file':
                                param_info['is_file'] = True
                            
                            params[name] = param_info
                        except StaleElementReferenceException:
                            continue
                        except:
                            continue
                    
                    # Only add forms that have actual parameters
                    if params:
                        # Skip forms that only contain infrastructure params
                        infra_fields = BWAPP_INFRA_FIELDS | DVWA_INFRA_FIELDS
                        real_params = {k for k in params if k not in infra_fields}
                        if not real_params:
                            continue
                        
                        form_data = {
                            'url': form_url,
                            'method': method,
                            'params': params,
                            'enctype': enctype,
                            'form_id': form_id,
                            'form_class': form_class
                        }
                        forms.append(form_data)
                    
                except StaleElementReferenceException:
                    continue
                except Exception as e:
                    continue
                    
        except Exception as e:
            pass
        
        return forms
    
    def _extract_iframe_links(self, current_url: str) -> List[str]:
        """Extract links from iframe content"""
        urls = []
        try:
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            for iframe in iframes:
                try:
                    src = iframe.get_attribute('src')
                    if src:
                        resolved = self._resolve_url(src, current_url)
                        if resolved and not self._should_skip(resolved):
                            urls.append(resolved)
                    
                    # Switch into iframe to extract its links
                    self.driver.switch_to.frame(iframe)
                    iframe_links = self._extract_links(current_url)
                    urls.extend(iframe_links)
                    self.driver.switch_to.default_content()
                except:
                    try:
                        self.driver.switch_to.default_content()
                    except:
                        pass
                    continue
        except:
            pass
        return urls
    
    def _extract_url_params(self, url: str) -> Optional[Dict]:
        """Extract GET parameters from a URL's query string"""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        return None
    
    # ========================================================================
    # PAGE PROCESSING
    # ========================================================================
    
    def _process_page(self, url: str) -> Dict:
        """Visit a page and extract all endpoints.
        
        Error-isolated: exceptions here won't stop the overall crawl.
        """
        result = {
            'url': url,
            'links': 0,
            'forms': 0,
            'endpoints_added': 0,
            'js_links': 0,
            'discovered_links': []  # All links found on this page
        }
        
        try:
            self.driver.get(url)
            self._wait_for_page()
            
            # Check if we got redirected to login
            current = self.driver.current_url
            if 'login' in current.lower() and current != url:
                login_ok = self._try_login()
                if login_ok:
                    # Retry the original URL
                    self.driver.get(url)
                    self._wait_for_page()
                else:
                    result['error'] = 'Login required but auto-login failed'
                    return result
            
            # Refresh cookies after each page (they may change)
            self._export_cookies()
            
            # Get page title
            try:
                title = self.driver.title or ''
            except:
                title = ''
            result['title'] = title
            
            # ---- Extract links ----
            links = self._extract_links(url)
            result['links'] = len(links)
            self.links_found += len(links)
            
            for link in links:
                normalized = self._normalize_url(link)
                if normalized not in self.discovered_urls:
                    self.discovered_urls.add(normalized)
                    
                    # Check for URL parameters
                    url_params = self._extract_url_params(link)
                    if url_params:
                        self._add_endpoint({
                            'url': link.split('?')[0],
                            'method': 'GET',
                            'parameters': url_params,
                            'body_params': None,
                            'extra_headers': {},
                            'source': 'selenium_crawler',
                            'form_details': None,
                            'page_title': title
                        })
                        result['endpoints_added'] += 1
            
            # ---- Extract JavaScript links ----
            js_links = self._extract_js_links(url)
            result['js_links'] = len(js_links)
            
            for link in js_links:
                normalized = self._normalize_url(link)
                if normalized not in self.discovered_urls:
                    self.discovered_urls.add(normalized)
                    url_params = self._extract_url_params(link)
                    if url_params:
                        self._add_endpoint({
                            'url': link.split('?')[0],
                            'method': 'GET',
                            'parameters': url_params,
                            'body_params': None,
                            'extra_headers': {},
                            'source': 'selenium_crawler_js',
                            'form_details': None,
                            'page_title': title
                        })
                        result['endpoints_added'] += 1
            
            # ---- Extract iframe links ----
            iframe_links = self._extract_iframe_links(url)
            for link in iframe_links:
                normalized = self._normalize_url(link)
                if normalized not in self.discovered_urls:
                    self.discovered_urls.add(normalized)
            
            # Store all discovered links for the caller (avoids double extraction)
            result['discovered_links'] = links + js_links + iframe_links
            
            # ---- Extract forms ----
            forms = self._extract_forms(url)
            result['forms'] = len(forms)
            self.forms_found += len(forms)
            
            for form_data in forms:
                method = form_data['method']
                
                if method == 'POST':
                    added = self._add_endpoint({
                        'url': form_data['url'],
                        'method': 'POST',
                        'parameters': None,
                        'body_params': form_data['params'],
                        'extra_headers': {},
                        'source': 'selenium_crawler',
                        'form_details': {
                            'enctype': form_data['enctype'],
                            'id': form_data['form_id'],
                            'class': form_data['form_class']
                        },
                        'page_title': title
                    })
                else:
                    added = self._add_endpoint({
                        'url': form_data['url'],
                        'method': 'GET',
                        'parameters': form_data['params'],
                        'body_params': None,
                        'extra_headers': {},
                        'source': 'selenium_crawler',
                        'form_details': {
                            'enctype': form_data['enctype'],
                            'id': form_data['form_id'],
                            'class': form_data['form_class']
                        },
                        'page_title': title
                    })
                
                if added:
                    result['endpoints_added'] += 1
            
            # ---- Register the page itself as a GET endpoint ----
            page_url_clean = url.split('?')[0]
            self._add_endpoint({
                'url': page_url_clean,
                'method': 'GET',
                'parameters': self._extract_url_params(url),
                'body_params': None,
                'extra_headers': {},
                'source': 'selenium_crawler',
                'form_details': None,
                'page_title': title
            })
            
        except TimeoutException:
            result['error'] = 'Page load timeout'
        except WebDriverException as e:
            result['error'] = f'WebDriver error: {str(e)[:100]}'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    # ========================================================================
    # MAIN CRAWL
    # ========================================================================
    
    def crawl(self) -> List[Dict]:
        """
        BFS crawl the local application.
        
        Flow:
        1. Open browser, navigate to base URL
        2. Detect and handle login if needed
        3. Detect app type (bWAPP, DVWA, generic)
        4. Extract navigation URLs based on app type
        5. BFS crawl all discovered pages
        6. Extract forms and parameters from each page
        7. Export session cookies with all endpoints
        
        Returns:
            List of discovered endpoint dictionaries
        """
        self._log(f"\n[+] Starting Local Machine Crawl (v3 — Multi-App Support)")
        self._log("=" * 70)
        self._log(f"    Target: {self.base_url}")
        self._log(f"    Max Depth: {self.max_depth}")
        self._log(f"    Max Pages: {self.max_pages}")
        
        try:
            self._init_browser()
            
            # Step 1: Navigate to base URL
            self._log(f"\n[*] Loading {self.base_url}")
            self.driver.get(self.base_url)
            self._wait_for_page()
            
            # Step 1.5: Handle DVWA setup page (database not initialized)
            self._handle_dvwa_setup()
            
            # Step 2: Handle login if needed
            current_url = self.driver.current_url
            login_form = self._detect_login_form()
            if login_form:
                self._try_login()
            
            # Step 3: Export session cookies after login
            self._export_cookies()
            if self.session_cookies:
                self._log(f"[✓] Active session cookies: {list(self.session_cookies.keys())}")
            
            # Step 4: Detect which application we're scanning
            current_url = self.driver.current_url
            self.app_type = self._detect_app_type()
            
            # Step 5: Extract navigation URLs based on app type
            nav_urls = []
            direct_select_urls = []
            
            if self.app_type == 'dvwa':
                # ---- DVWA path ----
                self._log(f"\n[*] Phase 1: DVWA Sidebar Navigation on {current_url}")
                
                # Set security level to 'low' for maximum vulnerability discovery
                self._set_dvwa_security_low()
                
                # Add DVWA-specific skip patterns
                for skip_page in DVWA_SKIP_PAGES:
                    self.skip_patterns.append(re.escape(skip_page))
                
                # Navigate back to main page after setting security
                self.driver.get(self.base_url)
                self._wait_for_page()
                current_url = self.driver.current_url
                
                nav_urls = self._extract_sidebar_links(current_url)
                
            elif self.app_type == 'bwapp':
                # ---- bWAPP path (existing logic) ----
                self._log(f"\n[*] Phase 1: bWAPP Dropdown Interaction on {current_url}")
                
                portal_url = current_url
                nav_urls = self._extract_dropdown_pages(portal_url)
                
                if not nav_urls:
                    for portal_path in ['/portal.php', '/bWAPP/portal.php', '/bwapp/portal.php']:
                        try:
                            test_url = f"{self.base_scheme}://{self.base_host}{portal_path}"
                            self.driver.get(test_url)
                            self._wait_for_page()
                            if 'portal' in self.driver.current_url.lower():
                                portal_url = self.driver.current_url
                                nav_urls = self._extract_dropdown_pages(portal_url)
                                if nav_urls:
                                    break
                        except:
                            continue
                
                # Also try direct URL extraction from selects
                self.driver.get(portal_url)
                self._wait_for_page()
                direct_select_urls = self._extract_select_urls(portal_url)
                
            else:
                # ---- Generic path ----
                self._log(f"\n[*] Phase 1: Generic Navigation Extraction on {current_url}")
                nav_urls = self._extract_nav_links(current_url)
            
            # Step 6: BFS crawl
            self._log(f"\n[*] Phase 2: BFS Crawling all discovered pages")
            queue = deque()
            
            # Seed the queue with base URL
            queue.append((self.base_url, 0))
            self.discovered_urls.add(self._normalize_url(self.base_url))
            
            # Add current URL (might be portal/index after login)
            if current_url != self.base_url:
                queue.append((current_url, 0))
                self.discovered_urls.add(self._normalize_url(current_url))
            
            # Add navigation-discovered URLs at depth 1 (these are the key finds!)
            for url in nav_urls + direct_select_urls:
                normalized = self._normalize_url(url)
                if normalized not in self.discovered_urls:
                    self.discovered_urls.add(normalized)
                    queue.append((url, 1))
            
            if nav_urls:
                self._log(f"[✓] Seeded {len(nav_urls)} URLs from {self.app_type} navigation")
            if direct_select_urls:
                self._log(f"[✓] Seeded {len(direct_select_urls)} URLs from direct select extraction")
            
            pages_visited = 0
            
            while queue and pages_visited < self.max_pages:
                if self.cancel_check():
                    self._log("[!] Scan cancelled — stopping BFS crawl")
                    break
                
                url, depth = queue.popleft()
                
                normalized = self._normalize_url(url)
                if normalized in self.visited_urls:
                    continue
                
                if depth > self.max_depth:
                    continue
                
                self.visited_urls.add(normalized)
                pages_visited += 1
                
                self._log(f"[*] [{pages_visited}/{self.max_pages}] "
                         f"Depth {depth}: {url}")
                
                # Process the page (error-isolated)
                result = self._process_page(url)
                
                if result.get('error'):
                    self._log(f"    [!] Error: {result['error']}")
                else:
                    parts = [f"Links: {result['links']}"]
                    if result.get('js_links', 0) > 0:
                        parts.append(f"JS Links: {result['js_links']}")
                    parts.append(f"Forms: {result['forms']}")
                    parts.append(f"Endpoints: {result['endpoints_added']}")
                    self._log(f"    [✓] {', '.join(parts)}")
                
                # Add new links to queue (use links already extracted by _process_page)
                if depth < self.max_depth and not result.get('error'):
                    for link in result.get('discovered_links', []):
                        link_normalized = self._normalize_url(link)
                        if (link_normalized not in self.visited_urls and
                            link_normalized not in self.discovered_urls and
                            not self._should_skip(link)):
                            self.discovered_urls.add(link_normalized)
                            queue.append((link, depth + 1))
            
            # Summary
            summary = self.get_summary()
            summary['pages_visited'] = pages_visited
            
            self._log(f"\n[✓] Local Crawl Complete")
            self._log(f"    Pages visited: {pages_visited}")
            self._log(f"    Total links found: {self.links_found}")
            self._log(f"    Total forms found: {self.forms_found}")
            self._log(f"    Total endpoints: {summary['total_endpoints']}")
            self._log(f"    GET endpoints: {summary['get_endpoints']}")
            self._log(f"    POST endpoints: {summary['post_endpoints']}")
            self._log(f"    Endpoints with parameters: {summary['endpoints_with_params']}")
            if self.session_cookies:
                self._log(f"    Session cookies: {list(self.session_cookies.keys())}")
            self._log("=" * 70)
            
        except Exception as e:
            self._log(f"[!] Crawl error: {e}")
            import traceback
            traceback.print_exc()
            raise
        
        finally:
            self._close_browser()
        
        return self.endpoints
    
    def get_summary(self) -> Dict:
        """Get crawl summary statistics"""
        param_endpoints = sum(
            1 for e in self.endpoints 
            if (e.get('parameters') and isinstance(e.get('parameters'), dict) and len(e['parameters']) > 0)
            or (e.get('body_params') and isinstance(e.get('body_params'), dict) and len(e['body_params']) > 0)
        )
        
        return {
            'pages_visited': len(self.visited_urls),
            'total_links': self.links_found,
            'total_forms': self.forms_found,
            'total_endpoints': len(self.endpoints),
            'get_endpoints': sum(1 for e in self.endpoints if e['method'] == 'GET'),
            'post_endpoints': sum(1 for e in self.endpoints if e['method'] == 'POST'),
            'endpoints_with_params': param_endpoints,
            'session_cookies': list(self.session_cookies.keys()) if self.session_cookies else [],
        }


def is_local_target(target: str) -> bool:
    clean = target.strip().lower()
    if not clean.startswith(('http://', 'https://')):
        clean = 'http://' + clean
    
    try:
        parsed = urlparse(clean)
        hostname = parsed.hostname or ''
        
        # Obvious local targets
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0',
                        'host.docker.internal'):
            return True
        
        # Private IP ranges
        if hostname.startswith('192.168.'):
            return True
        if hostname.startswith('10.'):
            return True
        if hostname.startswith('172.'):
            try:
                second_octet = int(hostname.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except:
                pass
        
        # Hostname without dots = Docker container name or local hostname
        if '.' not in hostname:
            return True
        
        return False
    except:
        return False


# ============================================================================
# QUICK LOGIN — standalone function for getting session cookies without crawl
# ============================================================================

def quick_login(target_url: str, on_progress=None) -> str:
    """Quick login using LocalCrawler's existing auth logic.
    
    Launches a headless browser, navigates to the target, detects a login form,
    tries known credentials, and returns the session cookies as a string.
    For DVWA targets, automatically sets security level to 'low'.
    
    Args:
        target_url: Target URL (e.g. http://localhost/bWAPP/login.php)
        on_progress: Optional callback(message) for progress updates
        
    Returns:
        Cookie string for sqlmap (e.g. "PHPSESSID=abc; security=low")
        or None if login fails or no login form is found.
    """
    if not SELENIUM_AVAILABLE:
        return None
    
    crawler = LocalCrawler(base_url=target_url, on_progress=on_progress)
    try:
        crawler._init_browser()
        crawler.driver.get(target_url)
        crawler._wait_for_page()
        
        # Handle DVWA setup page if needed
        crawler._handle_dvwa_setup()
        
        # Attempt login if a form is detected
        if crawler._detect_login_form():
            crawler._try_login()
        
        # Detect app type and set DVWA security to low if applicable
        crawler.app_type = crawler._detect_app_type()
        if crawler.app_type == 'dvwa':
            crawler._set_dvwa_security_low()
            crawler._log("[✓] DVWA detected — security level forced to 'low' for vuln scanning")
        
        # Export cookies (works whether login happened or page had existing session)
        crawler._export_cookies()
        if crawler.session_cookies:
            cookie_str = '; '.join(f"{k}={v}" for k, v in crawler.session_cookies.items())
            crawler._log(f"[✓] Quick login: Session cookies: {list(crawler.session_cookies.keys())}")
            return cookie_str
        
        crawler._log("[*] Quick login: No cookies available")
        return None
        
    except Exception as e:
        crawler._log(f"[!] Quick login error: {e}")
        return None
    finally:
        crawler._close_browser()

