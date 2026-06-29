#!/usr/bin/env python3

import subprocess
import requests
import json
import sys
import argparse
from typing import Set, List, Dict, Callable, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from pathlib import Path
import concurrent.futures
from bs4 import BeautifulSoup
import re


class URLCrawler:
    def __init__(self, alive_urls: List[str] = None,
                 threads: int = 10,
                 on_endpoint_found: Callable[[Dict], None] = None,
                 cancel_check: Callable[[], bool] = None):
        self.alive_urls = set(alive_urls or [])
        self.threads = threads
        self.on_endpoint_found = on_endpoint_found
        self.cancel_check = cancel_check or (lambda: False)
        
        self.urls: Set[str] = set()
        self.urls_with_params: Set[str] = set()
        self.endpoints: List[Dict] = []
        
        # Static file extensions to skip
        self.skip_extensions = {
            # JavaScript
            '.js', '.mjs', '.jsx', '.ts', '.tsx',
            # CSS/Styles
            '.css', '.scss', '.sass', '.less',
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp', '.bmp', '.tiff',
            # Fonts
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            # Media
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.ogg', '.wav',
            # Archives
            '.zip', '.rar', '.tar', '.gz', '.7z',
            # Maps/Source
            '.map', '.min.js', '.min.css',
            # Other
            '.xml', '.rss', '.atom'
        }
    
    def _notify_endpoint(self, endpoint: Dict):
        if self.on_endpoint_found:
            try:
                # Normalize URL for storage
                if endpoint.get('url') and 'host.docker.internal' in endpoint['url']:
                    endpoint['url'] = endpoint['url'].replace('://host.docker.internal', '://localhost')
                
                self.on_endpoint_found(endpoint)
            except Exception as e:
                print(f"[!] Callback error: {e}")
    
    # ========================================================================
    # URL CRAWLING METHODS
    # ========================================================================
    
    def crawl_urls(self) -> Set[str]:
        print(f"\n[+] Starting URL Crawling")
        print("=" * 70)
        
        if not self.alive_urls:
            print("[!] No alive URLs to crawl")
            return set()
        
        if self.cancel_check():
            print("[!] Scan cancelled before URL crawling")
            return self.urls
        
        # Passive discovery
        self._crawl_wayback()
        
        if self.cancel_check():
            print("[!] Scan cancelled after wayback crawl")
            return self.urls
        
        # Active crawling
        self._crawl_active()
        
        if self.cancel_check():
            print("[!] Scan cancelled after active crawl")
            return self.urls
        
        # Path discovery
        self._crawl_common_paths()
        
        print(f"\n[✓] Crawling Complete: {len(self.urls)} URLs found")
        print(f"[✓] URLs with parameters: {len(self.urls_with_params)}")
        return self.urls
    
    def _crawl_wayback(self):
        print("[*] Querying Wayback Machine...")
        
        for url in list(self.alive_urls)[:10]:  # Limit to avoid timeout
            if self.cancel_check():
                print("[!] Scan cancelled during wayback crawl")
                return
            try:
                domain = urlparse(url).netloc
                wayback_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
                
                response = requests.get(wayback_url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    before_count = len(self.urls)
                    for entry in data[1:]:
                        if len(entry) > 2:
                            historical_url = entry[2]
                            # Use _add_url for filtering and deduplication
                            self._add_url(historical_url)
                    
                    added = len(self.urls) - before_count
                    if added > 0:
                        print(f"    [✓] Found {added} valid URLs for {domain}")
            except:
                pass
    
    def _crawl_active(self):
        print("[*] Active crawling...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._crawl_page, url): url 
                      for url in self.alive_urls}
            
            for future in concurrent.futures.as_completed(futures):
                if self.cancel_check():
                    executor.shutdown(wait=False, cancel_futures=True)
                    print("[!] Scan cancelled during active crawl")
                    return
                result = future.result()
                if result and result.get('links', 0) > 0:
                    print(f"    [✓] {result['url']}: {result['links']} links, {result.get('forms', 0)} forms")
    
    def _crawl_page(self, base_url: str) -> Dict:
        try:
            response = requests.get(base_url, timeout=10, verify=False, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links_found = 0
            forms_found = 0
            
            # Extract links (GET endpoints)
            for tag in soup.find_all('a', href=True):
                href = tag.get('href')
                if href:
                    full_url = urljoin(base_url, href)
                    if self._is_valid_url(full_url, base_url):
                        normalized = self._normalize_url(full_url)
                        if normalized not in self.urls:
                            self.urls.add(normalized)
                            links_found += 1
                            if '?' in normalized:
                                self.urls_with_params.add(normalized)
            
            # Extract forms (GET & POST endpoints)
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                full_url = urljoin(base_url, action) if action else base_url
                
                if self._is_valid_url(full_url, base_url):
                    normalized = self._normalize_url(full_url)
                    if normalized not in self.urls:
                        self.urls.add(normalized)
                        forms_found += 1
                    
                    # Extract form parameters
                    params = {}
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name')
                        if name:
                            input_type = input_tag.get('type', 'text')
                            value = input_tag.get('value', '')
                            params[name] = {
                                'type': input_type,
                                'value': value,
                                'required': input_tag.has_attr('required')
                            }
                    
                    if params:
                        endpoint = {
                            'url': full_url,
                            'method': method,
                            'parameters': params if method == 'GET' else None,
                            'body_params': params if method == 'POST' else None,
                            'extra_headers': {},
                            'source': 'form_crawler',
                            'form_details': {
                                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                                'id': form.get('id'),
                                'class': form.get('class')
                            }
                        }
                        self.endpoints.append(endpoint)
                        self._notify_endpoint(endpoint)
                        
                        if method == 'POST':
                            print(f"    [!] POST endpoint found: {full_url}")
            
            # Skip extracting script sources - they're static files
            # for script in soup.find_all('script', src=True):
            #     script_url = urljoin(base_url, script['src'])
            #     if self._is_valid_url(script_url, base_url):
            #         self.urls.add(script_url)
            
            return {'url': base_url, 'links': links_found, 'forms': forms_found}
            
        except Exception as e:
            return {'url': base_url, 'links': 0, 'forms': 0, 'error': str(e)}
    
    def _crawl_common_paths(self):
        print("[*] Checking common paths...")
        
        common_paths = [
            '/admin', '/login', '/api', '/dashboard', '/upload', '/search',
            '/contact', '/profile', '/settings', '/logout', '/register',
            '/api/v1', '/api/v2', '/graphql', '/rest', '/swagger',
            '/admin/login', '/user/login', '/wp-admin', '/phpmyadmin',
            '/api/users', '/api/login', '/api/register', '/api/auth'
        ]
        
        found_count = 0
        for base_url in list(self.alive_urls)[:5]:  # Limit to avoid too many requests
            if self.cancel_check():
                print("[!] Scan cancelled during common path check")
                return
            for path in common_paths:
                if self.cancel_check():
                    return
                url = urljoin(base_url, path)
                try:
                    response = requests.head(url, timeout=5, verify=False, allow_redirects=True)
                    if response.status_code < 500:
                        # Use _add_url for normalization and check if it's new
                        normalized = self._normalize_url(url)
                        if normalized not in self.urls:
                            self._add_url(url)
                            found_count += 1
                except:
                    pass
        
        if found_count > 0:
            print(f"    [✓] Found {found_count} common paths")
    
    
    def _check_and_crawl(self, url: str, base_url: str) -> bool:
        try:
            # Determine if we should treat it as success
            # We use GET to potentially trigger forms/response bodies
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            
            # 200-399 are good. 401/403 are also "found" but maybe not crawlable.
            if response.status_code < 404:
                normalized = self._normalize_url(url)
                
                # Add to URLs list
                if normalized not in self.urls:
                    self.urls.add(normalized)
                    
                    # If it has parameters, track them!
                    if '?' in normalized:
                        self.urls_with_params.add(normalized)
                    
                    self._crawl_page(url)
                    
                    # Create generic endpoint entry immediately
                    endpoint = {
                        'url': url,
                        'method': 'GET',
                        'parameters': None, # extract_parameters will handle query params later
                        'body_params': None,
                        'extra_headers': {},
                        'source': 'common_path',
                        'form_details': None
                    }
                    self.endpoints.append(endpoint)
                    self._notify_endpoint(endpoint)
                    return True
        except:
            pass
        return False
    
    def _is_valid_url(self, url: str, base_url: str) -> bool:
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(base_url)
            
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Must be same domain
            if parsed.netloc != base_parsed.netloc:
                return False
            
            # Skip static file extensions
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in self.skip_extensions):
                return False
            
            # Skip common static directories
            static_dirs = ['/static/', '/assets/', '/images/', '/img/', '/css/', '/js/', 
                          '/fonts/', '/media/', '/uploads/', '/vendor/', '/node_modules/',
                          '/dist/', '/build/', '/.well-known/']
            if any(d in path_lower for d in static_dirs):
                return False
            
            return True
        except:
            return False
    
    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            # Remove trailing slash, fragment, and normalize
            path = parsed.path.rstrip('/')
            if not path:
                path = '/'
            normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
            if parsed.query:
                # Sort query params for consistent comparison
                params = sorted(parse_qs(parsed.query).items())
                normalized += '?' + '&'.join(f"{k}={v[0]}" for k, v in params)
            return normalized
        except:
            return url
    
    def _add_url(self, url: str):
        if not self._is_valid_url(url, url):
            return
        normalized = self._normalize_url(url)
        if normalized not in self.urls:
            self.urls.add(normalized)
            if '?' in normalized:
                self.urls_with_params.add(normalized)
    
    # ========================================================================
    # PARAMETER EXTRACTION
    # ========================================================================
    
    def extract_parameters(self) -> List[Dict]:
        if self.cancel_check():
            print("[!] Scan cancelled before parameter extraction")
            return self.endpoints
        
        print(f"\n[+] Extracting Parameters")
        print("=" * 70)
        
        for url in self.urls_with_params:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                endpoint = {
                    'url': url,
                    'method': 'GET',
                    'parameters': {k: v[0] if len(v) == 1 else v for k, v in params.items()},
                    'body_params': None,
                    'extra_headers': {},
                    'source': 'url_parser'
                }
                self.endpoints.append(endpoint)
                self._notify_endpoint(endpoint)
        
        print(f"[✓] Extracted {len(self.endpoints)} endpoints")
        print(f"    GET endpoints: {sum(1 for e in self.endpoints if e['method'] == 'GET')}")
        print(f"    POST endpoints: {sum(1 for e in self.endpoints if e['method'] == 'POST')}")
        return self.endpoints
    
    # ========================================================================
    # EXPORT METHODS
    # ========================================================================
    
    def export_urls(self, output_file: str = "urls.txt"):
        try:
            with open(output_file, 'w') as f:
                for url in sorted(self.urls):
                    f.write(f"{url}\n")
            print(f"[✓] All URLs: {output_file}")
        except Exception as e:
            print(f"[!] Export error: {e}")
    
    def export_urls_with_params(self, output_file: str = "urls_with_params.txt"):
        try:
            with open(output_file, 'w') as f:
                for url in sorted(self.urls_with_params):
                    f.write(f"{url}\n")
            print(f"[✓] URLs with params: {output_file}")
        except Exception as e:
            print(f"[!] Export error: {e}")
    
    def export_endpoints_json(self, output_file: str = "endpoints.json"):
        try:
            with open(output_file, 'w') as f:
                json.dump(self.endpoints, f, indent=2)
            print(f"[✓] Endpoints JSON: {output_file}")
        except Exception as e:
            print(f"[!] Export error: {e}")
    
    def display_summary(self):
        print(f"\n{'='*70}")
        print("URL CRAWLING SUMMARY")
        print(f"{'='*70}")
        print(f"Alive URLs Input: {len(self.alive_urls)}")
        print(f"Total URLs: {len(self.urls)}")
        print(f"URLs with Params: {len(self.urls_with_params)}")
        print(f"Total Endpoints: {len(self.endpoints)}")
        print(f"  └─ GET: {sum(1 for e in self.endpoints if e['method'] == 'GET')}")
        print(f"  └─ POST: {sum(1 for e in self.endpoints if e['method'] == 'POST')}")
        print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(description="NileDefender - URL Crawler")
    parser.add_argument('-f', '--file', required=True, help='File with alive URLs')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Threads')
    parser.add_argument('-o', '--output-dir', default='.', help='Output directory')
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Read alive URLs from file
    alive_urls = []
    if Path(args.file).exists():
        with open(args.file, 'r') as f:
            alive_urls = [line.strip() for line in f if line.strip()]
    
    crawler = URLCrawler(alive_urls=alive_urls, threads=args.threads)
    crawler.crawl_urls()
    crawler.extract_parameters()
    crawler.display_summary()
    
    crawler.export_urls(str(output_dir / "urls.txt"))
    crawler.export_urls_with_params(str(output_dir / "urls_with_params.txt"))
    crawler.export_endpoints_json(str(output_dir / "endpoints.json"))


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
