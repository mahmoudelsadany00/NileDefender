#!/usr/bin/env python3

import subprocess
import requests
import json
import sys
import argparse
import configparser
from typing import Set, List, Dict, Callable, Optional
from urllib.parse import urlparse
from pathlib import Path
import dns.resolver
import concurrent.futures
from datetime import datetime
from bs4 import BeautifulSoup


class SubdomainEnumerator:
    def __init__(self, domain: str, config_file: str = "config.ini",
                 on_subdomain_found: Callable[[str], None] = None,
                 on_alive_found: Callable[[str, int, str], None] = None,
                 threads: int = 10,
                 cancel_check: Callable[[], bool] = None):
        self.domain = domain.lower().strip()
        self.subdomains: Set[str] = set()
        self.alive_subdomains: Set[str] = set()
        self.api_keys = self._load_api_keys(config_file)
        self.on_subdomain_found = on_subdomain_found
        self.on_alive_found = on_alive_found
        self.threads = threads
        self.cancel_check = cancel_check or (lambda: False)
        
    def _load_api_keys(self, config_file: str) -> dict:
        api_keys = {}
        config_path = Path(config_file)
        
        if config_path.exists():
            try:
                config = configparser.ConfigParser()
                config.read(config_file)
                
                if 'API_KEYS' in config:
                    api_keys = dict(config['API_KEYS'])
                    # Filter out empty keys
                    api_keys = {k: v for k, v in api_keys.items() if v and v.strip()}
                    if api_keys:
                        print(f"[✓] Loaded {len(api_keys)} API keys from {config_file}")
                else:
                    print(f"[!] No [API_KEYS] section found in {config_file}")
            except Exception as e:
                print(f"[!] Error reading config file: {e}")
        else:
            print(f"[!] Config file not found: {config_file}")
        
        return api_keys
    
    def _notify_subdomain(self, subdomain: str):
        if self.on_subdomain_found and subdomain not in self.subdomains:
            try:
                self.on_subdomain_found(subdomain)
            except Exception as e:
                print(f"[!] Callback error: {e}")
    
    def _notify_alive(self, url: str, status_code: int, title: str):
        if self.on_alive_found:
            try:
                self.on_alive_found(url, status_code, title)
            except Exception as e:
                print(f"[!] Callback error: {e}")
    
    # ========================================================================
    # PASSIVE RECONNAISSANCE METHODS
    # ========================================================================
    
    def run_passive_recon(self) -> Set[str]:
        print(f"\n[+] Starting Passive Reconnaissance for {self.domain}")
        print("=" * 70)
        
        initial_count = len(self.subdomains)
        
        # Free sources (no API key needed) — check cancellation between each
        sources = [
            ('crtsh', self._crtsh),
            ('hackertarget', self._hackertarget),
            ('threatcrowd', self._threatcrowd),
            ('alienvault', self._alienvault),
        ]
        
        # API-based sources
        if self.api_keys.get('virustotal'):
            sources.append(('virustotal', self._virustotal))
        if self.api_keys.get('securitytrails'):
            sources.append(('securitytrails', self._securitytrails))
        
        for name, func in sources:
            if self.cancel_check():
                print(f"[!] Scan cancelled during passive recon (at {name})")
                return self.subdomains
            func()
        
        new_count = len(self.subdomains) - initial_count
        print(f"\n[✓] Passive Recon Complete: Found {new_count} new subdomains (Total: {len(self.subdomains)})")
        return self.subdomains
    
    def _add_subdomain(self, subdomain: str):
        subdomain = subdomain.strip().lower()
        if subdomain and subdomain not in self.subdomains:
            self.subdomains.add(subdomain)
            self._notify_subdomain(subdomain)
    
    def _crtsh(self):
        print("[*] Querying crt.sh...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower().replace('*.', '')
                        if subdomain and (subdomain.endswith(self.domain) or subdomain == self.domain):
                            if subdomain not in self.subdomains:
                                self._add_subdomain(subdomain)
                                count += 1
                print(f"    [✓] Found {count} subdomains from crt.sh")
            else:
                print(f"    [!] crt.sh returned {response.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _hackertarget(self):
        print("[*] Querying HackerTarget...")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                count = 0
                for line in response.text.split('\n'):
                    if line and ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain and subdomain.endswith(self.domain):
                            if subdomain not in self.subdomains:
                                self._add_subdomain(subdomain)
                                count += 1
                print(f"    [✓] Found {count} subdomains from HackerTarget")
            else:
                print(f"    [!] HackerTarget returned {response.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _threatcrowd(self):
        print("[*] Querying ThreatCrowd...")
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                for subdomain in data.get('subdomains', []):
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain.endswith(self.domain):
                        if subdomain not in self.subdomains:
                            self._add_subdomain(subdomain)
                            count += 1
                print(f"    [✓] Found {count} subdomains from ThreatCrowd")
            else:
                print(f"    [!] ThreatCrowd returned {response.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _alienvault(self):
        print("[*] Querying AlienVault OTX...")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '').strip().lower()
                    if hostname and hostname.endswith(self.domain):
                        if hostname not in self.subdomains:
                            self._add_subdomain(hostname)
                            count += 1
                print(f"    [✓] Found {count} subdomains from AlienVault")
            else:
                print(f"    [!] AlienVault returned {response.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _virustotal(self):
        print("[*] Querying VirusTotal...")
        try:
            api_key = self.api_keys.get('virustotal')
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': self.domain}
            response = requests.get(url, params=params, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                for subdomain in data.get('subdomains', []):
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain.endswith(self.domain):
                        if subdomain not in self.subdomains:
                            self._add_subdomain(subdomain)
                            count += 1
                print(f"    [✓] Found {count} subdomains from VirusTotal")
            else:
                print(f"    [!] VirusTotal returned {response.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _securitytrails(self):
        print("[*] Querying SecurityTrails...")
        try:
            api_key = self.api_keys.get('securitytrails')
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': api_key}
            response = requests.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                for sub in data.get('subdomains', []):
                    subdomain = f"{sub}.{self.domain}".lower()
                    if subdomain not in self.subdomains:
                        self._add_subdomain(subdomain)
                        count += 1
                print(f"    [✓] Found {count} subdomains from SecurityTrails")
            else:
                print(f"    [!] SecurityTrails returned {response.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    # ========================================================================
    # ACTIVE RECONNAISSANCE METHODS
    # ========================================================================
    
    def run_active_recon(self, wordlist: str = None) -> Set[str]:
        print(f"\n[+] Starting Active Reconnaissance for {self.domain}")
        print("=" * 70)
        
        initial_count = len(self.subdomains)
        
        if wordlist and Path(wordlist).exists():
            self._dns_bruteforce_wordlist(wordlist)
        else:
            if wordlist:
                print(f"[!] Wordlist not found: {wordlist}")
            self._dns_bruteforce_default()
        
        new_count = len(self.subdomains) - initial_count
        print(f"\n[✓] Active Recon Complete: Found {new_count} new subdomains (Total: {len(self.subdomains)})")
        return self.subdomains
    
    def _dns_bruteforce_wordlist(self, wordlist_path: str):
        print(f"[*] DNS brute-forcing with wordlist: {wordlist_path}")
        
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            
            print(f"    [✓] Loaded {len(words)} words")
            self._dns_resolve_list(words)
            
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _dns_bruteforce_default(self):
        print("[*] DNS brute-forcing with default subdomains...")
        
        common_subs = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en',
            'sms', 'office', 'exchange', 'help', 'git', 'faq', 'status', 'payment'
        ]
        
        print(f"    [*] Testing {len(common_subs)} common subdomains...")
        self._dns_resolve_list(common_subs)
    
    def _dns_resolve_list(self, subdomain_list: List[str]):
        found_count = 0
        total = len(subdomain_list)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._resolve_dns, f"{word}.{self.domain}"): word 
                for word in subdomain_list
            }
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                
                if completed % 50 == 0 or completed == total:
                    print(f"    [*] Progress: {completed}/{total} ({found_count} found)")
                
                result = future.result()
                if result and result not in self.subdomains:
                    self._add_subdomain(result)
                    found_count += 1
                    print(f"    [✓] Found: {result}")
        
        print(f"    [✓] Brute-force complete: {found_count} new subdomains")
    
    def _resolve_dns(self, hostname: str) -> str:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.resolve(hostname, 'A')
            return hostname if answers else None
        except:
            return None
    
    # ========================================================================
    # ALIVE CHECKING METHODS 
    # ========================================================================
    
    def check_alive_subdomains(self) -> Set[str]:
        if self.cancel_check():
            return self.alive_subdomains
        
        print(f"\n[+] Checking Alive Subdomains")
        print("=" * 70)
        
        if not self.subdomains:
            print("[!] No subdomains to check")
            return set()
        
        # Use httpx-pd (ProjectDiscovery's httpx) if available
        import os
        httpx_binary = os.path.expanduser('~/.local/bin/httpx-pd')
        try:
            result = subprocess.run([httpx_binary, '-version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return self._check_with_httpx(httpx_binary)
        except:
            pass
        
        print("[!] httpx not found, using fallback method...")
        return self._fallback_alive_check()
    
    def _check_with_httpx(self, httpx_binary: str = 'httpx-pd') -> Set[str]:
        print("[*] Using httpx for alive checking...")
        
        # Write subdomains to temp file
        input_file = 'temp_subdomains_httpx.txt'
        with open(input_file, 'w') as f:
            for sub in self.subdomains:
                f.write(f"{sub}\n")
        
        try:
            cmd = [httpx_binary, '-l', input_file, '-silent', '-json',
                   '-follow-redirects', '-status-code', '-title']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        if url:
                            self.alive_subdomains.add(url)
                            status = data.get('status_code')
                            title = data.get('title', '')[:100]
                            self._notify_alive(url, status, title)
                            print(f"    [✓] {url} [{status}] - {title[:50]}")
                    except json.JSONDecodeError:
                        pass
            
            # Cleanup temp file
            if Path(input_file).exists():
                Path(input_file).unlink()
            
            print(f"\n[✓] Found {len(self.alive_subdomains)} alive subdomains")
            return self.alive_subdomains
            
        except Exception as e:
            print(f"[!] httpx error: {e}")
            # Cleanup temp file
            if Path(input_file).exists():
                Path(input_file).unlink()
            return self._fallback_alive_check()
    
    def _fallback_alive_check(self) -> Set[str]:
        print("[*] Using Python requests...")
        
        print(f"[*] Checking {len(self.subdomains)} subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_url, sub): sub for sub in self.subdomains}
            
            for future in concurrent.futures.as_completed(futures):
                if self.cancel_check():
                    executor.shutdown(wait=False, cancel_futures=True)
                    print("[!] Scan cancelled during alive check")
                    break
                result = future.result()
                if result:
                    self.alive_subdomains.add(result['url'])
                    self._notify_alive(result['url'], result.get('status'), result.get('title'))
                    print(f"    [✓] {result['url']}")
        
        print(f"\n[✓] Found {len(self.alive_subdomains)} alive subdomains")
        return self.alive_subdomains
    
    def _check_url(self, subdomain: str) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}" if not subdomain.startswith('http') else subdomain
            try:
                response = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                if response.status_code < 500:
                    title = ''
                    try:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        if soup.title:
                            title = soup.title.string.strip()[:100]
                    except:
                        pass
                    return {'url': url, 'status': response.status_code, 'title': title}
            except:
                continue
        return None
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def export_results(self, output_file: str = None):
        if not output_file:
            output_file = f"subdomains_{self.domain.replace('.', '_')}.txt"
        
        try:
            with open(output_file, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
            print(f"\n[✓] Results exported to: {output_file}")
            return output_file
        except Exception as e:
            print(f"\n[!] Export error: {e}")
            return None
    
    def export_alive_subdomains(self, output_file: str = "alive_subdomains.txt"):
        try:
            with open(output_file, 'w') as f:
                for subdomain in sorted(self.alive_subdomains):
                    f.write(f"{subdomain}\n")
            print(f"[✓] Alive subdomains: {output_file}")
        except Exception as e:
            print(f"[!] Export error: {e}")
    
    def display_results(self):
        print(f"\n{'='*70}")
        print(f"SUBDOMAIN ENUMERATION - {self.domain}")
        print(f"{'='*70}")
        print(f"Total Subdomains: {len(self.subdomains)}")
        print(f"Alive Subdomains: {len(self.alive_subdomains)}\n")
        
        if self.subdomains:
            for subdomain in sorted(self.subdomains):
                print(f"  • {subdomain}")
        else:
            print("  No subdomains discovered.")


def main():
    parser = argparse.ArgumentParser(
        description="NileDefender - Subdomain Enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('--passive', action='store_true', help='Passive recon only')
    parser.add_argument('--active', action='store_true', help='Active recon only')
    parser.add_argument('--check-alive', action='store_true', help='Check alive subdomains')
    parser.add_argument('-w', '--wordlist', help='Wordlist for brute-force')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-c', '--config', default='config.ini', help='Config file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    
    args = parser.parse_args()
    
    if args.domain.startswith('http'):
        args.domain = urlparse(args.domain).netloc
    
    if not args.passive and not args.active:
        args.passive = args.active = True
    
    enumerator = SubdomainEnumerator(args.domain, args.config, threads=args.threads)
    
    if args.passive:
        enumerator.run_passive_recon()
    if args.active:
        enumerator.run_active_recon(args.wordlist)
    
    if args.check_alive:
        enumerator.check_alive_subdomains()
    
    enumerator.display_results()
    enumerator.export_results(args.output)


if __name__ == "__main__":
    main()
