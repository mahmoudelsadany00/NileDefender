#!/usr/bin/env python3

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Docker networking: translate localhost URLs to host.docker.internal
_IN_DOCKER = os.environ.get('RUNNING_IN_DOCKER', '0') == '1'

def _docker_translate_url(url: str) -> str:
    """When running inside Docker, localhost/127.0.0.1 means the container
    itself — not the host machine.  Replace with host.docker.internal so
    the Selenium browser and HTTP requests can reach host services."""
    if not _IN_DOCKER:
        return url
    url = url.replace('://localhost', '://host.docker.internal')
    url = url.replace('://127.0.0.1', '://host.docker.internal')
    return url

def _docker_reverse_url(url: str) -> str:
    """Reverse Docker URL translation for display/storage — convert
    host.docker.internal back to localhost so the user sees clean URLs."""
    if not url:
        return url
    return url.replace('://host.docker.internal', '://localhost')

# Import recon modules
from recon.local_crawler import LocalCrawler, is_local_target, quick_login

# Import scanner modules
from scanners import SCANNER_MODULES
from scanners.sqli import run_sqli_scan

# Import database module
from core.database import (
    init_db, get_session, create_scan, update_scan_status,
    save_subdomain, save_endpoint, get_scan_results,
    get_all_scans, get_scan_by_id, get_endpoints, get_subdomains,
    get_vulnerabilities
)


class VulnWorkflow:

    def __init__(self, target_url: str = None, scan_id: int = None,
                 db_path: str = None, output_dir: str = "output",
                 modules: list = None, scan_type: str = 'full',
                 on_progress=None, on_endpoint_found=None,
                 cancel_check=None):
        self.target_url = target_url
        self.scan_id = scan_id
        self.scan_type = scan_type
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Database setup
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = str(self.output_dir / "niledefender.db")
        
        self.db_engine = init_db(f"sqlite:///{self.db_path}")
        self.session = get_session(self.db_engine)
        
        # Module selection
        self.trigger_idor = (self.scan_type == 'full')

        if modules:
            self.modules = [m for m in modules if m in SCANNER_MODULES]
            if 'idor' in modules:
                self.trigger_idor = True
            unknown = [m for m in modules if m not in SCANNER_MODULES and m != 'idor']
            if unknown:
                print(f"[!] Unknown modules (ignored): {', '.join(unknown)}")
                print(f"    Available modules: {', '.join(SCANNER_MODULES.keys())}")
        else:
            self.modules = list(SCANNER_MODULES.keys())
        
        # Callbacks
        self.on_progress = on_progress
        self.on_endpoint_found = on_endpoint_found
        self.cancel_check = cancel_check or (lambda: False)
        
        # Results tracking
        self.results = {
            'modules_run': [],
            'total_targets_scanned': 0,
            'total_vulnerabilities_found': 0,
            'module_results': {},
            'cookie': None,
            'auto_recon': False,
        }

    def _log(self, message: str):
        # Normalize URLs in logs so they show localhost instead of host.docker.internal
        message = _docker_reverse_url(message)
        print(f"[VulnWorkflow] {message}")
        if self.on_progress:
            self.on_progress(message)

    def run(self, skip_recon: bool = False) -> dict:
        self._log("Starting vulnerability scanning workflow...")

        # Step 1: Ensure we have a scan_id
        if self.scan_id is None and self.target_url:
            self._log(f"Creating new scan for {self.target_url}")
            self.scan_id = create_scan(self.session, self.target_url, 'vulnscan')
        elif self.scan_id is None:
            raise ValueError("Either target_url or scan_id must be provided")

        # Step 2: Ensure endpoints exist
        if not skip_recon:
            if self.cancel_check(): return self.results
            self._ensure_endpoints()

        # Step 3: Authenticate
        if self.cancel_check(): return self.results
        cookie = self._authenticate()
        self.results['cookie'] = cookie

        # Step 4: Run selected vulnerability modules
        if self.cancel_check(): return self.results
        ai_triggered = self._run_modules(cookie)

        # Step 5: Mark scan as completed or keep it running for AI
        self.results['ai_triggered'] = ai_triggered
        if ai_triggered:
            update_scan_status(self.session, self.scan_id, 'running')
        else:
            update_scan_status(self.session, self.scan_id, 'completed')

        # Step 6: Generate summary
        scan_results = get_scan_results(self.session, self.scan_id)
        total_vulns = len(scan_results.get('vulnerabilities', []))
        total_endpoints = len(scan_results.get('endpoints', []))

        self._log(f"Vulnerability scan completed! "
                  f"Found {total_vulns} vulnerabilities across {total_endpoints} endpoints")

        self.results['total_endpoints'] = total_endpoints

        return self.results

    def _ensure_endpoints(self):
        endpoints = get_endpoints(self.session, self.scan_id)
        
        if endpoints:
            self._log(f"Found {len(endpoints)} existing endpoints")
            return
        
        # No endpoints — need to crawl
        scan = get_scan_by_id(self.session, self.scan_id)
        if not scan:
            self._log("Error: Scan not found in database")
            return
        
        target_url = _docker_translate_url(scan.domain)
        self._log(f"No endpoints found. Running auto-recon on {target_url}...")
        self.results['auto_recon'] = True
        
        # Define endpoint callback
        def on_endpoint_found(endpoint):
            save_endpoint(
                self.session, self.scan_id,
                url=endpoint.get('url'),
                method=endpoint.get('method', 'GET'),
                parameters=endpoint.get('parameters'),
                body_params=endpoint.get('body_params'),
                extra_headers=endpoint.get('extra_headers'),
                source=endpoint.get('source', 'auto_recon'),
                form_details=endpoint.get('form_details')
            )
            # Also notify external callback if set
            if self.on_endpoint_found:
                self.on_endpoint_found(endpoint)
        
        if is_local_target(target_url):
            # ======= LOCAL TARGET: Selenium crawler =======
            # Register target as subdomain entry
            # Save the user-facing URL (localhost), not the Docker-internal one
            save_subdomain(self.session, self.scan_id, _docker_reverse_url(target_url),
                          is_alive=1, status_code=200, title='Local Target')
            
            self._log("Starting local crawler (Selenium)...")
            crawler = LocalCrawler(
                base_url=target_url,
                max_depth=5,
                max_pages=500,
                on_endpoint_found=on_endpoint_found,
                on_progress=lambda msg: self._log(msg),
                cancel_check=self.cancel_check
            )
            crawler.crawl()
            summary = crawler.get_summary()
            self._log(f"Recon complete: {summary['pages_visited']} pages, "
                      f"{summary['get_endpoints']} GET, {summary['post_endpoints']} POST endpoints")
        else:
            # ======= REMOTE TARGET: SubdomainEnumerator + URLCrawler =======
            from recon.subdomain_enum import SubdomainEnumerator
            from recon.url_crawler import URLCrawler
            
            # Normalize domain (strip scheme/trailing slash)
            domain = target_url.replace('http://', '').replace('https://', '').strip('/')
            
            # Phase 1: Subdomain enumeration
            self._log(f"Running passive subdomain enumeration for {domain}...")
            
            def on_alive_found(url, status_code, title):
                save_subdomain(self.session, self.scan_id, url,
                              is_alive=1, status_code=status_code, title=title)
                self._log(f"Alive: {url} [{status_code}]")
            
            enumerator = SubdomainEnumerator(
                domain,
                config_file='config.ini',
                on_alive_found=on_alive_found,
                cancel_check=self.cancel_check
            )
            
            if self.cancel_check(): return
            enumerator.run_passive_recon()
            
            subdomains = enumerator.subdomains
            self._log(f"Found {len(subdomains)} subdomains")
            
            if not subdomains:
                # No subdomains found — try the target URL directly
                self._log(f"No subdomains discovered. Using target directly: {domain}")
                save_subdomain(self.session, self.scan_id, f"http://{domain}",
                              is_alive=1, status_code=200, title='Direct Target')
                alive_urls = {f"http://{domain}"}
            else:
                # Phase 2: Alive check
                if self.cancel_check(): return
                self._log("Checking alive subdomains...")
                alive_urls = enumerator.check_alive_subdomains()
                self._log(f"Found {len(alive_urls)} alive subdomains")
            
            if not alive_urls:
                self._log("No alive hosts found — cannot proceed.")
                return
            
            # Phase 3: URL Crawling
            if self.cancel_check(): return
            self._log("Starting URL crawling and parameter extraction...")
            
            crawler = URLCrawler(
                alive_urls=list(alive_urls),
                threads=10,
                on_endpoint_found=on_endpoint_found,
                cancel_check=self.cancel_check
            )
            
            crawler.crawl_urls()
            endpoints = crawler.extract_parameters()
            self._log(f"URL crawling complete: {len(endpoints)} endpoints discovered")


    def _authenticate(self) -> str:
        scan = get_scan_by_id(self.session, self.scan_id)
        
        if not scan or not is_local_target(scan.domain):
            return None
        
        self._log("Performing authentication for local target...")
        target = _docker_translate_url(scan.domain)
        cookie = quick_login(target, on_progress=self.on_progress)
        
        if cookie:
            self._log("Session cookie acquired for authenticated scanning")
        else:
            self._log("No session cookie obtained — scanning without authentication")
        
        return cookie

    def _run_modules(self, cookie: str = None) -> bool:
        self._log(f"Starting vulnerability modules...")
        ai_triggered = False
        self._log(f"Running {len(self.modules)} vulnerability module(s): {', '.join(self.modules)}")
        
        for module_key in self.modules:
            if self.cancel_check():
                self._log("Scan cancelled — stopping module execution")
                break

            module_info = SCANNER_MODULES[module_key]
            module_name = module_info['name']
            run_func = module_info['run']
            
            self._log(f"Starting {module_name} scanner...")
            
            try:
                result = run_func(
                    scan_id=self.scan_id,
                    db_path=self.db_path,
                    on_progress=self.on_progress,
                    cookie=cookie,
                    cancel_check=self.cancel_check
                )
                
                self.results['modules_run'].append(module_key)
                self.results['module_results'][module_key] = result
                
                targets_scanned = result.get('targets_scanned', 0)
                vulns_found = result.get('vulnerabilities_found', 0)
                
                self.results['total_targets_scanned'] += targets_scanned
                self.results['total_vulnerabilities_found'] += vulns_found
                
                self._log(f"{module_name} complete: "
                          f"{targets_scanned} targets scanned, "
                          f"{vulns_found} vulnerabilities found")
                
            except Exception as e:
                self._log(f"Error running {module_name}: {e}")
                self.results['module_results'][module_key] = {
                    'error': str(e),
                    'targets_scanned': 0,
                    'vulnerabilities_found': 0
                }

        # --- Smart n8n trigger: IDOR ---
        try:
            import configparser, requests as _req, os
            config = configparser.ConfigParser()
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')
            config.read(config_path)

            if config.has_option('API_KEYS', 'N8N_WEBHOOK_URL') and self.trigger_idor:
                webhook_url = config.get('API_KEYS', 'N8N_WEBHOOK_URL').strip()
                if webhook_url:
                    # Mark as triggered BEFORE the request - timeout/error is expected
                    ai_triggered = True
                    self._log(f"Triggering n8n IDOR Agent (scan_type={self.scan_type}, modules={self.modules})...")
                    try:
                        _req.post(webhook_url, json={'scan_id': self.scan_id, 'cookie': cookie}, timeout=5)
                    except Exception as req_err:
                        self._log(f"n8n webhook sent (response: {type(req_err).__name__})")
            else:
                self._log(f"Skipping n8n trigger (trigger_idor={self.trigger_idor})")
        except Exception as e:
            self._log(f"Warning: n8n trigger failed: {e}")

        self._log(f"_run_modules done. ai_triggered={ai_triggered}")
        return ai_triggered


    def generate_report(self) -> str:
        scan = get_scan_by_id(self.session, self.scan_id)
        vulns = get_vulnerabilities(self.session, self.scan_id)
        endpoints = get_endpoints(self.session, self.scan_id)
        
        sep = "=" * 70
        report = []
        report.append(f"\n{sep}")
        report.append("🛡️  NILEDEFENDER — VULNERABILITY SCAN REPORT")
        report.append(sep)
        report.append(f"Target:     {scan.domain if scan else 'Unknown'}")
        report.append(f"Scan ID:    {self.scan_id}")
        report.append(f"Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Modules:    {', '.join(self.results.get('modules_run', []))}")
        report.append(f"Auto-Recon: {'Yes' if self.results.get('auto_recon') else 'No'}")
        report.append(sep)
        
        # Summary
        report.append(f"\n📊 SUMMARY")
        report.append(f"   Endpoints scanned:       {len(endpoints)}")
        report.append(f"   Targets tested:          {self.results.get('total_targets_scanned', 0)}")
        report.append(f"   Vulnerabilities found:   {self.results.get('total_vulnerabilities_found', 0)}")
        
        # Per-module results
        for module_key, result in self.results.get('module_results', {}).items():
            module_info = SCANNER_MODULES.get(module_key, {})
            module_name = module_info.get('name', module_key)
            report.append(f"\n   [{module_name}]")
            if 'error' in result:
                report.append(f"     Error: {result['error']}")
            else:
                report.append(f"     Targets scanned:       {result.get('targets_scanned', 0)}")
                report.append(f"     Vulnerabilities found:  {result.get('vulnerabilities_found', 0)}")
        
        # Vulnerability details
        if vulns:
            report.append(f"\n{sep}")
            report.append(f"🔴 VULNERABILITIES FOUND ({len(vulns)})")
            report.append(sep)
            
            for i, v in enumerate(vulns, 1):
                report.append(f"\n  [{i}] {v.vulnerability_type} — {v.severity}")
                report.append(f"      URL:       {v.url}")
                report.append(f"      Method:    {v.method}")
                report.append(f"      Parameter: {v.parameter}")
                if v.payload:
                    payload_preview = v.payload[:100] + ('...' if len(v.payload) > 100 else '')
                    report.append(f"      Payload:   {payload_preview}")
                report.append(f"      Discovered: {v.discovered_at}")
        else:
            report.append(f"\n✅ No vulnerabilities found.")
        
        report.append(f"\n{sep}\n")
        
        report_text = '\n'.join(report)
        return report_text

    def close(self):
        try:
            self.session.close()
        except:
            pass


def main():
    """CLI entry point for standalone vulnerability scanning."""
    parser = argparse.ArgumentParser(
        description="NileDefender — Vulnerability Scanning Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vuln_workflow.py --target http://localhost/bWAPP/
  python vuln_workflow.py --target http://localhost/bWAPP/ --modules sqli
  python vuln_workflow.py --scan-id 5 --modules sqli
  python vuln_workflow.py --list-modules

Available modules:
""" + '\n'.join(f"  {k:10s} — {v['description']}" for k, v in SCANNER_MODULES.items())
    )
    
    parser.add_argument('--target', '-t', type=str,
                       help='Target URL (e.g., http://localhost/bWAPP/)')
    parser.add_argument('--scan-id', '-s', type=int,
                       help='Reuse an existing scan ID')
    parser.add_argument('--modules', '-m', nargs='+',
                       default=None,
                       help=f'Vulnerability modules to run (default: all). '
                            f'Available: {", ".join(SCANNER_MODULES.keys())}')
    parser.add_argument('--skip-recon', action='store_true',
                       help='Skip auto-recon (fail if no endpoints exist)')
    parser.add_argument('--output-dir', '-o', type=str, default='output',
                       help='Output directory (default: output)')
    parser.add_argument('--db-path', type=str, default=None,
                       help='Custom database path')
    parser.add_argument('--list-modules', action='store_true',
                       help='List available scanner modules')
    parser.add_argument('--report', action='store_true', default=True,
                       help='Generate report after scanning (default: True)')
    
    args = parser.parse_args()
    
    # List modules
    if args.list_modules:
        print("\n🔧 Available Vulnerability Scanner Modules:")
        print("=" * 50)
        for key, info in SCANNER_MODULES.items():
            print(f"  {key:10s} — {info['name']}")
            print(f"             {info['description']}")
        print()
        return
    
    # Validate args
    if not args.target and args.scan_id is None:
        parser.error("Either --target or --scan-id is required")
    
    # Print banner
    print("\n" + "=" * 70)
    print("🛡️  NILEDEFENDER — VULNERABILITY SCANNER")
    print("=" * 70)
    if args.target:
        print(f"🎯 Target: {args.target}")
    if args.scan_id:
        print(f"📋 Scan ID: {args.scan_id}")
    print(f"🔧 Modules: {', '.join(args.modules) if args.modules else 'all'}")
    print("=" * 70 + "\n")
    
    try:
        workflow = VulnWorkflow(
            target_url=args.target,
            scan_id=args.scan_id,
            db_path=args.db_path,
            output_dir=args.output_dir,
            modules=args.modules
        )
        
        results = workflow.run(skip_recon=args.skip_recon)
        
        # Generate report
        if args.report:
            report = workflow.generate_report()
            print(report)
            
            # Save report to file
            report_file = Path(args.output_dir) / f"vulnscan_report_{workflow.scan_id}.txt"
            report_file.write_text(report)
            print(f"📄 Report saved to: {report_file}")
        
        workflow.close()
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
