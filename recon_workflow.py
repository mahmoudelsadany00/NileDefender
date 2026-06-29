#!/usr/bin/env python3
"""
NileDefender - Enhanced Reconnaissance Workflow
Production-ready with multi-target support and POST endpoint detection
Database operations are centralized here (backend only)
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# Import scanner modules 
from recon.subdomain_enum import SubdomainEnumerator
from recon.url_crawler import URLCrawler

# Import database module (from core package)
from core.database import (
    init_db, get_session, create_scan, update_scan_status,
    save_subdomain, save_endpoint, get_scan_results
)


class ReconWorkflow:
    def __init__(self, domain: str = None,
                 config_file: str = "config.ini", 
                 output_dir: str = "output", wordlist: str = None):
        """
        Initialize reconnaissance workflow
        
        Args:
            domain: Target domain (for subdomain enumeration mode)
            config_file: Path to config.ini
            output_dir: Output directory
            wordlist: Wordlist for active subdomain recon
        """
        self.config_file = config_file
        self.output_dir = Path(output_dir)
        self.wordlist = wordlist
        
        if not domain:
            raise ValueError("--domain must be provided")
        
        self.domain = domain
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database (centralized here)
        db_path = f"sqlite:///{self.output_dir}/niledefender.db"
        self.engine = init_db(db_path)
        self.session = get_session(self.engine)
        
        scan_type = 'recon_only'
        self.scan_id = create_scan(self.session, self.domain, scan_type)
        
        print("\n" + "="*70)
        print("NILEDEFENDER - WEB VULNERABILITY SCANNER")
        print("RECONNAISSANCE WORKFLOW")
        print("="*70)
        print(f"Target Domain: {self.domain}")
        print(f"Mode: DOMAIN (subdomain enumeration)")
        print(f"Scan ID: {self.scan_id}  <- NEW SCAN")
        print(f"Output Directory: {self.output_dir}")
        print(f"Database: {db_path}")
        print("="*70 + "\n")
    
    def _save_alive_callback(self, url: str, status_code: int, title: str):
        """Callback to save alive subdomain to database (only alive ones are stored)"""
        save_subdomain(self.session, self.scan_id, url, 
                      is_alive=1, status_code=status_code, title=title)
    
    def _save_endpoint_callback(self, endpoint: dict):
        """Callback to save endpoint to database"""
        save_endpoint(
            self.session, self.scan_id,
            url=endpoint.get('url'),
            method=endpoint.get('method', 'GET'),
            parameters=endpoint.get('parameters'),
            body_params=endpoint.get('body_params'),
            extra_headers=endpoint.get('extra_headers'),
            source=endpoint.get('source', 'crawler'),
            form_details=endpoint.get('form_details')
        )
    
    def run(self, passive: bool = True, active: bool = True, crawl: bool = True):
        """Run complete reconnaissance workflow"""
        try:
            # Domain mode: subdomain enum -> crawl
            self._run_domain_mode(passive, active, crawl)
            
            # Final Phase: Generate Report
            print("\n" + "="*70)
            print("FINAL PHASE: GENERATING REPORT")
            print("="*70)
            
            self.generate_report()
            
            # Mark scan as completed
            update_scan_status(self.session, self.scan_id, 'completed')
            
            print("\n" + "="*70)
            print("RECONNAISSANCE WORKFLOW COMPLETED")
            print("="*70)
            print(f"\nResults saved to: {self.output_dir}")
            print(f"Database: {self.output_dir}/niledefender.db")
            print(f"Scan ID: {self.scan_id}\n")
            
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
            update_scan_status(self.session, self.scan_id, 'failed')
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] Error: {e}")
            import traceback
            traceback.print_exc()
            update_scan_status(self.session, self.scan_id, 'failed')
            raise
        finally:
            self.session.close()
    
    # ========================================================================
    # DOMAIN MODE (subdomain enum -> crawl)
    # ========================================================================
    
    def _run_domain_mode(self, passive: bool, active: bool, crawl: bool):
        """Run traditional domain scan mode: subdomain enum -> URL crawling"""
        
        # Phase 1: Subdomain Enumeration
        print("\n" + "="*70)
        print("PHASE 1: SUBDOMAIN ENUMERATION")
        print("="*70)
        
        subdomains, alive_urls = self.enumerate_subdomains(passive, active)
        
        if not subdomains:
            print("\n[!] No subdomains discovered. Exiting...")
            update_scan_status(self.session, self.scan_id, 'failed')
            return
        
        # Phase 2: URL Crawling & Parameter Extraction
        if crawl and alive_urls:
            print("\n" + "="*70)
            print("PHASE 2: URL CRAWLING & PARAMETER EXTRACTION")
            print("="*70)
            
            self.crawl_and_extract(alive_urls)
    
    def enumerate_subdomains(self, passive: bool, active: bool):
        """Phase 1: Subdomain enumeration with alive checking"""
        print("\n[*] Starting subdomain enumeration...")
        
        # Initialize with callback (only save alive subdomains to DB)
        enumerator = SubdomainEnumerator(
            self.domain, 
            self.config_file,
            on_alive_found=self._save_alive_callback
        )
        
        # Run passive
        if passive:
            enumerator.run_passive_recon()
        
        # Run active
        if active:
            enumerator.run_active_recon(self.wordlist)
        
        # Check alive subdomains
        alive_urls = enumerator.check_alive_subdomains()
        
        # Export to file
        subdomain_file = self.output_dir / f"subdomains_{self.domain.replace('.', '_')}.txt"
        enumerator.export_results(str(subdomain_file))
        
        alive_file = self.output_dir / "alive_subdomains.txt"
        enumerator.export_alive_subdomains(str(alive_file))
        
        print(f"\n[+] Subdomain enumeration complete: {len(enumerator.subdomains)} subdomains, {len(alive_urls)} alive")
        
        return enumerator.subdomains, alive_urls
    
    def crawl_and_extract(self, alive_urls):
        """URL crawling and parameter extraction"""
        print("\n[*] Starting URL crawler...")
        
        crawler = URLCrawler(
            alive_urls=list(alive_urls),
            threads=10,
            on_endpoint_found=self._save_endpoint_callback
        )
        
        # Crawl URLs
        crawler.crawl_urls()
        
        # Extract parameters
        endpoints = crawler.extract_parameters()
        
        # Export results
        crawler.export_urls(str(self.output_dir / "urls.txt"))
        crawler.export_urls_with_params(str(self.output_dir / "urls_with_params.txt"))
        crawler.export_endpoints_json(str(self.output_dir / "endpoints.json"))
        
        # Display summary
        crawler.display_summary()
        
        print(f"[+] URL crawling complete")
    
    def generate_report(self):
        """Generate final report"""
        print("\n[*] Generating report...")
        
        results = get_scan_results(self.session, self.scan_id)
        
        if not results:
            print("[!] No results found")
            return
        
        report_file = self.output_dir / f"recon_report_{self.domain.replace('.', '_').replace(':', '_')}_scan{self.scan_id}.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("NILEDEFENDER - RECONNAISSANCE REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Scan ID: {results['scan']['id']}\n")
            f.write(f"Domain: {results['scan']['domain']}\n")
            f.write(f"Scan Type: {results['scan'].get('scan_type', 'unknown')}\n")
            f.write(f"Scan Date: {results['scan']['scan_date']}\n")
            f.write(f"Status: {results['scan']['status']}\n\n")
            
            f.write("="*70 + "\n")
            f.write("SUMMARY\n")
            f.write("="*70 + "\n\n")
            
            total_subdomains = len(results['subdomains'])
            alive_subdomains = sum(1 for s in results['subdomains'] if s['is_alive'] == 1)
            total_endpoints = len(results['endpoints'])
            get_endpoints = sum(1 for e in results['endpoints'] if e['method'] == 'GET')
            post_endpoints = sum(1 for e in results['endpoints'] if e['method'] == 'POST')
            endpoints_with_params = sum(1 for e in results['endpoints'] 
                                       if e['parameters'] or e['body_params'])
            
            f.write(f"Total Subdomains: {total_subdomains}\n")
            f.write(f"Alive Subdomains: {alive_subdomains}\n")
            f.write(f"Total Endpoints: {total_endpoints}\n")
            f.write(f"  GET Endpoints: {get_endpoints}\n")
            f.write(f"  POST Endpoints: {post_endpoints}\n")
            f.write(f"Endpoints with Parameters: {endpoints_with_params}\n\n")
            
            f.write("="*70 + "\n")
            f.write("SUBDOMAINS\n")
            f.write("="*70 + "\n\n")
            
            for subdomain in results['subdomains']:
                status = "ALIVE" if subdomain['is_alive'] == 1 else "NOT CHECKED"
                f.write(f"{status} - {subdomain['subdomain']}")
                if subdomain['status_code']:
                    f.write(f" [{subdomain['status_code']}]")
                if subdomain['title']:
                    f.write(f" - {subdomain['title'][:60]}")
                f.write("\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("ENDPOINTS (READY FOR VULNERABILITY TESTING)\n")
            f.write("="*70 + "\n\n")
            
            f.write("GET ENDPOINTS:\n")
            f.write("-" * 70 + "\n")
            for endpoint in results['endpoints']:
                if endpoint['method'] == 'GET' and endpoint['parameters']:
                    f.write(f"\n{endpoint['url']}\n")
                    f.write(f"  Parameters: {endpoint['parameters']}\n")
                    f.write(f"  Source: {endpoint.get('source', 'unknown')}\n")
            
            f.write("\n" + "-" * 70 + "\n")
            f.write("POST ENDPOINTS:\n")
            f.write("-" * 70 + "\n")
            for endpoint in results['endpoints']:
                if endpoint['method'] == 'POST' and endpoint['body_params']:
                    f.write(f"\n{endpoint['url']}\n")
                    f.write(f"  Body Parameters: {endpoint['body_params']}\n")
                    f.write(f"  Source: {endpoint.get('source', 'unknown')}\n")
                    if endpoint.get('form_details'):
                        f.write(f"  Form Details: {endpoint['form_details']}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("ALL DISCOVERED ENDPOINTS:\n")
            f.write("="*70 + "\n\n")
            for endpoint in results['endpoints']:
                f.write(f"[{endpoint['method']}] {endpoint['url']} (source: {endpoint.get('source', 'unknown')})\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")
        
        print(f"[+] Report: {report_file}")
        
        # Console summary
        print("\n" + "="*70)
        print("FINAL SUMMARY")
        print("="*70)
        print(f"Scan ID: {self.scan_id}")
        print(f"Total Subdomains: {total_subdomains}")
        print(f"Alive Subdomains: {alive_subdomains}")
        print(f"Total Endpoints: {total_endpoints}")
        print(f"  GET Endpoints: {get_endpoints}")
        print(f"  POST Endpoints: {post_endpoints}")
        print(f"Endpoints with Parameters: {endpoints_with_params}")
        print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description="NileDefender - Complete Reconnaissance Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full reconnaissance
  python recon_workflow.py -d example.com
  
  # Passive only
  python recon_workflow.py -d example.com --passive-only
  
  # Skip URL crawling
  python recon_workflow.py -d example.com --no-crawl
        """
    )
    
    # Target
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    
    # General options
    parser.add_argument('-c', '--config', default='config.ini', help='Config file')
    parser.add_argument('-o', '--output', default='output', help='Output directory')
    parser.add_argument('--no-crawl', action='store_true', help='Skip URL crawling')
    
    # Domain mode options
    parser.add_argument('-w', '--wordlist', help='Wordlist for active subdomain recon')
    parser.add_argument('--passive-only', action='store_true', help='Passive only (domain mode)')
    parser.add_argument('--active-only', action='store_true', help='Active only (domain mode)')
    
    args = parser.parse_args()
    
    # Determine phases
    passive = True
    active = True
    crawl = not args.no_crawl
    
    if args.passive_only:
        active = False
    elif args.active_only:
        passive = False
    
    # Extract domain from URL if domain mode
    domain = args.domain
    if domain and domain.startswith('http'):
        domain = urlparse(domain).netloc
    
    # Run workflow
    workflow = ReconWorkflow(
        domain=domain,
        config_file=args.config,
        output_dir=args.output,
        wordlist=args.wordlist
    )
    
    workflow.run(passive=passive, active=active, crawl=crawl)


if __name__ == "__main__":
    main()
