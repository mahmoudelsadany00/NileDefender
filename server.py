#!/usr/bin/env python3

# Monkey-patch standard library for gevent (required for Flask-SocketIO async support)
try:
    import gevent.monkey
    gevent.monkey.patch_all()
except ImportError:
    pass

from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import sys
import threading
from datetime import datetime
from pathlib import Path


# Import scanner modules (organized in packages)
from recon.subdomain_enum import SubdomainEnumerator
from recon.url_crawler import URLCrawler
from recon.local_crawler import LocalCrawler, is_local_target, quick_login
from scanners.sqli import run_sqli_scan

# Import AI report generator
from ai_report import get_scan_vulnerabilities as ai_get_vulns, generate_report_html, html_to_pdf_bytes

# Import vulnerability workflow
from vuln_workflow import VulnWorkflow

# Import database module (centralized in core/)
from core.database import (
    init_db, get_session, create_scan, update_scan_status,
    save_subdomain, save_endpoint, get_scan_results,
    get_all_scans, get_scan_by_id, get_endpoints, get_subdomains,
    get_vulnerabilities, save_vulnerability
)

# Initialize Flask app
# Serve React build from frontend/dist/ in production
FRONTEND_DIST = Path(__file__).parent / "frontend" / "dist"

app = Flask(
    __name__,
    template_folder='templates',
    static_folder=str(FRONTEND_DIST / 'assets') if FRONTEND_DIST.exists() else 'static',
    static_url_path='/assets' if FRONTEND_DIST.exists() else '/static'
)
app.config['SECRET_KEY'] = 'niledefender-secret-key'

# Enable CORS for all routes
CORS(app, resources={r"/api/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database - use output folder to share with CLI tools
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = OUTPUT_DIR / "niledefender.db"

db_engine = init_db(f"sqlite:///{DB_PATH}")
db_session = get_session(db_engine)

# Store active scans
active_scans = {}
cancelled_scans = set()  # scan IDs marked for cancellation

# Docker networking: translate localhost URLs to host.docker.internal
import os
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


def is_scan_cancelled(scan_id):
    return scan_id in cancelled_scans


# ============================================================================
# BACKGROUND SCAN RUNNER - Uses callbacks for database operations
# ============================================================================

def emit_progress(scan_id, phase, message, progress=None):
    # Normalize URLs in progress messages so the UI shows localhost, not host.docker.internal
    message = _docker_reverse_url(message)
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'status': 'running',
        'phase': phase,
        'message': message,
        'progress': progress
    }, room=f'scan_{scan_id}')


def make_endpoint_callback(session, scan_id):
    def on_endpoint_found(endpoint):
        save_endpoint(
            session, scan_id,
            url=endpoint.get('url'),
            method=endpoint.get('method', 'GET'),
            parameters=endpoint.get('parameters'),
            body_params=endpoint.get('body_params'),
            extra_headers=endpoint.get('extra_headers'),
            source=endpoint.get('source', 'crawler'),
            form_details=endpoint.get('form_details')
        )
    return on_endpoint_found


def run_scan_with_lifecycle(scan_id, scan_fn):
    """Run a scan function with shared lifecycle management.
    
    Handles: thread DB session, error handling, status updates,
    WebSocket error emission, and active_scans cleanup.
    """
    # If already cancelled before thread even starts, bail out
    if is_scan_cancelled(scan_id):
        print(f"[*] Scan {scan_id} was cancelled before starting")
        cancelled_scans.discard(scan_id)
        active_scans.pop(scan_id, None)
        return

    thread_session = get_session(db_engine)
    try:
        scan_fn(thread_session)
    except Exception as e:
        if is_scan_cancelled(scan_id):
            print(f"[*] Scan {scan_id} cancelled during execution")
        else:
            import traceback
            print(f"[!] Scan {scan_id} error: {e}")
            traceback.print_exc()
            try:
                update_scan_status(thread_session, scan_id, 'failed')
            except:
                pass
            socketio.emit('scan_error', {
                'scan_id': scan_id,
                'status': 'failed',
                'error': str(e)
            }, room=f'scan_{scan_id}')
    finally:
        active_scans.pop(scan_id, None)
        cancelled_scans.discard(scan_id)
        try:
            thread_session.close()
        except:
            pass


def run_scan_background(domain, scan_id, passive=True, active=False, crawl=True):
    def _scan(thread_session):
        if is_scan_cancelled(scan_id): return
        print(f"[*] Starting scan {scan_id} for {domain}")
        print(f"    Options: passive={passive}, active={active}, crawl={crawl}")
        
        on_endpoint_found = make_endpoint_callback(thread_session, scan_id)
        
        # Define callback for alive subdomains (only save alive ones)
        def on_alive_found(url, status_code, title):
            save_subdomain(thread_session, scan_id, url,
                          is_alive=1, status_code=status_code, title=title)
            emit_progress(scan_id, 'alive_check', f'Alive: {url} [{status_code}]')
        
        # Phase 1: Subdomain Enumeration
        emit_progress(scan_id, 'subdomain_enum', 'Phase 1: Starting subdomain enumeration...')
        
        enumerator = SubdomainEnumerator(
            domain,
            config_file='config.ini',
            on_alive_found=on_alive_found,
            cancel_check=lambda: is_scan_cancelled(scan_id)
        )
        
        if passive:
            if is_scan_cancelled(scan_id): return
            emit_progress(scan_id, 'subdomain_enum', 'Running passive reconnaissance (CT logs, APIs)...')
            enumerator.run_passive_recon()
        
        if active:
            if is_scan_cancelled(scan_id): return
            emit_progress(scan_id, 'subdomain_enum', 'Running active reconnaissance (DNS brute-force)...')
            enumerator.run_active_recon()
        
        subdomains = enumerator.subdomains
        emit_progress(scan_id, 'subdomain_enum', f'Found {len(subdomains)} subdomains')
        
        if not subdomains:
            emit_progress(scan_id, 'complete', 'No subdomains found')
            update_scan_status(thread_session, scan_id, 'completed')
            return
        
        emit_progress(scan_id, 'alive_check', 'Checking alive subdomains...')
        alive_urls = enumerator.check_alive_subdomains()
        emit_progress(scan_id, 'alive_check', f'Found {len(alive_urls)} alive subdomains')
        
        # Phase 2: URL Crawling & Parameter Extraction
        if crawl and alive_urls:
            if is_scan_cancelled(scan_id): return
            emit_progress(scan_id, 'url_crawl', 'Phase 2: Starting URL crawling...')
            
            crawler = URLCrawler(
                alive_urls=list(alive_urls),
                threads=10,
                on_endpoint_found=on_endpoint_found,
                cancel_check=lambda: is_scan_cancelled(scan_id)
            )
            
            emit_progress(scan_id, 'url_crawl', 'Crawling URLs...')
            crawler.crawl_urls()
            
            emit_progress(scan_id, 'param_extract', 'Phase 3: Extracting parameters...')
            endpoints = crawler.extract_parameters()
            emit_progress(scan_id, 'param_extract', f'Found {len(endpoints)} endpoints with parameters')
        
        # Complete scan
        update_scan_status(thread_session, scan_id, 'completed')
        
        results = get_scan_results(thread_session, scan_id)
        total_subdomains = len(results.get('subdomains', []))
        total_endpoints = len(results.get('endpoints', []))
        
        socketio.emit('scan_completed', {
            'scan_id': scan_id,
            'status': 'completed',
            'message': f'Scan completed! Found {total_subdomains} subdomains and {total_endpoints} endpoints'
        }, room=f'scan_{scan_id}')
        
        print(f"[+] Scan {scan_id} completed successfully")
    
    run_scan_with_lifecycle(scan_id, _scan)


def run_vulnscan_background(scan_id, scan_type='full', modules=None):
    def _scan(thread_session):
        if is_scan_cancelled(scan_id): return
        print(f"[*] Starting vuln scan for scan_id={scan_id}, type={scan_type}, modules={modules}")
        
        def on_progress(message):
            emit_progress(scan_id, 'vuln_scan', message)
        
        on_endpoint_found = make_endpoint_callback(thread_session, scan_id)
        
        workflow = VulnWorkflow(
            scan_id=scan_id,
            db_path=str(DB_PATH),
            modules=modules,
            scan_type=scan_type,
            on_progress=on_progress,
            on_endpoint_found=on_endpoint_found,
            cancel_check=lambda: is_scan_cancelled(scan_id)
        )
        
        results = workflow.run()
        total_vulns = results.get('total_vulnerabilities_found', 0)
        total_endpoints = results.get('total_endpoints', 0)
        ai_triggered = results.get('ai_triggered', False)
        final_status = 'running' if ai_triggered else 'completed'
        final_msg = 'Static scanners finished. AI Analysis in progress...' if ai_triggered else f'Vulnerability scan completed! Found {total_vulns} vulnerabilities across {total_endpoints} endpoints'
        
        update_scan_status(thread_session, scan_id, final_status)
        
        socketio.emit('vulnscan_completed', {
            'scan_id': scan_id,
            'status': final_status,
            'message': final_msg
        }, room=f'scan_{scan_id}')
        
        print(f"[+] Vuln scan {scan_id} done. ai_triggered={ai_triggered}, final_status={final_status}")
        
        # 🛡️ Safety timeout: if n8n fails to call /complete within 10 minutes → auto-complete the scan
        if ai_triggered:
            def _safety_complete(sid, timeout_sec=10*60):
                import time as _t
                _t.sleep(timeout_sec)
                try:
                    s = get_session(db_engine)
                    scan = get_scan_by_id(s, sid)
                    if scan and scan.status == 'running':
                        print(f"[!] Safety timeout: scan {sid} still running after {timeout_sec//60}min - auto-completing")
                        update_scan_status(s, sid, 'completed')
                        socketio.emit('scan_completed', {'scan_id': sid, 'status': 'completed',
                            'message': 'Scan auto-completed (AI timeout).'}, room=f'scan_{sid}')
                    s.close()
                except Exception as ex:
                    print(f"[!] Safety timeout error: {ex}")
            threading.Thread(target=_safety_complete, args=(scan_id,), daemon=True).start()
        
        workflow.close()
    
    run_scan_with_lifecycle(scan_id, _scan)


def run_local_scan_background(target_url, scan_id):
    """Run Selenium-based local crawl in background thread."""
    def _scan(thread_session):
        if is_scan_cancelled(scan_id): return
        # Translate localhost → host.docker.internal when running in Docker
        effective_url = _docker_translate_url(target_url)
        print(f"[*] Starting LOCAL scan {scan_id} for {effective_url}")
        
        on_endpoint_found = make_endpoint_callback(thread_session, scan_id)
        
        def on_progress(message):
            emit_progress(scan_id, 'local_crawl', message)
        
        # Save the base URL as a "subdomain" entry so stats work
        emit_progress(scan_id, 'local_crawl', 'Registering local target...')
        # Save the user-facing URL (localhost), not the Docker-internal one
        save_subdomain(thread_session, scan_id, _docker_reverse_url(effective_url),
                      is_alive=1, status_code=200, title='Local Target')
        
        # Run Selenium crawler
        if is_scan_cancelled(scan_id): return
        emit_progress(scan_id, 'local_crawl', 'Starting Selenium crawler...')
        
        crawler = LocalCrawler(
            base_url=effective_url,
            max_depth=5,
            max_pages=500,
            on_endpoint_found=on_endpoint_found,
            on_progress=on_progress,
            cancel_check=lambda: is_scan_cancelled(scan_id)
        )
        
        endpoints = crawler.crawl()
        summary = crawler.get_summary()
        
        # Complete
        update_scan_status(thread_session, scan_id, 'completed')
        
        results = get_scan_results(thread_session, scan_id)
        total_endpoints = len(results.get('endpoints', []))
        
        socketio.emit('scan_completed', {
            'scan_id': scan_id,
            'status': 'completed',
            'message': (f'Local scan completed! '
                       f'Visited {summary["pages_visited"]} pages, '
                       f'found {total_endpoints} endpoints '
                       f'({summary["get_endpoints"]} GET, {summary["post_endpoints"]} POST)')
        }, room=f'scan_{scan_id}')
        
        print(f"[+] Local scan {scan_id} completed successfully")
    
    run_scan_with_lifecycle(scan_id, _scan)


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/scans', methods=['GET'])
def list_scans():
    try:
        db_session.expire_all()  # Refresh to pick up raw sqlite3 inserts from sqli.py
        scans = get_all_scans(db_session)
        
        result = []
        for scan in scans:
            subdomains = get_subdomains(db_session, scan.id)
            endpoints = get_endpoints(db_session, scan.id)
            vulns = get_vulnerabilities(db_session, scan.id)
            
            result.append({
                'id': scan.id,
                'domain': scan.domain,
                'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
                'status': scan.status,
                'subdomain_count': len(subdomains),
                'endpoint_count': len(endpoints),
                'vulnerability_count': len(vulns)
            })
        
        return jsonify({'success': True, 'scans': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans', methods=['POST'])
def create_new_scan():
    """Create new scan — auto-detects local vs remote target""" #git
    try:
        data = request.json
        target = data.get('target', '').strip()
        crawl = data.get('crawl', True)
        passive = data.get('passive', True)
        active = data.get('active', False)
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        # Check if this is a local target #git
        if is_local_target(target):
            # Local target — use Selenium crawler
            # Ensure it has a scheme
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            scan_id = create_scan(db_session, target, 'local_crawl')
            cancelled_scans.discard(scan_id)  # Clear any stale cancellation
            
            thread = threading.Thread(
                target=run_local_scan_background,
                args=(target, scan_id)
            )
            thread.daemon = True
            thread.start()
            
            active_scans[scan_id] = thread
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'message': f'Local scan started for {target}'
            })
        
        else:
            # Remote target — standard subdomain enum + crawl pipeline
            domain = target.replace('http://', '').replace('https://', '').strip('/')
            
            scan_type = 'passive'
            if passive and active:
                scan_type = 'full'
            elif active and not passive:
                scan_type = 'active'
            
            scan_id = create_scan(db_session, domain, scan_type)
            cancelled_scans.discard(scan_id)  # Clear any stale cancellation
            
            thread = threading.Thread(
                target=run_scan_background,
                args=(domain, scan_id),
                kwargs={'passive': passive, 'active': active, 'crawl': crawl}
            )
            thread.daemon = True
            thread.start()
            
            active_scans[scan_id] = thread
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'message': f'Domain scan started for {domain}'
            })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    try:
        db_session.expire_all()  # Refresh to pick up status changes from background threads
        results = get_scan_results(db_session, scan_id)
        
        if not results:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
        
        # Normalize all URLs to localhost for display
        for ep in results.get('endpoints', []):
            ep['url'] = _docker_reverse_url(ep.get('url', ''))
        for v in results.get('vulnerabilities', []):
            v['url'] = _docker_reverse_url(v.get('url', ''))
        
        return jsonify({
            'success': True,
            'scan': results
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete scan and all related data (subdomains, endpoints, vulnerabilities).
    If the scan is still running, signal its background thread to stop."""
    try:
        from sqlalchemy import text
        
        # Signal cancellation so the background thread stops
        cancelled_scans.add(scan_id)
        active_scans.pop(scan_id, None)
        
        # Give background thread a moment to notice the cancellation
        import time
        time.sleep(0.3)
        
        # First, expire and close any pending transactions on global session
        # This releases the database lock
        try:
            db_session.expire_all()
            db_session.close()
        except:
            pass
        
        # Use a fresh connection for raw SQL to avoid ORM session issues
        with db_engine.connect() as conn:
            # First check if scan exists
            result = conn.execute(text("SELECT domain FROM scan_history WHERE id = :id"), {"id": scan_id})
            row = result.fetchone()
            
            if not row:
                cancelled_scans.discard(scan_id)
                return jsonify({'success': False, 'error': 'Scan not found'}), 404
            
            domain = row[0]
            
            # Delete in order: vulnerabilities -> endpoints -> subdomains -> scan
            conn.execute(text("DELETE FROM vulnerabilities WHERE scan_id = :id"), {"id": scan_id})
            conn.execute(text("DELETE FROM endpoints WHERE scan_id = :id"), {"id": scan_id})
            conn.execute(text("DELETE FROM subdomains WHERE scan_id = :id"), {"id": scan_id})
            conn.execute(text("DELETE FROM scan_history WHERE id = :id"), {"id": scan_id})
            conn.commit()
        
        # NOTE: Do NOT discard from cancelled_scans here.
        # The background thread's run_scan_with_lifecycle finally block
        # will clean it up once the thread actually stops.
        
        print(f"[*] Deleted scan {scan_id} for {domain}")
        
        return jsonify({
            'success': True,
            'message': f'Scan {scan_id} for {domain} deleted successfully'
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/all', methods=['DELETE']) #delete all
def delete_all_scans():
    try:
        from sqlalchemy import text
        
        # Signal cancellation for all active scans
        for sid in list(active_scans.keys()):
            cancelled_scans.add(sid)
        active_scans.clear()
        
        # Give background threads a moment to notice the cancellation
        import time
        time.sleep(0.3)
        
        # Expire and close any pending transactions
        try:
            db_session.expire_all()
            db_session.close()
        except:
            pass
        
        with db_engine.connect() as conn:
            # Count scans before deleting
            result = conn.execute(text("SELECT COUNT(*) FROM scan_history"))
            count = result.fetchone()[0]
            
            if count == 0:
                return jsonify({'success': False, 'error': 'No scans to delete'}), 404
            
            # Delete all in order: vulnerabilities -> endpoints -> subdomains -> scans
            conn.execute(text("DELETE FROM vulnerabilities"))
            conn.execute(text("DELETE FROM endpoints"))
            conn.execute(text("DELETE FROM subdomains"))
            conn.execute(text("DELETE FROM scan_history"))
            conn.commit()
        
        # NOTE: Do NOT clear cancelled_scans here.
        # Background threads' run_scan_with_lifecycle finally blocks
        # will clean up their own IDs once they actually stop.
        
        print(f"[*] Deleted all {count} scans")
        
        return jsonify({
            'success': True,
            'message': f'All {count} scans deleted successfully',
            'deleted_count': count
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/search', methods=['GET'])
def search_existing_scans():
    """Search for existing completed scans that have endpoints for a target."""
    try:
        target = request.args.get('target', '').strip()
        if not target:
            return jsonify({'success': True, 'scans': []})

        # Normalize: strip scheme and trailing slash
        normalized = target.replace('http://', '').replace('https://', '').strip('/')

        all_scans = get_all_scans(db_session)
        matching = []
        for scan in all_scans:
            scan_domain = scan.domain.replace('http://', '').replace('https://', '').strip('/')
            if normalized.lower() in scan_domain.lower() or scan_domain.lower() in normalized.lower():
                if scan.status != 'completed':
                    continue
                endpoints = get_endpoints(db_session, scan.id)
                if endpoints:
                    matching.append({
                        'id': scan.id,
                        'domain': scan.domain,
                        'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
                        'endpoint_count': len(endpoints),
                    })

        return jsonify({'success': True, 'scans': matching})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnscan/start', methods=['POST']) #git
def start_vulnscan_new():
    try:
        data = request.json or {}
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'full')
        modules = data.get('modules', ['sqli'])
        fresh = data.get('fresh', False)  # If True, always create a new scan
        
        if not target:
            return jsonify({'success': False, 'error': 'Target URL is required'}), 400
        
        # Ensure URL has a scheme
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Try to reuse an existing completed scan with endpoints for this target
        # (skip reuse if user explicitly requested a fresh scan)
        scan_id = None
        if not fresh:
            normalized = target.replace('http://', '').replace('https://', '').strip('/')
            all_scans = get_all_scans(db_session)
            for scan in all_scans:
                scan_domain = scan.domain.replace('http://', '').replace('https://', '').strip('/')
                if normalized.lower() == scan_domain.lower() and scan.status == 'completed':
                    endpoints = get_endpoints(db_session, scan.id)
                    if endpoints:
                        scan_id = scan.id
                        print(f"[*] Reusing existing scan {scan_id} for {target}")
                        # Reset status to running
                        update_scan_status(db_session, scan_id, 'running')
                        break
        
        # If no existing scan found, create a new one
        if scan_id is None:
            # Store domain without scheme for remote targets, consistent with recon scans
            if is_local_target(target):
                scan_id = create_scan(db_session, target, 'vulnscan')
            else:
                domain = target.replace('http://', '').replace('https://', '').strip('/')
                scan_id = create_scan(db_session, domain, 'vulnscan')
        

        cancelled_scans.discard(scan_id)

        

        thread = threading.Thread(
            target=run_vulnscan_background,
            args=(scan_id,),
            kwargs={'scan_type': scan_type, 'modules': modules}
        )
        thread.daemon = True
        thread.start()
        
        active_scans[scan_id] = thread
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Vulnerability scan started for {target} (modules: {", ".join(modules)})'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/vulnscan', methods=['POST']) #git
def start_vulnscan(scan_id):
    try:
        data = request.json or {}
        scan_type = data.get('scan_type', 'full')
        modules = data.get('modules', ['sqli'])
        
        # Check if scan exists
        scan = get_scan_by_id(db_session, scan_id)
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
        
        # Check if already running
        if scan_id in active_scans:
            return jsonify({'success': False, 'error': 'Scan already running'}), 409
        
        # Update scan status
        update_scan_status(db_session, scan_id, 'running')
        

        
        thread = threading.Thread(
            target=run_vulnscan_background,
            args=(scan_id,),
            kwargs={'scan_type': scan_type, 'modules': modules}
        )
        thread.daemon = True
        thread.start()
        
        active_scans[scan_id] = thread
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Vulnerability scan started (modules: {", ".join(modules)})'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# n8n AI AGENT ENDPOINTS — Receive IDOR findings from the external AI Agent
# ============================================================================

@app.route('/api/scans/<int:scan_id>/complete', methods=['POST'])
def mark_scan_complete(scan_id):
    """Mark a scan as completed (called by n8n after AI analysis)."""
    try:
        scan = get_scan_by_id(db_session, scan_id)
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404

        update_scan_status(db_session, scan_id, 'completed')

        socketio.emit('scan_completed', {
            'scan_id': scan_id,
            'status': 'completed',
            'message': 'AI Analysis completed! All vulnerabilities have been saved.'
        }, room=f'scan_{scan_id}')

        print(f"[+] Scan {scan_id} marked as completed via Webhook")
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/vulnerabilities', methods=['POST'])
def add_external_vulnerability(scan_id):
    """Receive a vulnerability discovered by the n8n AI Agent and save it."""
    try:
        data = request.json or {}

        vuln_type  = data.get('vulnerability_type', 'IDOR')
        severity   = data.get('severity', 'High')
        url        = data.get('url', '')
        method     = data.get('method', 'GET')
        parameter  = data.get('parameter', '')
        payload    = data.get('payload', '')
        evidence   = data.get('evidence', '')

        if not url:
            return jsonify({'success': False, 'error': 'url is required'}), 400

        # Normalize Docker-internal URL to localhost before storing
        url = _docker_reverse_url(url)

        scan = get_scan_by_id(db_session, scan_id)
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404

        save_vulnerability(
            db_session, scan_id,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            method=method,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            vuln_data='Discovered by n8n AI Agent'
        )

        emit_progress(
            scan_id, 'n8n_agent',
            f'⚠️ AI Agent found {vuln_type}: {url} (param: {parameter})'
        )

        print(f'[n8n] Saved {vuln_type} for scan {scan_id} at {url}')
        return jsonify({'success': True, 'message': 'Vulnerability saved successfully'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/vulnerabilities', methods=['GET']) #git
def get_scan_vulnerabilities(scan_id):
    try:
        db_session.expire_all()  # Refresh to pick up raw sqlite3 inserts from sqli.py
        vulns = get_vulnerabilities(db_session, scan_id)
        
        result = []
        for v in vulns:
            result.append({
                'id': v.id,
                'type': v.vulnerability_type,
                'severity': v.severity,
                'url': _docker_reverse_url(v.url),
                'method': v.method,
                'parameter': v.parameter,
                'payload': v.payload,
                'evidence': v.evidence,
                'discovered_at': v.discovered_at.isoformat() if v.discovered_at else None
            })
        
        return jsonify({'success': True, 'vulnerabilities': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/stats', methods=['GET'])
def get_scan_stats(scan_id):
    try:
        db_session.expire_all()  # Refresh to pick up raw sqlite3 inserts
        subdomains = get_subdomains(db_session, scan_id)
        endpoints = get_endpoints(db_session, scan_id)
        vulns = get_vulnerabilities(db_session, scan_id)
        
        get_count = sum(1 for e in endpoints if e.method == 'GET')
        post_count = sum(1 for e in endpoints if e.method == 'POST')
        
        # All stored subdomains are alive (we only save alive ones now)
        stats = {
            'total_subdomains': len(subdomains),
            'get_endpoints': get_count,
            'post_endpoints': post_count,
            'vulnerability_count': len(vulns)
        }
        
        return jsonify({'success': True, 'stats': stats})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/subdomains', methods=['GET'])
def get_scan_subdomains(scan_id):
    try:
        subdomains = get_subdomains(db_session, scan_id)
        
        result = []
        for s in subdomains:
            result.append({
                'id': s.id,
                'subdomain': _docker_reverse_url(s.subdomain),
                'is_alive': s.is_alive,
                'status_code': s.status_code,
                'title': s.title or ''
            })
        
        return jsonify({'success': True, 'subdomains': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/endpoints', methods=['GET'])
def get_scan_endpoints(scan_id):
    try:
        endpoints = get_endpoints(db_session, scan_id)

        # Use ?docker=1 query param for n8n/Docker callers that need
        # host.docker.internal URLs to reach host services.
        # Default behavior: return localhost URLs for the dashboard.
        wants_docker = request.args.get('docker', '0') == '1'

        def _translate(url):
            if not url:
                return url
            if wants_docker:
                # n8n or other Docker service — needs host.docker.internal to reach host
                return url.replace('://localhost', '://host.docker.internal') \
                          .replace('://127.0.0.1', '://host.docker.internal')
            # Browser/dashboard — always show localhost
            return _docker_reverse_url(url)

        result = []
        for e in endpoints:
            result.append({
                'id': e.id if hasattr(e, 'id') else None,
                'url': _translate(e.url if hasattr(e, 'url') else ''),
                'method': e.method if hasattr(e, 'method') else 'GET',
                'parameters': e.parameters if hasattr(e, 'parameters') else {},
                'body_params': e.body_params if hasattr(e, 'body_params') else {},
                'source': e.source if hasattr(e, 'source') else '',
                'form_details': e.form_details if hasattr(e, 'form_details') else {}
            })

        return jsonify({'success': True, 'endpoints': result})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    try:
        db_session.expire_all()  # Refresh to pick up raw sqlite3 inserts
        all_scans = get_all_scans(db_session)
        
        total_scans = len(all_scans)
        running_scans = sum(1 for s in all_scans if s.status == 'running')
        
        total_subdomains = 0
        total_endpoints = 0
        total_vulnerabilities = 0
        
        for scan in all_scans:
            subdomains = get_subdomains(db_session, scan.id)
            endpoints = get_endpoints(db_session, scan.id)
            vulns = get_vulnerabilities(db_session, scan.id)
            total_subdomains += len(subdomains)
            total_endpoints += len(endpoints)
            total_vulnerabilities += len(vulns)
        
        stats = {
            'total_scans': total_scans,
            'running_scans': running_scans,
            'total_subdomains': total_subdomains,
            'total_endpoints': total_endpoints,
            'total_vulnerabilities': total_vulnerabilities
        }
        
        return jsonify({'success': True, 'stats': stats})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# AI REPORT GENERATION
# ============================================================================

@app.route('/api/scans/<int:scan_id>/report', methods=['POST'])
def generate_ai_report(scan_id):
    """Generate an AI-powered PDF security assessment report for a scan."""
    try:
        from flask import send_file
        import io

        # Check scan exists
        scan = get_scan_by_id(db_session, scan_id)
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404

        # Get vulnerabilities for this scan
        vuln_data = ai_get_vulns(str(DB_PATH), scan_id)

        if vuln_data['total_vulnerabilities'] == 0:
            return jsonify({'success': False, 'error': 'No vulnerabilities found for this scan. Run a vulnerability scan first.'}), 400

        print(f"[*] Generating AI report for scan {scan_id} ({vuln_data['total_vulnerabilities']} vulns)...")

        # AI generates styled HTML report
        html_report = generate_report_html(vuln_data)

        # Convert HTML → PDF bytes
        pdf_bytes = html_to_pdf_bytes(html_report)

        print(f"[+] AI report generated for scan {scan_id} ({len(pdf_bytes) / 1024:.0f} KB)")

        # Stream PDF back to client
        domain_safe = scan.domain.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
        filename = f"NileDefender_Report_{domain_safe}_{datetime.now().strftime('%Y%m%d')}.pdf"

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# AGGREGATE API ROUTES (across all scans)
# ============================================================================

@app.route('/api/all/subdomains', methods=['GET'])
def get_all_subdomains():
    try:
        db_session.expire_all()
        all_scans = get_all_scans(db_session)
        result = []
        for scan in all_scans:
            subdomains = get_subdomains(db_session, scan.id)
            for s in subdomains:
                result.append({
                    'id': s.id,
                    'scan_id': scan.id,
                    'domain': scan.domain,
                    'subdomain': _docker_reverse_url(s.subdomain),
                    'status_code': s.status_code,
                    'title': s.title or ''
                })
        return jsonify({'success': True, 'subdomains': result, 'total': len(result)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/all/endpoints', methods=['GET'])
def get_all_endpoints():
    try:
        db_session.expire_all()
        all_scans = get_all_scans(db_session)
        result = []
        for scan in all_scans:
            endpoints = get_endpoints(db_session, scan.id)
            for e in endpoints:
                result.append({
                    'id': e.id if hasattr(e, 'id') else None,
                    'scan_id': scan.id,
                    'domain': scan.domain,
                    'url': _docker_reverse_url(e.url if hasattr(e, 'url') else ''),
                    'method': e.method if hasattr(e, 'method') else 'GET',
                    'parameters': e.parameters if hasattr(e, 'parameters') else {},
                    'body_params': e.body_params if hasattr(e, 'body_params') else {},
                    'source': e.source if hasattr(e, 'source') else ''
                })
        return jsonify({'success': True, 'endpoints': result, 'total': len(result)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/all/vulnerabilities', methods=['GET'])
def get_all_vulnerabilities():
    try:
        db_session.expire_all()
        all_scans = get_all_scans(db_session)
        result = []
        for scan in all_scans:
            vulns = get_vulnerabilities(db_session, scan.id)
            for v in vulns:
                result.append({
                    'id': v.id,
                    'scan_id': scan.id,
                    'domain': scan.domain,
                    'type': v.vulnerability_type,
                    'severity': v.severity,
                    'url': _docker_reverse_url(v.url),
                    'method': v.method,
                    'parameter': v.parameter,
                    'payload': v.payload,
                    'evidence': v.evidence,
                    'discovered_at': v.discovered_at.isoformat() if v.discovered_at else None
                })
        return jsonify({'success': True, 'vulnerabilities': result, 'total': len(result)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    print("[WebSocket] Client connected")
    emit('connected', {'message': 'Connected to NileDefender'})


@socketio.on('join_scan')
def handle_join_scan(data):
    scan_id = data.get('scan_id')
    if scan_id:
        room = f'scan_{scan_id}'
        join_room(room)
        print(f"[WebSocket] Client joined scan {scan_id}")


# ============================================================================
# SERVE REACT FRONTEND (or fallback to old templates)
# ============================================================================

@app.route('/')
@app.route('/<path:path>')
def serve_frontend(path=''):
    """Serve the React SPA. Falls back to old templates if no build exists."""
    if FRONTEND_DIST.exists():
        # Serve static files from dist
        file_path = FRONTEND_DIST / path
        if path and file_path.is_file():
            return send_from_directory(str(FRONTEND_DIST), path)
        # All other routes → index.html (client-side routing)
        return send_from_directory(str(FRONTEND_DIST), 'index.html')
    else:
        # Fallback: old Jinja template
        return render_template('index.html')


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🛡️  NILEDEFENDER - WEB VULNERABILITY SCANNER")
    print("="*70)
    print(f"🌐 Web Interface: http://localhost:5000")
    print(f"💾 Database: niledefender.db")
    print(f"📡 WebSocket: Enabled")
    print("="*70)
    print("\n[*] Starting server...")
    print("[*] Press CTRL+C to stop\n")
    
    # Run with SocketIO
    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n[*] Server stopped gracefully. Goodbye!")

