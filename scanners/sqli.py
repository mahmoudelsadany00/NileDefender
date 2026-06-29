import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import threading

# Docker networking: translate localhost URLs to host.docker.internal
_IN_DOCKER = os.environ.get('RUNNING_IN_DOCKER', '0') == '1'

def _docker_translate_url(url: str) -> str:
    if not _IN_DOCKER:
        return url
    url = url.replace('://localhost', '://host.docker.internal')
    url = url.replace('://127.0.0.1', '://host.docker.internal')
    return url

def _docker_reverse_url(url: str) -> str:
    """Reverse Docker URL translation for display/storage."""
    if not url:
        return url
    return url.replace('://host.docker.internal', '://localhost')

DB_PATH = "niledefender.db"
WORKERS = 3
LIMIT = 5  # Increased for thorough scanning


def check_database():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found: {DB_PATH}")
        return False
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            for table in ("vulnerabilities", "endpoints"):
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
                if not cur.fetchone():
                    print(f"Error: '{table}' table not found in database")
                    return False
        return True
    except Exception as e:
        print(f"Database check error: {e}")
        return False





def flatten(raw):
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(data, dict):
            return {}
        return {k: str(v.get("value", v) if isinstance(v, dict) else v) for k, v in data.items()}
    except Exception:
        return {}


def calculate_sqli_score(url, method, params):
    url_lower = url.lower()

    if any(p in url_lower for p in ['captcha','logout','robots.txt','favicon','static','css','js','img','image','upload','download','print','export','pdf']):
        return -1

    score = 0
    if 'sqli' in url_lower:  
        score += 50
    elif any(p in url_lower for p in ['sql','search','login','user','id','product','article','page','news','item','category','post']):
        score += 15

    high_risk = {'id','user','userid','username','login','email','search','query','keyword','title','name','pass','password','page','category','cat','item','product','article','order','sort','filter'}
    for p in params:
        pl = p.lower()
        if pl in high_risk:
            score += 20
        elif pl.endswith('id') or pl.startswith('id'):  
            score += 25

    score += 10 if len(params) >= 3 else (5 if len(params) >= 2 else 0)
    if method == "GET":            score += 5
    if any(v and v.isdigit() for v in params.values()): score += 10

    return score


def get_targets(db_path=None, scan_id=None):
    db = db_path or DB_PATH
    targets_with_scores = []
    skipped_count = 0

    try:
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            if scan_id:
                query = "SELECT url, method, parameters, body_params FROM endpoints WHERE scan_id = ?"
                rows = conn.execute(query, (scan_id,))
            else:
                rows = conn.execute("SELECT url, method, parameters, body_params FROM endpoints")

            for row in rows:
                url    = _docker_translate_url(row["url"])
                method = (row["method"] or "GET").upper()
                params = flatten(row["body_params"] if method == "POST" else row["parameters"])

                if not params or all(not v for v in params.values()):
                    continue

                score = calculate_sqli_score(url, method, params)
                if score < 0:
                    skipped_count += 1
                    continue

                if method == "GET":
                    parts = urlsplit(url)
                    q = {**dict(parse_qsl(parts.query)), **params}
                    url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
                    data = None
                else:
                    data = urlencode(params)

                targets_with_scores.append((score, url, method, data))
    except Exception as e:
        print(f"DB Error: {e}")
        return []

    targets_with_scores.sort(reverse=True, key=lambda x: x[0])

    seen, unique_targets = set(), []
    for item in targets_with_scores:
        key = item[1:]
        if key not in seen:
            seen.add(key)
            unique_targets.append(item)

    if unique_targets:
        sep = "=" * 80
        print(f"\n{sep}\nIntelligent Filtering: Analyzed {len(unique_targets)} unique endpoints")
        if skipped_count:
            print(f"Skipped {skipped_count} blacklisted URLs")
        print(f"Top 5 High-Risk Targets:")
        for i, (score, url, method, _) in enumerate(unique_targets[:5], 1):
            print(f"  {i}. [Score: {score:3d}] {method:4s} {url}")
        print(sep)

    selected = unique_targets[:LIMIT]

    return [(url, method, data) for _, url, method, data in selected]


def parse_log(content):
    parameter = "Unknown"
    payload   = ""

    for line in content.split('\n'):
        if "Parameter:" in line and parameter == "Unknown":
            parameter = line.split("Parameter:")[-1].strip().split()[0]
        if "Payload:" in line and not payload:
            payload = line.split("Payload:")[-1].strip()

    if not payload:
        m = re.search(r"(['\"]\\s*(?:OR|AND|UNION).*?['\"])", content, re.IGNORECASE)
        payload = m.group(0)[:200] if m else "Check vulnerability_data for details"

    return parameter, payload.strip()


def scan_target(target, scan_id: int, cookie=None, db_path=None, on_progress=None, cancel_check=None):
    db = db_path or DB_PATH
    url, method, data = target
    out_dir = f"scan_{hashlib.md5((url + str(data or '')).encode()).hexdigest()[:12]}"

    cmd = ["sqlmap", "-u", url, "--batch", "--random-agent",
           "--level=1", "--risk=1",
           "--threads=3", "--timeout=10", "--retries=1", "--time-sec=5",
           f"--output-dir={out_dir}",
           "--disable-coloring", "--technique=BET"]
    if cookie: cmd.append(f"--cookie={cookie}")
    if data:   cmd.extend(["--data", data])

    msg = f"[SCANNING] {method} {url}"
    print(msg)
    if on_progress:
        on_progress(msg)

    result = None
    proc = None
    try:
        # Start sqlmap in its own process group so we can kill the entire tree
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=os.setsid)
        
        # Wait for process to finish, checking for cancellation
        while proc.poll() is None:
            if cancel_check and cancel_check():
                # Kill entire process group (sqlmap + children)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                msg = f"[CANCELLED] {url}"
                print(msg)
                if on_progress:
                    on_progress(msg)
                shutil.rmtree(out_dir, ignore_errors=True)
                return None
            time.sleep(0.5)
        
        # Check if process completed with timeout (returncode)
        if proc.returncode is None:
            proc.terminate()

        log_path = next(
            (os.path.join(r, "log") for r, _, f in os.walk(out_dir) if "log" in f), None
        )

        if log_path:
            content = open(log_path, encoding="utf-8", errors="ignore").read()
            is_vuln = (
                ("Type:" in content and "Parameter:" in content) or
                "sqlmap identified the following injection point" in content or
                "injectable" in content.lower()
            )
            if is_vuln:
                parameter, payload = parse_log(content)
                msg = f"[VULNERABLE] {url} — param: {parameter}"
                print(msg)
                if on_progress:
                    on_progress(msg)

                for attempt in range(5):
                    try:
                        with sqlite3.connect(db, timeout=10) as conn:
                            conn.execute("PRAGMA journal_mode=WAL")
                            conn.execute(
                                """INSERT OR IGNORE INTO vulnerabilities
                                (scan_id, vulnerability_type, severity, url, method, parameter, payload, evidence, vulnerability_data, discovered_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (scan_id, "SQL Injection", "High", _docker_reverse_url(url), method,
                                 parameter, payload, "sqlmap detection", content,
                                 time.strftime("%Y-%m-%d %H:%M:%S")),
                            )
                            saved = conn.execute("SELECT changes()").fetchone()[0]
                            print("[SAVED]" if saved else "[DUPLICATE]")
                            conn.commit()
                        break
                    except sqlite3.OperationalError:
                        time.sleep(0.5 * (attempt + 1))
                else:
                    print(f"[DB ERROR] Failed after 5 attempts: {url}")

                result = {
                    "url": url, "method": method, "parameter": parameter,
                    "payload": payload, "vulnerable": True
                }
            else:
                msg = f"[CLEAN] {url}"
                print(msg)
                if on_progress:
                    on_progress(msg)
        else:
            msg = f"[NO LOG] {url}"
            print(msg)
            if on_progress:
                on_progress(msg)
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
        msg = f"[TIMEOUT] {url}"
        print(msg)
        if on_progress:
            on_progress(msg)
    except Exception as e:
        msg = f"[ERROR] {url}: {e}"
        print(msg)
        if on_progress:
            on_progress(msg)
    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                try:
                    proc.kill()
                except:
                    pass
        shutil.rmtree(out_dir, ignore_errors=True)

    return result


# ============================================================================
# HIGH-LEVEL API — called from server.py
# ============================================================================

def run_sqli_scan(scan_id, db_path, on_progress=None, cookie=None, cancel_check=None):
    if on_progress:
        on_progress("Starting SQL Injection scan...")

    targets = get_targets(db_path=db_path, scan_id=scan_id)

    if not targets:
        msg = "No injectable targets found for this scan."
        print(msg)
        if on_progress:
            on_progress(msg)
        return {"targets_scanned": 0, "vulnerabilities_found": 0}

    msg = f"Found {len(targets)} potential SQLi targets"
    print(msg)
    if on_progress:
        on_progress(msg)



    vuln_count = 0
    scanned_count = 0
    for i, target in enumerate(targets, 1):
        if cancel_check and cancel_check():
            if on_progress:
                on_progress("Scan cancelled — stopping")
            break

        if on_progress:
            on_progress(f"Scanning target {i}/{len(targets)}: {target[0][:80]}")

        result = scan_target(
            target, scan_id=scan_id, cookie=cookie,
            db_path=db_path, on_progress=on_progress,
            cancel_check=cancel_check
        )
        scanned_count += 1
        if result and result.get("vulnerable"):
            vuln_count += 1

    summary = f"SQLi scan complete: {len(targets)} targets scanned, {vuln_count} vulnerabilities found"
    print(summary)
    if on_progress:
        on_progress(summary)

    return {"targets_scanned": scanned_count, "vulnerabilities_found": vuln_count}
