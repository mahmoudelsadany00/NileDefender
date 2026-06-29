import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse, urlsplit, urlunsplit

# Define dalfox binary path dynamically
DALFOX_PATH = "dalfox"  # Default fallback

# Common installation directories to search
possible_paths = [
    "/usr/local/bin/dalfox",
    "/usr/bin/dalfox",
    os.path.expanduser("~/go/bin/dalfox"),
    "/root/go/bin/dalfox",
    "/snap/bin/dalfox",
]
for path in possible_paths:
    if os.path.exists(path) and os.access(path, os.X_OK):
        DALFOX_PATH = path
        break

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

DB_PATH  = "niledefender.db"
WORKERS  = 3
LIMIT    = 20

SKIP_PATTERNS = ('logout', 'robots.txt', 'favicon', 'static', 'css', 'sqli',
                 'img', 'image', 'upload', 'download', 'pdf', 'export')

NUMERIC_HINTS = ("id", "num", "page", "count", "limit", "offset", "size", "qty", "age")
EMAIL_HINTS   = ("email", "mail")
URL_HINTS     = ("url", "link", "href", "redirect", "return", "next", "callback", "ref")
DATE_HINTS    = ("date", "time", "day", "month", "created", "updated", "from", "to")

XSS_URL_HIGH   = ('xss', 'htmli', 'iframe', 'inject')
XSS_URL_MEDIUM = ('search', 'comment', 'feedback', 'message', 'input',
                  'content', 'page', 'news', 'article', 'post', 'profile', 'blog')

XSS_PARAM_HIGH   = {'name', 'search', 'query', 'q', 'text', 'message', 'comment',
                    'content', 'title', 'input', 'feedback', 'subject', 'body',
                    'description', 'username', 'firstname', 'lastname'}
XSS_PARAM_MEDIUM = {'url', 'redirect', 'return', 'next', 'callback', 'ref',
                    'lang', 'language', 'page', 'email', 'data', 'value'}

VULN_KEYWORDS = ("[v]", "[found]", "reflected xss", "stored xss",
                 "[poc]", "xss vulnerability", "verified")


def flatten(raw):
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(data, dict): return {}
        return {k: str(v.get("value", v) if isinstance(v, dict) else v) for k, v in data.items()}
    except Exception:
        return {}

def _fill_params(params: dict) -> dict:
    filled = {}
    for k, v in params.items():
        if v and v.strip():
            filled[k] = v; continue
        kl = k.lower()
        if   any(h in kl for h in EMAIL_HINTS):   filled[k] = "test@example.com"
        elif any(h in kl for h in URL_HINTS):      filled[k] = "http://example.com"
        elif any(h in kl for h in DATE_HINTS):     filled[k] = "2026-05-09"
        elif any(h in kl for h in NUMERIC_HINTS):  filled[k] = "1"
        else:                                       filled[k] = "test"
    return filled

def _xss_score(url: str, params: dict) -> int:
    ul    = url.lower()
    score = 0
    if   any(p in ul for p in XSS_URL_HIGH):   score += 40
    elif any(p in ul for p in XSS_URL_MEDIUM):  score += 15
    for p in params:
        pl = p.lower()
        if   pl in XSS_PARAM_HIGH:   score += 25
        elif pl in XSS_PARAM_MEDIUM: score += 10
    return score

def get_targets(db_path=None, scan_id=None):
    db = db_path or DB_PATH
    scored, seen = [], set()
    try:
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            if scan_id:
                rows = conn.execute("SELECT url, method, parameters, body_params FROM endpoints WHERE scan_id = ?", (scan_id,))
            else:
                rows = conn.execute("SELECT url, method, parameters, body_params FROM endpoints")

            for row in rows:
                url    = _docker_translate_url(row["url"])
                method = (row["method"] or "GET").upper()
                params = flatten(row["body_params"] if method == "POST" else row["parameters"])

                if not params: continue
                if any(p in url.lower() for p in SKIP_PATTERNS): continue

                params = _fill_params(params)
                score  = _xss_score(url, params)

                if method == "POST" and "form" not in params:
                    params["form"] = "submit"

                if method == "GET":
                    parts = urlsplit(url)
                    q     = {**dict(parse_qsl(parts.query)), **params}
                    url   = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
                    data  = None
                else:
                    data = urlencode(params)

                key = (url, method, data)
                if key not in seen:
                    seen.add(key)
                    scored.append((score, url, method, data))

    except Exception as e:
        print(f"DB Error: {e}")
        return []

    scored.sort(reverse=True, key=lambda x: x[0])
    return [(url, method, data) for _, url, method, data in scored[:LIMIT]]


def parse_dalfox_output(content):
    parameter, payload = "Unknown", ""

    for line in content.splitlines():
        if parameter == "Unknown":
            m = re.search(r"(?:param(?:eter)?|inject(?:ed)?)[:\s]+['\"]?(\w+)['\"]?", line, re.IGNORECASE)
            if m:
                parameter = m.group(1)

        poc = re.search(r"\[POC\].*?(https?://\S+)", line)
        if poc:
            poc_url   = poc.group(1)
            qs_params = parse_qs(urlparse(poc_url).query)
            for k, v in qs_params.items():
                decoded = unquote(v[0])
                if any(x in decoded.lower() for x in ("<script", "javascript:", "onerror", "onload", "alert")):
                    parameter = k
                    payload   = decoded[:300]
                    break
            if not payload and qs_params:
                k         = next(iter(qs_params))
                parameter = k
                payload   = unquote(qs_params[k][0])[:300]
            break

    if not payload:
        m = re.search(
            r"(<script[^>]*>.*?</script>|javascript:[^\s\"']+|on\w+\s*=\s*['\"][^'\"]+['\"])",
            content, re.IGNORECASE)
        if m:
            payload = unquote(m.group(0))[:300]

    return parameter, (payload or "Check vulnerability_data for details").strip()


def scan_target(target, scan_id: int, db_path=None, cookie=None, cancel_check=None):
    db  = db_path or DB_PATH
    url, method, data = target
    out_file = f"dalfox_{hashlib.md5((url + str(data or '')).encode()).hexdigest()[:12]}.txt"

    cmd = [DALFOX_PATH, "url", url,
           "--output", out_file,
           "--timeout", "10", "--worker", "10",
           "--no-color", "--follow-redirects",
           "--header", "X-Requested-With: XMLHttpRequest"]

    if cookie:              cmd.extend(["--cookie", cookie])

    if method == "POST" and data:
        cmd.extend(["--data", data])
        cmd.extend(["--method", "POST"])

    try:
        if cancel_check and cancel_check():
            return None

        result       = subprocess.run(cmd, timeout=120, capture_output=True, text=True, errors="ignore", stdin=subprocess.DEVNULL)
        file_content = open(out_file, encoding="utf-8", errors="ignore").read() if os.path.exists(out_file) else ""
        content      = file_content + result.stdout + result.stderr

        if any(kw in content.lower() for kw in VULN_KEYWORDS):
            parameter, payload = parse_dalfox_output(content)
            for attempt in range(5):
                try:
                    with sqlite3.connect(db, timeout=10) as conn:
                        conn.execute("PRAGMA journal_mode=WAL")
                        conn.execute(
                            "INSERT OR IGNORE INTO vulnerabilities "
                            "(scan_id, vulnerability_type, severity, url, method, parameter, payload, evidence, vulnerability_data, discovered_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (scan_id, "Cross-Site Scripting (XSS)", "High", _docker_reverse_url(url), method,
                             parameter, payload, "dalfox detection", content,
                             time.strftime("%Y-%m-%d %H:%M:%S")))
                        conn.commit()
                    break
                except sqlite3.OperationalError:
                    time.sleep(0.5 * (attempt + 1))

    except subprocess.TimeoutExpired:
        print(f"[!] Timeout expired scanning target: {url}")
    except FileNotFoundError:
        print("[!] Error: 'dalfox' binary could not be executed. Check system PATH.")
    except Exception as e:
        print(f"[!] Error running scan on {url}: {e}")
    finally:
        if os.path.exists(out_file): os.remove(out_file)


# ============================================================================
# HIGH-LEVEL API — called from server.py
# Same interface as run_sqli_scan(scan_id, db_path, on_progress, cookie)
# ============================================================================

def run_xss_scan(scan_id, db_path, on_progress=None, cookie=None, cancel_check=None):
    if on_progress:
        on_progress("Starting XSS scan...")

    targets = get_targets(db_path=db_path, scan_id=scan_id)

    if not targets:
        msg = "No targets found for XSS testing."
        print(msg)
        if on_progress:
            on_progress(msg)
        return {"targets_scanned": 0, "vulnerabilities_found": 0}

    msg = f"Found {len(targets)} potential XSS targets"
    print(msg)
    if on_progress:
        on_progress(msg)

    scanned_count = 0

    for i, target in enumerate(targets, 1):
        if cancel_check and cancel_check():
            if on_progress:
                on_progress("Scan cancelled — stopping")
            break

        scanned_count += 1
        if on_progress:
            on_progress(f"Scanning target {scanned_count}/{len(targets)}: {target[0][:80]}")

        scan_target(target, scan_id=scan_id, db_path=db_path, cookie=cookie, cancel_check=cancel_check)

    vuln_count = 0
    try:
        with sqlite3.connect(db_path) as conn:
            vuln_count = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND vulnerability_type = 'Cross-Site Scripting (XSS)'",
                (scan_id,)
            ).fetchone()[0]
    except Exception:
        pass

    summary = f"XSS scan complete: {scanned_count} targets scanned, {vuln_count} vulnerabilities found"
    print(summary)
    if on_progress:
        on_progress(summary)

    return {"targets_scanned": scanned_count, "vulnerabilities_found": vuln_count}
