import json
import os
import sqlite3
import time
import requests
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, urljoin
from html.parser import HTMLParser

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

SKIP_PARAMS = {
    "form", "submit", "action", "csrf", "token", "_token", "security_level",
    "login", "password", "pass", "passwd", "username", "user", "email",
    "captcha", "logout", "redirect", "return", "next",
    "secret", "secret_key", "api_key", "apikey", "auth", "session",
    "db", "database", "table", "column", "key", "id", "scan_id",
}

# URLs containing these patterns are skipped entirely — they modify credentials/state
SKIP_URL_PATTERNS = [
    "login", "logout", "signin", "signup", "register",
    "password", "passwd", "changepass", "resetpass", "forgot",
    "admin", "user_new", "user_edit", "user_delete", "create_user",
    "portal", "credential", "account", "profile",
    "phpmyadmin", "phpMyAdmin", "sql", "db_",
    "install", "setup", "config",
]

HTMLI_PAYLOADS = [
    "<h1>nd_htmli</h1>",  #  HTML payload
    "%3Ch1%3End_htmli%3C%2Fh1%3E",  # URL-encoded HTML payload
    "<a href='http://evil.nd'>nd_htmli</a>",]  # payload with external link

PARAM_DEFAULTS = {}
number_keywords = [
    "id", "num", "page", "count", "total", "index", "limit", "order","row", "size", "length", "width", "height", "max", "min", "age",
    "old", "year", "price", "cost", "amount", "salary", "budget", "rate","balance", "payment", "phone", "tel", "mobile", "cell", "fax", "zip",
    "postal", "postcode", "port", "status", "flag", "active"]
text_keywords = [
    "email", "mail", "name", "user", "login", "account", "member","username", "nickname", "message", "comment", "body", "text",
    "content", "reply", "feedback", "search", "query", "keyword", "term","filter", "find", "firstname", "lastname", "fullname", "city",
    "country", "address", "host", "color", "language", "file", "filename","path", "token", "pass", "password", "url",
      "link", "time", "sort","orderby", "gender", "format", "mode", "view", "action", "title","subject", "product", "item", "movie"]

for word in number_keywords:
    PARAM_DEFAULTS[word] = "1"  
for word in text_keywords:
    PARAM_DEFAULTS[word] = "test" 
# ============================================================
# helper function
# ============================================================
def is_dangerous_url(url: str) -> bool:
    """Return True if URL looks like it modifies credentials or state."""
    url_lower = url.lower()
    return any(pattern in url_lower for pattern in SKIP_URL_PATTERNS)

def fill_params(params: dict) -> dict:
    return {
        k: v if (v and v.strip()) else next(  # if param is empty assign a default
            (val for kw, val in PARAM_DEFAULTS.items() if kw in k.lower()), "test"
        ) for k, v in params.items()
    }

def parse_query(query_or_body: str) -> dict:
    return fill_params(dict(parse_qsl(query_or_body or "", keep_blank_values=True)))  

def make_url(url: str, params: dict = None) -> str:
    """Build URL with optional query params (no host rewriting)."""
    parts = urlsplit(url)
    return urlunsplit(parts._replace(
        query=urlencode(params) if params is not None else parts.query,
        fragment=""))

def flatten_params(raw) -> dict:
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw  # jSON string to dict 
        if not isinstance(data, dict):
            return {}
        return {k: str(v.get("value", v) if isinstance(v, dict) else v) for k, v in data.items()}
    except Exception:
        return {}
# ============================================================
# headers
# ============================================================
def get_headers(cookie=None):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"}
    if cookie:
        headers["Cookie"] = cookie
    return headers
# ============================================================
# html parser
# ============================================================
class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms  = []
        self._cur   = None
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._depth += 1
            if self._depth == 1:
                self._cur = {
                    "fields": {}, "hidden": {},
                    "action": a.get("action", ""),
                    "method": a.get("method", "get").lower(),  
                }
            return
        if not self._cur:
            return
        name  = a.get("name", "")
        value = a.get("value", "")
        itype = a.get("type", "text").lower()
        if not name:
            return
        if tag in ("textarea", "select"):
            self._cur["fields"][name] = value
        elif tag == "input":
            if itype == "hidden":
                self._cur["hidden"][name] = value  
            elif itype not in ("submit","button","image","reset","file","checkbox","radio"):
                self._cur["fields"][name] = value 

    def handle_endtag(self, tag):
        if tag == "form" and self._depth > 0:
            self._depth -= 1
            if self._depth == 0 and self._cur:
                self.forms.append(self._cur)  # Save completed form
                self._cur = None
# ============================================================
# target loading from database
# ============================================================
def get_targets(db_path, scan_id=None) -> list:
    if not os.path.exists(db_path):
        print(f"DB not found: {db_path}"); return []
    targets = []
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            if scan_id:
                rows = conn.execute("SELECT url, method, parameters, body_params FROM endpoints WHERE scan_id = ?", (scan_id,))
            else:
                rows = conn.execute("SELECT url, method, parameters, body_params FROM endpoints")
            for row in rows:
                url    = _docker_translate_url(row["url"])
                method = (row["method"] or "GET").upper()
                params = fill_params(flatten_params(row["body_params"] if method == "POST" else row["parameters"]))
                if method == "GET":
                    q    = {**parse_query(urlsplit(url).query), **params}
                    url  = make_url(url, q)
                    data = None
                else:
                    data = urlencode(params)
                targets.append((url, method, data))
    except Exception as e:
        print(f"DB Error: {e}"); return []

    seen, unique = set(), []
    for item in targets:
        key = (item[0], item[1])
        if key not in seen:
            seen.add(key); unique.append(item)  

    sep = "=" * 60
    print(f"\n{sep}\nEndpoints: {len(unique)} | Payloads: {len(HTMLI_PAYLOADS)} | Est. requests: ~{len(unique) * len(HTMLI_PAYLOADS)}\n{sep}")
    return unique
# ============================================================
# payload reflection
# ============================================================
def check_reflection(body: str, payload: str):
    html_enc = payload.replace("<", "&lt;").replace(">", "&gt;")
    bl = body.lower()
    if payload.lower()  in bl: return "VULNERABLE",        "Medium",  payload  # payload executed unescaped
    if html_enc.lower() in bl: return "REFLECTED_ENCODED", "Medium",  html_enc  # payload returned HTML-encoded
    if "nd_htmli"       in bl: return "REFLECTED_PARTIAL", "Medium",  "nd_htmli"  # only partial marker reflected
    return None, None, None
# ============================================================
# scanner
# ============================================================
def scan_form(url, method, active_params, form_extras, headers, found, cancel_check=None):
    # Skip dangerous URLs that could modify credentials/state
    if is_dangerous_url(url):
        print(f"[HTMLI SKIP] Dangerous URL: {url[:80]}")
        return
    has_cookie = "Cookie" in headers
    filled = fill_params(active_params)
    found_params = set()  # track params already found vulnerable (skip further payloads)

    for payload in HTMLI_PAYLOADS:
        if cancel_check and cancel_check():
            return
        for param in active_params:
            if param.lower() in SKIP_PARAMS:
                continue
            if param in found_params:
                continue  # already found vuln for this param, skip remaining payloads
            test_params = {**filled, **form_extras, param: payload}  # inject payload into parameters
            try:
                if method == "GET":
                    req_url = make_url(url, test_params)
                    resp = requests.get(
                        req_url, headers=headers, timeout=10, allow_redirects=True
                    )
                else:
                    req_url = url
                    resp = requests.post(url, data=test_params, headers=headers,
                                         timeout=10, allow_redirects=True)

                print(f"[HTMLI DEBUG] {method} {req_url[:80]} | param={param} | "
                      f"status={resp.status_code} | len={len(resp.text)} | cookie={'yes' if has_cookie else 'NO'}")

                # Check if we got redirected to a different page (possible auth redirect)
                if resp.url and resp.url.rstrip('/') != req_url.split('?')[0].rstrip('/'):
                    final_host = urlsplit(resp.url).path
                    print(f"[HTMLI DEBUG]   → Redirected to: {resp.url[:80]}")

                status, severity, evidence = check_reflection(resp.text, payload)

                if status is None and method == "POST":
                    try:
                        view_url = resp.url or urlunsplit(urlsplit(url)._replace(query="", fragment=""))
                        gr = requests.get(view_url, headers=headers, timeout=10, allow_redirects=True)
                        status, severity, evidence = check_reflection(gr.text, payload)
                        if status:
                            status = "STORED_" + status  
                    except Exception:
                        pass

                if status:
                    print(f"[HTMLI FOUND] ✓ {param} → {status} ({severity})")
                    found.append((param, payload, status, severity, evidence))
                    found_params.add(param)

            except Exception as e:
                print(f"[ERROR] {url} param={param}: {e}")

def _looks_like_login_page(body: str) -> bool:
    """Detect if the response is a login/redirect page instead of the real target."""
    bl = body.lower()
    login_signals = ["name=\"login\"", "name=\"password\"", "type=\"password\"",
                     "action=\"login", "please log in", "please sign in",
                     "authentication required"]
    hits = sum(1 for s in login_signals if s in bl)
    return hits >= 2  # at least 2 signals → likely a login page


def scan_target(target, scan_id: int, db_path=None, cookie=None, cancel_check=None):
    url, method, data = target

    # Skip dangerous URLs entirely
    if is_dangerous_url(url):
        print(f"[HTMLI SKIP] Skipping dangerous target: {url[:80]}")
        return

    headers   = get_headers(cookie)
    db_params = parse_query(urlsplit(url).query if method == "GET" else (data or ""))
    found     = []
    tested_params = set()  # track tested params to avoid duplicates

    # Fetch page and discover HTML forms
    try:
        resp   = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        parser = FormParser()
        parser.feed(resp.text)
        html_forms = parser.forms
    except Exception as e:
        print(f"[FORM ERR] {url}: {e}")
        html_forms = []

    # Warn if response looks like a login page (cookie might be missing/expired)
    if html_forms and _looks_like_login_page(resp.text):
        print(f"[HTMLI WARN] Page looks like a login redirect, forms may be wrong: {url[:80]}")
        html_forms = []  # discard login-page forms, fall through to db_params

    # Strategy 1: Test discovered HTML forms
    if html_forms:
        for form in html_forms:
            active = fill_params(form["fields"])
            if not active:
                continue
            f_action   = form["action"]
            submit_url = urljoin(url, f_action) if f_action else url
            print(f"[HTMLI TEST] Form on {url[:60]} → action={f_action or '(self)'} "
                  f"method={form['method'].upper()} params=[{', '.join(active.keys())}]")
            scan_form(submit_url, form["method"].upper(), active, form["hidden"], headers, found, cancel_check=cancel_check)
            tested_params.update(active.keys())

    # Strategy 2: Also test DB params not already covered by form discovery
    if db_params:
        untested = {k: v for k, v in db_params.items() if k not in tested_params}
        if untested:
            print(f"[HTMLI TEST] DB params on {url[:60]} → method={method} "
                  f"params=[{', '.join(untested.keys())}]")
            scan_form(url, method, untested, {}, headers, found, cancel_check=cancel_check)

    if not html_forms and not db_params:
        print(f"[HTMLI SKIP] No testable params: {url[:80]}")
        return

    for param, payload, status, severity, evidence in found:
        save_finding(scan_id, url, method, param, payload, status, severity, evidence, db_path=db_path)
# ============================================================
# save vulns
# ============================================================
def save_finding(scan_id, url, method, param, payload, status, severity, evidence, db_path=None):
    db = db_path
    for attempt in range(5):
        try:
            with sqlite3.connect(db, timeout=10) as conn:
                conn.execute("PRAGMA journal_mode=WAL")  # WAL mode prevents write conflicts across threads
                conn.execute(
                    """INSERT INTO vulnerabilities(scan_id, vulnerability_type, severity, url, method,
                        parameter, payload, evidence, vulnerability_data, discovered_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                    (scan_id, "HTML Injection", severity, _docker_reverse_url(url), method,
                     param, payload, evidence,f"Reflection status: {status}",
                     time.strftime("%Y-%m-%d %H:%M:%S")),)
                conn.commit()
                return
        except sqlite3.OperationalError as e:
            print(f"[DB RETRY] Attempt {attempt+1} failed: {e}") 
            time.sleep(0.5 * (attempt + 1))  # sleep before retry
    print(f"[DB ERROR] Failed after 5 attempts: {url}")
# ============================================================================
# HIGH-LEVEL API — called from server.py / vuln_workflow.py
# Same interface as run_sqli_scan(scan_id, db_path, on_progress, cookie)
# ============================================================================
def run_htmli_scan(scan_id, db_path, on_progress=None, cookie=None, cancel_check=None):
    if on_progress:
        on_progress("Starting HTML Injection scan...")

    targets = get_targets(db_path=db_path, scan_id=scan_id)

    if not targets:
        msg = "No targets found for HTML Injection testing."
        print(f"[HTMLI] {msg}")
        if on_progress:
            on_progress(msg)
        return {"targets_scanned": 0, "vulnerabilities_found": 0}

    if on_progress:
        on_progress(f"Found {len(targets)} endpoints to test")

    vuln_count = 0
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

    # Count how many vulns were actually saved for this scan
    try:
        with sqlite3.connect(db_path) as conn:
            vuln_count = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND vulnerability_type = 'HTML Injection'",
                (scan_id,)
            ).fetchone()[0]
    except Exception:
        pass

    summary = f"HTML Injection scan complete: {scanned_count} targets scanned, {vuln_count} vulnerabilities found"
    print(f"[HTMLI] {summary}")
    if on_progress:
        on_progress(summary)

    return {"targets_scanned": scanned_count, "vulnerabilities_found": vuln_count}