# import necessary libraries
import requests
import sqlite3
import json 
import os
from datetime import datetime

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


# Define common file extensions to check for in the parameter values
exctantions = ['.jpg', '.png', '.svg', '.txt', '.pdf', '.docx', '.xlsx', '.pptx', '.zip', '.tar.gz', '.rar', '.7z', '.exe', '.dll', '.sys', '.bin', '.iso']

# payload file path (resolve relative to this module's directory)
payload_file_path = os.path.join(os.path.dirname(__file__), 'payloads', 'directory_traversal.txt')
payloads = [] # Load payloads from the payload file using load_payloads function

# credentials for login to the website to get cookies for the request
login_url = "http://localhost/login.php" # Specify your login URL
username = "bee" # Specify your username
password = "bug" # Specify your password
security_level = "0" # Specify your security level if needed, otherwise set to None 

# Database and table name for storing vulnerabilities
database = 'niledefender.db' # Specify your database name
table = 'endpoints' # Specify your table name
scan_id = 9 # Specify your scan ID if needed, otherwise set to None


######################################################################
# Load payloads from payload file (/Payloads/directory_traversal.txt)
######################################################################
def load_payloads(payload_file_path=None):
    loaded = []
    try:
        with open(payload_file_path, 'r') as file:
            for line in file:
                stripped = line.strip()
                if stripped:
                    loaded.append(stripped)
    except FileNotFoundError:
        print("Payload file not found. Please check the path and try again.")
    except Exception as e:
        print(f"An error occurred while loading payloads: {e}")
    return loaded



##################################################################
# get endpoints from database ex : niledefender.db
##################################################################
def get_endpoint(Database, Table, SCAN_ID=None):
    try:
        conn = sqlite3.connect(Database)
        cursor = conn.cursor()
        if SCAN_ID:
            cursor.execute(
                f"SELECT * FROM {Table} WHERE method = 'GET' AND parameters IS NOT 'null' AND scan_id = ?",
                (SCAN_ID,)
            )
        else:
            cursor.execute(f"SELECT * FROM {Table} WHERE method = 'GET' AND parameters IS NOT 'null'")
        get_endpoint = [row for row in cursor.fetchall()]
        return get_endpoint
    except sqlite3.Error as e:
        print(f"An error occurred while connecting to the database: {e}")
        return []
    finally:
        if conn:
            conn.close()


######################################################################
# Handle parameter with more than one key and check if the first parameter value ends with common file extensions
######################################################################
def handle_parameters(endpoint):
    parameter = json.loads(endpoint[4]) if endpoint[4] else {} # Assuming the parameter is in the 5th column (index 4) and is a JSON string
    parameter_keys = list(parameter.keys()) # Print the parameter keys to verify the data
    if len(parameter_keys) == 1 and str(parameter[parameter_keys[0]]).endswith(tuple(exctantions)): # Check if the parameter has more than one key and if the first parameter value ends with common file extensions
        url = _docker_translate_url(endpoint[2]) + "?" + parameter_keys[0] + "=" # Assuming the URL is in the 3rd column (index 2)
        print(f"Endpoint with ID {endpoint[0]} has a single parameter with a value that ends with common file extensions. URL: {url}")
        return url, parameter_keys[0]
    else:
        print(f"Endpoint with ID {endpoint[0]} has multiple parameters or the first parameter value does not end with common file extensions. Skipping this endpoint.")
        return None, None



##################################################################
# check path traversal vulnerability for each URL in the scope
##################################################################
# one session if the website requires login to get cookies for the request
# if login is required, otherwise you can use requests without session
# For each URL in the scope, send a request with each payload and check the response for signs of a successful path traversal attack
def check_path_traversal_vulnerability(url, payloads, session=None, cancel_check=None):
    for payload in payloads:
        if cancel_check and cancel_check():
            return None
        target_url = url + payload
        try:
            if session:
                response = session.get(target_url,timeout=10) # Use session to send the request if login is required
            else:
                response = requests.get(target_url, timeout=10) # Send the request without session if login is not required
            
            if check_response_for_vulnerability(response):
                print(f"Vulnerability found at: {target_url}")
                return payload  # Return the successful payload
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while sending the request to {target_url}: {e}")
    
    return None


def check_response_for_vulnerability(response):
    """Check the response content for signs of a successful path traversal attack."""
    danger_signs = [
        '[fonts]',                          # win.ini
        '[extensions]',                      # win.ini
        'root:x:0:0',                       # /etc/passwd
        'daemon:x:1:1',                      # /etc/passwd
        '[boot loader]',                     # boot.ini
        'multi(0)disk(0)',                   # boot.ini
        'Volume in drive',                    # cmd.exe dir output
        'Directory of',                       # cmd.exe dir output
        'RewriteEngine',                      # .htaccess
        'Deny from',                          # .htaccess
        '<Server',                            # server.xml
        'Session_OnStart'                     # global.asa
    ]
    
    if any(sign in response.text for sign in danger_signs):
        print("WARNING: Path traversal successful!")
        print(f"Found: {[s for s in danger_signs if s in response.text]}")
        return True
    
    return False



# ============================================================================
# HIGH-LEVEL API — called from server.py / vuln_workflow.py
# Same interface as run_sqli_scan(scan_id, db_path, on_progress, cookie)
# ============================================================================

def _save_vulnerability(db_path, scan_id, url, method, parameter, payload, evidence):
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """INSERT INTO vulnerabilities
               (scan_id, vulnerability_type, severity, url, method,
                parameter, payload, evidence, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, 'Path Traversal', 'High', _docker_reverse_url(url), method,
             parameter, payload, evidence, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"[!] DB error saving vulnerability: {e}")


def run_pt_scan(scan_id, db_path, on_progress=None, cookie=None, cancel_check=None):
    if on_progress:
        on_progress("Starting Path Traversal scan...")

    # Load payloads
    pt_payloads = load_payloads(payload_file_path)
    if not pt_payloads:
        msg = "No payloads loaded — cannot run Path Traversal scan."
        print(f"[!] {msg}")
        if on_progress:
            on_progress(msg)
        return {"targets_scanned": 0, "vulnerabilities_found": 0}

    if on_progress:
        on_progress(f"Loaded {len(pt_payloads)} traversal payloads")

    # Fetch endpoints from database
    endpoints = get_endpoint(db_path, 'endpoints', scan_id)
    if not endpoints:
        msg = "No suitable GET endpoints found for Path Traversal testing."
        print(msg)
        if on_progress:
            on_progress(msg)
        return {"targets_scanned": 0, "vulnerabilities_found": 0}

    msg = f"Found {len(endpoints)} GET endpoints to test"
    print(msg)
    if on_progress:
        on_progress(msg)



    # Build a session with the cookie for authenticated scanning
    session = requests.Session()
    if cookie:
        session.headers['Cookie'] = cookie
        if on_progress:
            on_progress("Using authentication cookie for scanning")

    # Scan each endpoint
    vuln_count = 0
    scanned_count = 0

    for i, endpoint in enumerate(endpoints, 1):
        if cancel_check and cancel_check():
            if on_progress:
                on_progress("Scan cancelled — stopping")
            break

        url, param_name = handle_parameters(endpoint)
        if not url:
            continue

        scanned_count += 1
        if on_progress:
            on_progress(f"Scanning target {scanned_count} ({i}/{len(endpoints)}): {url[:80]}")

        # Test this endpoint for path traversal
        successful_payload = check_path_traversal_vulnerability(url, pt_payloads, session, cancel_check=cancel_check)

        if successful_payload:
            vuln_count += 1
            evidence = "Path traversal payload returned sensitive file content"
            if on_progress:
                on_progress(f"🔴 VULNERABLE: {url} [{param_name}]")

            _save_vulnerability(
                db_path, scan_id,
                url=endpoint[2],  # original URL without query string
                method='GET',
                parameter=param_name,
                payload=successful_payload,
                evidence=evidence,
            )

    summary = (f"Path Traversal scan complete: {scanned_count} targets scanned, "
               f"{vuln_count} vulnerabilities found")
    print(summary)
    if on_progress:
        on_progress(summary)

    return {"targets_scanned": scanned_count, "vulnerabilities_found": vuln_count}