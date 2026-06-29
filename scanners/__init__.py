#!/usr/bin/env python3
"""
NileDefender - Scanners Package
Vulnerability scanner modules (SQLi, XSS, LFI/RFI, HTMLI, CMDi, etc.)
"""

from scanners.base import BaseScannerModule
from scanners.sqli import run_sqli_scan
from scanners.PTVuln import run_pt_scan #git
from scanners.htmli import run_htmli_scan
from scanners.xss import run_xss_scan
from scanners.Command_Injection import run_cmdi_scan

# Module registry — maps module name to its high-level scan function
# Each function must accept: (scan_id, db_path, on_progress=None, cookie=None) -> dict
SCANNER_MODULES = {
    'sqli': {
        'name': 'SQL Injection',
        'description': 'Detect SQL injection vulnerabilities using sqlmap',
        'run': run_sqli_scan,
    },
    'pt': {  #git
        'name': 'Path Traversal',
        'description': 'Detect directory traversal / LFI vulnerabilities',
        'run': run_pt_scan,
    },
    'htmli': {
        'name': 'HTML Injection',
        'description': 'Detect HTML injection vulnerabilities via payload reflection',
        'run': run_htmli_scan,
    },
    'xss': {
        'name': 'Cross-Site Scripting (XSS)',
        'description': 'Detect XSS vulnerabilities using dalfox',
        'run': run_xss_scan,
    },
    'cmdi': {
        'name': 'Command Injection',
        'description': 'Detect OS command injection vulnerabilities (verbose, time-based, OOB)',
        'run': run_cmdi_scan,
    },
}

__all__ = [
    'BaseScannerModule',
    'run_sqli_scan',
    'run_pt_scan', #git
    'run_htmli_scan',
    'run_xss_scan',
    'run_cmdi_scan',
    'SCANNER_MODULES',
]
