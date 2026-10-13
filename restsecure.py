#!/usr/bin/env python3
"""
REST Secure — API Security Testing Framework
Tests REST APIs against OWASP API Security Top 10 (2023).

Author: Vikash Vishnoi (@Vikash-Vishnoi)
"""

import argparse
import json
import sys
import os
import re
import time
import hashlib
import datetime
import copy
import concurrent.futures
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[ERROR] 'requests' library required: pip install requests")
    sys.exit(1)

VERSION = "1.0.0"
BANNER = r"""
  ____  _____ ____ _____   ____                          
 |  _ \| ____/ ___|_   _| / ___|  ___  ___ _   _ _ __ ___ 
 | |_) |  _| \___ \ | |   \___ \ / _ \/ __| | | | '__/ _ \
 |  _ <| |___ ___) || |    ___) |  __/ (__| |_| | | |  __/
 |_| \_\_____|____/ |_|   |____/ \___|\___|\__,_|_|  \___|

  API Security Testing Framework  v{ver}
  OWASP API Security Top 10 (2023)
  github.com/Vikash-Vishnoi/RESTSecure
""".format(ver=VERSION)

# ─── Configuration ────────────────────────────────────────────────────
OUTPUT_DIR = Path("./restsecure_reports")

class C:
    """Terminal colors."""
    R="\033[91m";G="\033[92m";Y="\033[93m";B="\033[94m"
    C="\033[96m";W="\033[97m";D="\033[90m";N="\033[0m";BOLD="\033[1m"

def log(msg, level="info"):
    tags = {"info":(C.C,"INFO"),"pass":(C.G,"PASS"),"fail":(C.R,"FAIL"),
            "warn":(C.Y,"WARN"),"data":(C.W,"DATA"),"vuln":(C.R,"VULN")}
    color, tag = tags.get(level, (C.W, "INFO"))
    print(f"  {color}[{tag}]{C.N} {msg}")

class Session:
    """HTTP session with retry logic."""
    def __init__(self, base_url, headers=None, timeout=10, verify=True):
        self.base = base_url.rstrip('/')
        self.timeout = timeout
        self.verify = verify
        self.session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[502,503,504])
        self.session.mount('http://', HTTPAdapter(max_retries=retry))
        self.session.mount('https://', HTTPAdapter(max_retries=retry))
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", "RESTSecure/1.0")

    def request(self, method, path, **kwargs):
        url = urljoin(self.base + '/', path.lstrip('/'))
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify)
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            return None

    def get(self, path, **kw): return self.request('GET', path, **kw)
    def post(self, path, **kw): return self.request('POST', path, **kw)
    def put(self, path, **kw): return self.request('PUT', path, **kw)
    def delete(self, path, **kw): return self.request('DELETE', path, **kw)
    def patch(self, path, **kw): return self.request('PATCH', path, **kw)
    def options(self, path, **kw): return self.request('OPTIONS', path, **kw)


# ═══════════════════════════════════════════════════════════════════════
# API1:2023 — Broken Object Level Authorization (BOLA)
# ═══════════════════════════════════════════════════════════════════════
class TestBOLA:
    """API1 — Tests for IDOR / broken object-level authorization."""

    ID = "API1:2023"
    NAME = "Broken Object Level Authorization (BOLA)"
    SEVERITY = "CRITICAL"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestBOLA.ID, "name": TestBOLA.NAME, "severity": TestBOLA.SEVERITY, "findings": []}
        log(f"{TestBOLA.ID} — {TestBOLA.NAME}", "info")

        id_patterns = [
            (r'/(\d+)(?:/|$)', 'numeric'),
            (r'/([a-f0-9]{24})(?:/|$)', 'mongodb_objectid'),
            (r'/([a-f0-9\-]{36})(?:/|$)', 'uuid'),
        ]

        for ep in endpoints:
            path = ep.get('path', '')
            for pattern, id_type in id_patterns:
                match = re.search(pattern, path)
                if match:
                    original_id = match.group(1)
                    # Try incrementing numeric IDs
                    if id_type == 'numeric':
                        test_ids = [str(int(original_id) + i) for i in [1, -1, 100, 999]]
                    elif id_type == 'uuid':
                        test_ids = ['00000000-0000-0000-0000-000000000001']
                    else:
                        test_ids = ['000000000000000000000001']

                    for test_id in test_ids:
                        test_path = path[:match.start(1)] + test_id + path[match.end(1):]
                        resp = session.get(test_path)
                        if resp and resp.status_code == 200:
                            results["findings"].append({
                                "endpoint": test_path,
                                "original_id": original_id,
                                "test_id": test_id,
                                "status": resp.status_code,
                                "risk": "Object accessible with different ID — potential BOLA",
                                "remediation": "Implement object-level authorization checks on every request"
                            })
                            log(f"BOLA: {test_path} returned 200 with different ID", "vuln")
                        elif resp and resp.status_code == 403:
                            log(f"BOLA: {test_path} properly returned 403", "pass")

        if not results["findings"]:
            log("No BOLA vulnerabilities detected in tested endpoints", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
# API2:2023 — Broken Authentication
# ═══════════════════════════════════════════════════════════════════════
class TestBrokenAuth:
    """API2 — Tests authentication mechanism weaknesses."""

    ID = "API2:2023"
    NAME = "Broken Authentication"
    SEVERITY = "CRITICAL"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestBrokenAuth.ID, "name": TestBrokenAuth.NAME, "severity": TestBrokenAuth.SEVERITY, "findings": []}
        log(f"{TestBrokenAuth.ID} — {TestBrokenAuth.NAME}", "info")

        auth_endpoints = ['/login', '/auth', '/token', '/oauth/token', '/api/login',
                          '/api/auth', '/signin', '/api/signin', '/auth/login', '/v1/auth']

        for ep in auth_endpoints:
            # Test without auth
            resp = session.get(ep)
            if resp and resp.status_code not in [404, 405]:
                log(f"Auth endpoint found: {ep} ({resp.status_code})", "data")

            # Test weak credentials
            weak_creds = [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": "123456"},
                {"username": "test", "password": "test"},
                {"username": "api", "password": "api"},
            ]

            for cred in weak_creds:
                resp = session.post(ep, json=cred)
                if resp and resp.status_code == 200:
                    try:
                        body = resp.json()
                        if any(k in body for k in ['token', 'access_token', 'jwt', 'session', 'key']):
                            results["findings"].append({
                                "endpoint": ep,
                                "credentials": f"{cred['username']}:{cred['password']}",
                                "risk": "Weak credentials accepted — token returned",
                                "remediation": "Enforce strong password policies, implement rate limiting"
                            })
                            log(f"Weak creds accepted at {ep}: {cred['username']}:{cred['password']}", "vuln")
                    except Exception:
                        pass

        # Check for missing auth on protected endpoints
        for ep in endpoints:
            path = ep.get('path', '')
            if any(s in path.lower() for s in ['/admin', '/users', '/settings', '/config', '/private']):
                headers_backup = dict(session.session.headers)
                session.session.headers.pop('Authorization', None)
                session.session.headers.pop('X-API-Key', None)
                resp = session.get(path)
                session.session.headers.update(headers_backup)
                if resp and resp.status_code == 200:
                    results["findings"].append({
                        "endpoint": path,
                        "risk": "Protected endpoint accessible without authentication",
                        "remediation": "Require authentication for all sensitive endpoints"
                    })
                    log(f"No auth required: {path}", "vuln")

        if not results["findings"]:
            log("No broken authentication issues detected", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
