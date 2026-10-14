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
# API3:2023 — Broken Object Property Level Authorization
# ═══════════════════════════════════════════════════════════════════════
class TestBOPLA:
    """API3 — Tests for mass assignment and excessive data exposure."""

    ID = "API3:2023"
    NAME = "Broken Object Property Level Authorization"
    SEVERITY = "HIGH"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestBOPLA.ID, "name": TestBOPLA.NAME, "severity": TestBOPLA.SEVERITY, "findings": []}
        log(f"{TestBOPLA.ID} — {TestBOPLA.NAME}", "info")

        sensitive_fields = ['password', 'secret', 'token', 'api_key', 'apikey', 'credit_card',
                            'ssn', 'private_key', 'admin', 'role', 'is_admin', 'permissions',
                            'salary', 'bank_account', 'internal_id', 'debug', 'hash', 'salt']

        for ep in endpoints:
            path = ep.get('path', '')
            resp = session.get(path)
            if resp and resp.status_code == 200:
                try:
                    body = resp.json()
                    body_str = json.dumps(body).lower()
                    exposed = [f for f in sensitive_fields if f in body_str]
                    if exposed:
                        results["findings"].append({
                            "endpoint": path,
                            "exposed_fields": exposed,
                            "risk": "Sensitive data fields in API response",
                            "remediation": "Filter response fields, implement view-level permissions"
                        })
                        log(f"Sensitive fields exposed at {path}: {', '.join(exposed)}", "vuln")
                except Exception:
                    pass

            # Mass assignment test — try adding admin/role fields
            if ep.get('method', '').upper() in ['POST', 'PUT', 'PATCH']:
                test_payloads = [
                    {"role": "admin", "is_admin": True},
                    {"permissions": ["*"], "admin": True},
                ]
                for payload in test_payloads:
                    resp = session.request(ep.get('method', 'POST'), path, json=payload)
                    if resp and resp.status_code in [200, 201]:
                        try:
                            body = resp.json()
                            if any(k in json.dumps(body).lower() for k in ['admin', 'role']):
                                results["findings"].append({
                                    "endpoint": path,
                                    "payload": payload,
                                    "risk": "Mass assignment — role/admin fields accepted",
                                    "remediation": "Whitelist allowed input fields, reject unknown properties"
                                })
                                log(f"Mass assignment possible at {path}", "vuln")
                        except Exception:
                            pass

        if not results["findings"]:
            log("No property-level authorization issues detected", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
# API4:2023 — Unrestricted Resource Consumption
# ═══════════════════════════════════════════════════════════════════════
class TestResourceConsumption:
    """API4 — Tests rate limiting and resource exhaustion."""

    ID = "API4:2023"
    NAME = "Unrestricted Resource Consumption"
    SEVERITY = "HIGH"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestResourceConsumption.ID, "name": TestResourceConsumption.NAME,
                    "severity": TestResourceConsumption.SEVERITY, "findings": []}
        log(f"{TestResourceConsumption.ID} — {TestResourceConsumption.NAME}", "info")

        test_endpoints = endpoints[:5] if endpoints else [{'path': '/'}]

        for ep in test_endpoints:
            path = ep.get('path', '/')

            # Rate limiting test — send 20 rapid requests
            responses = []
            for i in range(20):
                resp = session.get(path)
                if resp:
                    responses.append(resp.status_code)
                time.sleep(0.05)

            rate_limited = any(s in [429, 503] for s in responses)
            rate_headers = False

            # Check for rate limit headers
            resp = session.get(path)
            if resp:
                rl_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'RateLimit-Limit',
                               'RateLimit-Remaining', 'X-Rate-Limit', 'Retry-After']
                found = [h for h in rl_headers if h.lower() in [k.lower() for k in resp.headers]]
                rate_headers = bool(found)

            if not rate_limited and not rate_headers:
                results["findings"].append({
                    "endpoint": path,
                    "requests_sent": 20,
                    "rate_limited": False,
                    "rate_headers": False,
                    "risk": "No rate limiting detected — susceptible to DoS/brute force",
                    "remediation": "Implement rate limiting, add X-RateLimit headers, use API gateway"
                })
                log(f"No rate limiting on {path} (20 requests, no 429)", "vuln")
            else:
                log(f"Rate limiting present on {path}", "pass")

            # Large payload test
            large_payload = {"data": "A" * 100000}
            resp = session.post(path, json=large_payload)
            if resp and resp.status_code in [200, 201]:
                results["findings"].append({
                    "endpoint": path,
                    "risk": "Large payload accepted (100KB) — no size limit",
                    "remediation": "Set maximum request body size, validate input length"
                })
                log(f"Large payload accepted at {path}", "warn")

            # Pagination abuse
            resp = session.get(path, params={"limit": 999999, "page_size": 999999, "per_page": 999999})
            if resp and resp.status_code == 200:
                try:
                    body = resp.json()
                    if isinstance(body, list) and len(body) > 100:
                        results["findings"].append({
                            "endpoint": path,
                            "risk": "Pagination bypass — excessive records returned",
                            "remediation": "Enforce maximum page size server-side"
                        })
                        log(f"Pagination bypass at {path}: {len(body)} records", "vuln")
                except Exception:
                    pass

        if not results["findings"]:
            log("Rate limiting and resource controls appear adequate", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
# API5:2023 — Broken Function Level Authorization
# ═══════════════════════════════════════════════════════════════════════
class TestBFLA:
    """API5 — Tests for horizontal/vertical privilege escalation."""

    ID = "API5:2023"
    NAME = "Broken Function Level Authorization"
    SEVERITY = "CRITICAL"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestBFLA.ID, "name": TestBFLA.NAME, "severity": TestBFLA.SEVERITY, "findings": []}
        log(f"{TestBFLA.ID} — {TestBFLA.NAME}", "info")

        admin_paths = ['/admin', '/api/admin', '/api/v1/admin', '/admin/users', '/admin/config',
                       '/api/admin/settings', '/management', '/internal', '/debug', '/actuator',
                       '/actuator/health', '/actuator/env', '/swagger-ui.html', '/api-docs',
                       '/graphql', '/.env', '/config', '/api/config', '/metrics', '/health',
                       '/status', '/info', '/api/internal', '/v1/admin', '/v2/admin']

        for path in admin_paths:
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                resp = session.request(method, path)
                if resp and resp.status_code == 200:
                    results["findings"].append({
                        "endpoint": path,
                        "method": method,
                        "status": 200,
                        "risk": f"Administrative endpoint accessible via {method}",
                        "remediation": "Restrict admin functions to authorized roles only"
                    })
                    log(f"Admin endpoint accessible: {method} {path}", "vuln")
                    break
                elif resp and resp.status_code == 403:
                    log(f"Properly restricted: {method} {path}", "pass")
                    break

        # HTTP method tampering
        for ep in endpoints[:5]:
            path = ep.get('path', '')
            original_method = ep.get('method', 'GET')
            test_methods = ['DELETE', 'PUT', 'PATCH'] if original_method == 'GET' else ['GET']
            for method in test_methods:
                resp = session.request(method, path)
                if resp and resp.status_code in [200, 201, 204]:
                    results["findings"].append({
                        "endpoint": path,
                        "original_method": original_method,
                        "test_method": method,
                        "risk": f"Unexpected {method} method allowed on {original_method} endpoint",
                        "remediation": "Restrict HTTP methods per endpoint"
                    })
                    log(f"Method tampering: {method} {path} returned {resp.status_code}", "warn")

        if not results["findings"]:
            log("No function-level authorization issues detected", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
# API6:2023 — Unrestricted Access to Sensitive Business Flows
# ═══════════════════════════════════════════════════════════════════════
class TestSensitiveFlows:
    """API6 — Tests for abuse of business logic flows."""

    ID = "API6:2023"
    NAME = "Unrestricted Access to Sensitive Business Flows"
    SEVERITY = "MEDIUM"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestSensitiveFlows.ID, "name": TestSensitiveFlows.NAME,
                    "severity": TestSensitiveFlows.SEVERITY, "findings": []}
        log(f"{TestSensitiveFlows.ID} — {TestSensitiveFlows.NAME}", "info")

        sensitive_patterns = ['purchase', 'checkout', 'transfer', 'payment', 'order',
                              'register', 'signup', 'reset', 'forgot', 'verify', 'otp',
                              'coupon', 'discount', 'redeem', 'vote', 'comment', 'review']

        for ep in endpoints:
            path = ep.get('path', '').lower()
            if any(p in path for p in sensitive_patterns):
                # Check if CAPTCHA or anti-automation is required
                resp = session.get(path)
                if resp:
                    body_str = resp.text.lower()
                    has_captcha = any(c in body_str for c in ['captcha', 'recaptcha', 'hcaptcha', 'turnstile'])
                    has_csrf = any(h.lower() in [k.lower() for k in resp.headers]
                                  for h in ['X-CSRF-Token', 'X-XSRF-Token'])

                    if not has_captcha and not has_csrf:
                        matched = [p for p in sensitive_patterns if p in path]
                        results["findings"].append({
                            "endpoint": path,
                            "matched_patterns": matched,
                            "captcha": has_captcha,
                            "csrf": has_csrf,
                            "risk": "Sensitive flow without anti-automation controls",
                            "remediation": "Add CAPTCHA, rate limiting, or step-up auth for sensitive operations"
                        })
                        log(f"Sensitive flow unprotected: {path} (no CAPTCHA/CSRF)", "warn")

        if not results["findings"]:
            log("No unprotected sensitive business flows detected", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
# API7:2023 — Server Side Request Forgery (SSRF)
# ═══════════════════════════════════════════════════════════════════════
class TestSSRF:
    """API7 — Tests for SSRF vulnerabilities."""

    ID = "API7:2023"
    NAME = "Server Side Request Forgery (SSRF)"
    SEVERITY = "HIGH"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestSSRF.ID, "name": TestSSRF.NAME, "severity": TestSSRF.SEVERITY, "findings": []}
        log(f"{TestSSRF.ID} — {TestSSRF.NAME}", "info")

        ssrf_params = ['url', 'uri', 'link', 'href', 'src', 'source', 'redirect', 'redirect_url',
                       'callback', 'webhook', 'proxy', 'target', 'dest', 'destination', 'fetch',
                       'load', 'image', 'img', 'file', 'path', 'page', 'feed', 'host', 'site']

        internal_targets = [
            'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
            'http://169.254.169.254/latest/meta-data/',  # AWS IMDS
            'http://metadata.google.internal/',           # GCP
            'http://169.254.169.254/metadata/instance',   # Azure
            'http://[::1]',
        ]

        for ep in endpoints:
            path = ep.get('path', '')
            for param in ssrf_params:
                for target in internal_targets[:3]:
                    resp = session.get(path, params={param: target})
                    if resp and resp.status_code == 200:
                        body = resp.text[:500]
                        # Check for indicators of internal access
                        indicators = ['ami-id', 'instance-id', 'local-ipv4', 'metadata',
                                      'computeMetadata', 'root', 'localhost', '127.0.0.1']
                        if any(ind in body.lower() for ind in indicators):
                            results["findings"].append({
                                "endpoint": path,
                                "parameter": param,
                                "payload": target,
                                "risk": "Potential SSRF — internal resource accessible via URL parameter",
                                "remediation": "Validate and whitelist URLs, block internal IP ranges, disable redirects"
                            })
                            log(f"SSRF: {path}?{param}={target} returned internal data", "vuln")

        if not results["findings"]:
            log("No SSRF vulnerabilities detected", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
# API8:2023 — Security Misconfiguration
# ═══════════════════════════════════════════════════════════════════════
class TestMisconfig:
    """API8 — Tests for security misconfiguration."""

    ID = "API8:2023"
    NAME = "Security Misconfiguration"
    SEVERITY = "MEDIUM"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestMisconfig.ID, "name": TestMisconfig.NAME,
                    "severity": TestMisconfig.SEVERITY, "findings": []}
        log(f"{TestMisconfig.ID} — {TestMisconfig.NAME}", "info")

        base_resp = session.get('/')
        if not base_resp:
            log("Could not reach target", "fail")
            return results

        # CORS misconfiguration
        resp = session.get('/', headers={'Origin': 'https://evil.com'})
        if resp:
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            if acao == '*' or acao == 'https://evil.com':
                results["findings"].append({
                    "check": "CORS",
                    "value": acao,
                    "risk": "Overly permissive CORS — reflects arbitrary origin or uses wildcard",
                    "remediation": "Whitelist specific trusted origins, avoid wildcard with credentials"
                })
                log(f"CORS misconfiguration: Access-Control-Allow-Origin: {acao}", "vuln")
            else:
                log("CORS properly configured", "pass")

        # Security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'X-Frame-Options': 'Missing clickjacking protection',
            'Content-Security-Policy': 'Missing CSP header',
            'X-XSS-Protection': 'Missing XSS protection header',
            'Cache-Control': 'Missing cache control for API responses',
        }

        for header, risk in security_headers.items():
            if header.lower() not in [h.lower() for h in base_resp.headers]:
                results["findings"].append({
                    "check": "Security Header",
                    "header": header,
                    "risk": risk,
                    "remediation": f"Add {header} header to all API responses"
                })
                log(f"Missing header: {header}", "warn")

        # Server information disclosure
        server = base_resp.headers.get('Server', '')
        powered = base_resp.headers.get('X-Powered-By', '')
        if server:
            results["findings"].append({
                "check": "Information Disclosure",
                "header": "Server",
                "value": server,
                "risk": "Server version disclosed in headers",
                "remediation": "Remove or obfuscate Server header"
            })
            log(f"Server disclosed: {server}", "warn")
        if powered:
            results["findings"].append({
                "check": "Information Disclosure",
                "header": "X-Powered-By",
                "value": powered,
                "risk": "Technology stack disclosed via X-Powered-By",
                "remediation": "Remove X-Powered-By header"
            })
            log(f"X-Powered-By disclosed: {powered}", "warn")

        # Verbose errors
        error_paths = ['/api/undefined', '/api/../../etc/passwd', '/api/' + 'A' * 5000]
        for ep in error_paths:
            resp = session.get(ep)
            if resp and resp.status_code >= 400:
                body = resp.text.lower()
                if any(ind in body for ind in ['stack trace', 'traceback', 'exception',
                                                 'at line', 'sql', 'syntax error', 'debug']):
                    results["findings"].append({
                        "check": "Verbose Errors",
                        "endpoint": ep[:80],
                        "risk": "Detailed error messages expose internal information",
                        "remediation": "Return generic error messages, log details server-side"
                    })
                    log(f"Verbose error response at {ep[:60]}", "vuln")

        # HTTP methods
        resp = session.options('/')
        if resp and 'Allow' in resp.headers:
            allowed = resp.headers['Allow']
            dangerous = [m for m in ['TRACE', 'TRACK', 'DEBUG'] if m in allowed.upper()]
            if dangerous:
                results["findings"].append({
                    "check": "Dangerous Methods",
                    "methods": dangerous,
                    "risk": f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                    "remediation": "Disable TRACE, TRACK, and DEBUG methods"
                })
                log(f"Dangerous methods: {', '.join(dangerous)}", "vuln")

        if not results["findings"]:
            log("No security misconfigurations detected", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
