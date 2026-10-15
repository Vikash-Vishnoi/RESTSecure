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
# API9:2023 — Improper Inventory Management
# ═══════════════════════════════════════════════════════════════════════
class TestInventory:
    """API9 — Tests for exposed old/debug/undocumented endpoints."""

    ID = "API9:2023"
    NAME = "Improper Inventory Management"
    SEVERITY = "MEDIUM"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestInventory.ID, "name": TestInventory.NAME,
                    "severity": TestInventory.SEVERITY, "findings": []}
        log(f"{TestInventory.ID} — {TestInventory.NAME}", "info")

        discovery_paths = [
            '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api/docs', '/docs', '/swagger-ui.html', '/swagger-ui/',
            '/redoc', '/api/swagger', '/v1/swagger.json', '/v2/swagger.json',
            '/.well-known/openapi.yaml', '/graphql', '/graphiql', '/playground',
            '/api/v1', '/api/v2', '/api/v3', '/api/beta', '/api/staging',
            '/api/test', '/api/dev', '/api/debug', '/api/internal',
            '/healthz', '/readyz', '/livez', '/health', '/status', '/info',
            '/metrics', '/prometheus', '/actuator', '/actuator/health',
            '/actuator/env', '/actuator/beans', '/actuator/mappings',
            '/debug/pprof', '/debug/vars', '/_debug', '/trace',
            '/.git/config', '/.env', '/robots.txt', '/sitemap.xml',
            '/wp-admin', '/admin', '/phpinfo.php', '/server-status',
        ]

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_map = {executor.submit(session.get, p): p for p in discovery_paths}
            for future in concurrent.futures.as_completed(future_map):
                path = future_map[future]
                try:
                    resp = future.result()
                    if resp and resp.status_code == 200:
                        found.append(path)
                        category = 'documentation' if any(s in path for s in ['swagger', 'openapi', 'docs', 'redoc', 'graphql']) else \
                                   'debug' if any(s in path for s in ['debug', 'actuator', 'pprof', 'phpinfo']) else \
                                   'versioning' if any(s in path for s in ['/v1', '/v2', '/v3', '/beta', '/staging', '/test', '/dev']) else \
                                   'sensitive' if any(s in path for s in ['.git', '.env', 'admin', 'wp-admin']) else 'info'

                        risk_level = 'high' if category in ['debug', 'sensitive'] else 'medium'
                        results["findings"].append({
                            "endpoint": path,
                            "category": category,
                            "risk_level": risk_level,
                            "risk": f"Exposed {category} endpoint accessible",
                            "remediation": "Restrict access to documentation/debug endpoints in production"
                        })
                        log(f"Exposed: {path} [{category}]", "vuln" if risk_level == 'high' else "warn")
                except Exception:
                    pass

        if not results["findings"]:
            log("No exposed inventory/debug endpoints detected", "pass")
        else:
            log(f"Found {len(found)} exposed endpoints", "data")
        return results


# ═══════════════════════════════════════════════════════════════════════
# API10:2023 — Unsafe Consumption of APIs
# ═══════════════════════════════════════════════════════════════════════
class TestUnsafeConsumption:
    """API10 — Tests for injection via API inputs."""

    ID = "API10:2023"
    NAME = "Unsafe Consumption of APIs"
    SEVERITY = "HIGH"

    @staticmethod
    def run(session, endpoints):
        results = {"test": TestUnsafeConsumption.ID, "name": TestUnsafeConsumption.NAME,
                    "severity": TestUnsafeConsumption.SEVERITY, "findings": []}
        log(f"{TestUnsafeConsumption.ID} — {TestUnsafeConsumption.NAME}", "info")

        injection_payloads = {
            "sql": ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--", "1' AND '1'='1"],
            "nosql": ['{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}'],
            "xss": ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
            "ssti": ['{{7*7}}', '${7*7}', '<%= 7*7 %>'],
            "command": ['; ls', '| id', '`id`', '$(id)'],
            "path": ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam'],
        }

        for ep in endpoints[:5]:
            path = ep.get('path', '')

            # Test via query parameters
            for category, payloads in injection_payloads.items():
                for payload in payloads[:2]:
                    resp = session.get(path, params={"id": payload, "search": payload, "q": payload})
                    if resp:
                        body = resp.text.lower()
                        indicators = {
                            "sql": ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'oracle', 'mssql'],
                            "xss": ['<script>', 'onerror='],
                            "ssti": ['49'],  # 7*7
                            "command": ['uid=', 'root:', '/bin/'],
                            "path": ['root:', '[boot loader]', 'passwd'],
                            "nosql": ['mongoerror', 'bson'],
                        }
                        for ind in indicators.get(category, []):
                            if ind in body:
                                results["findings"].append({
                                    "endpoint": path,
                                    "injection_type": category.upper(),
                                    "payload": payload[:50],
                                    "risk": f"Potential {category.upper()} injection — indicator found in response",
                                    "remediation": f"Validate and sanitize all input, use parameterized queries"
                                })
                                log(f"{category.upper()} injection: {path} with {payload[:30]}", "vuln")
                                break

            # Test via JSON body
            for category, payloads in injection_payloads.items():
                resp = session.post(path, json={"input": payloads[0], "search": payloads[0]})
                if resp and resp.status_code in [200, 201, 500]:
                    body = resp.text.lower()
                    for ind in ['error', 'exception', 'syntax', 'sql', 'stack']:
                        if ind in body and resp.status_code == 500:
                            results["findings"].append({
                                "endpoint": path,
                                "injection_type": category.upper(),
                                "via": "JSON body",
                                "risk": f"Server error triggered by {category} payload — possible injection",
                                "remediation": "Input validation, WAF, parameterized queries"
                            })
                            log(f"{category.upper()} error at {path} via JSON body", "warn")
                            break

        if not results["findings"]:
            log("No injection vulnerabilities detected", "pass")
        return results


# ═══════════════════════════════════════════════════════════════════════
# REPORTING
# ═══════════════════════════════════════════════════════════════════════
class Reporter:
    """Generate JSON and HTML reports."""

    @staticmethod
    def save(data, target):
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r'[^\w\-.]', '_', target)

        # JSON
        jpath = OUTPUT_DIR / f"restsecure-{safe}-{ts}.json"
        with open(jpath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        log(f"JSON report: {jpath}", "pass")

        # HTML
        hpath = OUTPUT_DIR / f"restsecure-{safe}-{ts}.html"
        findings_html = ""
        total_vulns = 0
        for test in data.get("tests", []):
            count = len(test.get("findings", []))
            total_vulns += count
            sev_color = {"CRITICAL": "#ff4757", "HIGH": "#ff6348", "MEDIUM": "#ffa502", "LOW": "#2ed573"}.get(test.get("severity"), "#999")
            findings_html += f"""<h2 style="color:#00d4ff;border-bottom:1px solid #1e2d3e;padding-bottom:6px;margin-top:20px">
                {test['test']} — {test['name']} <span style="color:{sev_color};font-size:0.8em">[{test['severity']}]</span></h2>
                <p style="color:#7a8ea0">Findings: {count}</p>"""
            for f in test.get("findings", []):
                findings_html += f"<div style='background:#111922;border:1px solid #1e2d3e;border-radius:6px;padding:12px;margin:8px 0;font-size:13px'>"
                for k, v in f.items():
                    findings_html += f"<div><strong style='color:#f0a500'>{k}:</strong> <span style='color:#c8d6e5'>{v}</span></div>"
                findings_html += "</div>"

        score = max(0, 100 - (total_vulns * 5))
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>REST Secure Report</title>
<style>body{{font-family:monospace;background:#0a0e14;color:#c8d6e5;padding:24px;max-width:960px;margin:0 auto}}
h1{{color:#00d4ff}}.stat{{display:inline-block;padding:8px 16px;margin:4px;border:1px solid #1e2d3e;border-radius:6px}}</style></head>
<body><h1>REST Secure Security Report</h1>
<p>Target: {data.get('target','')}</p><p>Date: {data.get('timestamp','')}</p>
<div class="stat" style="color:#00d4ff;font-size:1.5em">Score: {score}%</div>
<div class="stat" style="color:#ff4757">Vulnerabilities: {total_vulns}</div>
<div class="stat">Tests: {len(data.get('tests',[]))}</div>
{findings_html}
<p style="margin-top:24px;color:#4a5d70;font-size:12px">REST Secure v{VERSION} — github.com/Vikash-Vishnoi/RESTSecure</p>
</body></html>"""
        with open(hpath, 'w') as f:
            f.write(html)
        log(f"HTML report: {hpath}", "pass")
        return total_vulns, score


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="REST Secure — API Security Testing Framework (OWASP API Top 10 2023)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tests:
  API1   Broken Object Level Authorization (BOLA/IDOR)
  API2   Broken Authentication
  API3   Broken Object Property Level Authorization
  API4   Unrestricted Resource Consumption (Rate Limiting)
  API5   Broken Function Level Authorization (Privilege Escalation)
  API6   Unrestricted Access to Sensitive Business Flows
  API7   Server Side Request Forgery (SSRF)
  API8   Security Misconfiguration (CORS, Headers, Errors)
  API9   Improper Inventory Management (Exposed Endpoints)
  API10  Unsafe Consumption of APIs (Injection)

Examples:
  restsecure.py -u https://api.example.com
  restsecure.py -u https://api.example.com -e /users,/orders
  restsecure.py -u https://api.example.com -H "Authorization: Bearer TOKEN"
  restsecure.py -u https://api.example.com --tests API1,API4,API8
  restsecure.py -u https://api.example.com --spec openapi.json
  restsecure.py -u https://api.example.com --spec https://api.example.com/openapi.json
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Base URL of the API")
    parser.add_argument("-e", "--endpoints", help="Comma-separated endpoint paths to test")
    parser.add_argument("-H", "--header", action="append", help="Custom header (e.g., 'Authorization: Bearer token')")
    parser.add_argument("--spec", metavar="SPEC",
                        help="OpenAPI 3.x / Swagger 2.0 spec (local file path or URL). "
                             "Endpoints are extracted from the spec's 'paths' section and merged with -e.")
    parser.add_argument("--tests", help="Specific tests to run (e.g., API1,API4,API8)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    parser.add_argument("--no-verify", action="store_true", help="Skip TLS verification")
    parser.add_argument("--version", action="version", version=f"REST Secure v{VERSION}")

    args = parser.parse_args()
    print(BANNER)

    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            key, _, val = h.partition(':')
            headers[key.strip()] = val.strip()

    # Parse endpoints
    endpoints = []

    # --spec: load endpoints from an OpenAPI / Swagger spec
    if args.spec:
        try:
            from openapi_loader import load_openapi
            spec_eps = load_openapi(args.spec)
            endpoints.extend(spec_eps)
            log(f"Loaded {len(spec_eps)} endpoints from spec: {args.spec}", "pass")
        except Exception as e:
            log(f"Failed to load spec '{args.spec}': {e}", "fail")
            sys.exit(1)

    # -e: manual comma-separated paths (merged on top of spec endpoints)
    if args.endpoints:
        for ep in args.endpoints.split(','):
            ep = ep.strip()
            if ep:
                endpoints.append({"path": ep, "method": "GET"})

    if not endpoints:
        # Default discovery endpoints when neither --spec nor -e is supplied
        endpoints = [{"path": "/", "method": "GET"},
                     {"path": "/api", "method": "GET"},
                     {"path": "/api/v1", "method": "GET"},
                     {"path": "/users", "method": "GET"},
                     {"path": "/api/users", "method": "GET"}]

    session = Session(args.url, headers=headers, timeout=args.timeout, verify=not args.no_verify)

    # Verify connectivity
    resp = session.get('/')
    if not resp:
        log(f"Cannot connect to {args.url}", "fail")
        sys.exit(1)
    log(f"Target: {args.url} — Status: {resp.status_code}", "pass")

    # Select tests
    ALL_TESTS = {
        'API1': TestBOLA, 'API2': TestBrokenAuth, 'API3': TestBOPLA,
        'API4': TestResourceConsumption, 'API5': TestBFLA, 'API6': TestSensitiveFlows,
        'API7': TestSSRF, 'API8': TestMisconfig, 'API9': TestInventory,
        'API10': TestUnsafeConsumption,
    }

    tests_to_run = ALL_TESTS
    if args.tests:
        selected = [t.strip().upper() for t in args.tests.split(',')]
        tests_to_run = {k: v for k, v in ALL_TESTS.items() if k in selected}

    # Execute
    all_results = {"target": args.url, "timestamp": datetime.datetime.now().isoformat(),
                   "version": VERSION, "tests": []}

    for test_id, test_class in tests_to_run.items():
        print(f"\n{'='*60}")
        result = test_class.run(session, endpoints)
        all_results["tests"].append(result)

    # Report
    print(f"\n{'='*60}")
    total_vulns, score = Reporter.save(all_results, urlparse(args.url).netloc)

    # Summary
    print(f"\n{C.BOLD}{'='*60}{C.N}")
    print(f"  REST Secure Scan Complete")
    print(f"{'='*60}")
    print(f"  Target:          {args.url}")
    print(f"  Tests Executed:  {len(all_results['tests'])}")
    print(f"  Vulnerabilities: {total_vulns}")
    score_color = C.G if score >= 80 else C.Y if score >= 60 else C.R
    print(f"  Security Score:  {score_color}{score}%{C.N}")
    print(f"  Reports:         {OUTPUT_DIR}/")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
