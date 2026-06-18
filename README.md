# AEM Hunter — Unauthenticated AEM Security Scanner

Single-file Adobe Experience Manager (AEM) audit scanner. Point it at a URL and
it runs every well-known AEM vulnerability check in depth — no auth, no
cookies, no role concept. Output is a console + HTML + JSON report.

> **Authorization required.** Only run this against systems you own or have
> explicit written permission to test.

## Install

```bash
git clone https://github.com/PratikKaran23/aem-hunter.git
cd aem-hunter
pip install -r requirements.txt
```

Single dependency: `requests`. `httpx[http2]` is optional (for HTTP/2-only
targets — see below).

## Usage

```bash
python3 aem_hunter.py                            # prompts for URL
python3 aem_hunter.py https://aem.example.com
python3 aem_hunter.py -u https://aem.example.com
python3 aem_hunter.py -u TARGET --proxy http://127.0.0.1:8080
python3 aem_hunter.py -u TARGET --aggressive     # bigger dispatcher fuzz
python3 aem_hunter.py -u TARGET --http2          # HTTP/2-only targets
python3 aem_hunter.py -u TARGET --exploit        # end-to-end JSP-RCE PoC
```

Every run writes `report-<host>-unauthenticated-<ts>.{json,html}` to the
current directory (override with `-o`).

### HTTP/2-only targets

Many enterprise AEM deployments sit behind a CDN/WAF/LB that **only speaks
HTTP/2**. Python `requests` is HTTP/1.1-only, so a direct scan dies with
`UnknownProtocol('HTTP/2')` and every request fails. Two options:

- **Through Burp/mitmproxy** (`--proxy ...`) — the proxy downgrades HTTP/2 to
  HTTP/1.1, so the default backend just works.
- **Native HTTP/2** — no proxy needed:

  ```bash
  pip install 'httpx[http2]'
  python3 aem_hunter.py -u https://aem.example.com --http2
  ```

The tool detects the HTTP/2 error at preflight and tells you which fix to use.

### All flags

| Flag                       | Purpose                                                                  |
| -------------------------- | ------------------------------------------------------------------------ |
| `target` / `-u`            | Target URL (positional or `-u`; prompted if absent)                      |
| `--proxy`                  | Route through a proxy (e.g. Burp)                                        |
| `--http2`                  | Native HTTP/2 backend (needs `httpx[http2]`)                             |
| `-o, --output-dir`         | Where reports land (default: current dir)                                |
| `--aggressive`             | Extended dispatcher-bypass / Sling-selector payload set (~10x requests)  |
| `--exploit`                | End-to-end JSP RCE PoC + deserialization probe (drops & removes canary)  |
| `--collaborator DOMAIN`    | Out-of-band SSRF via Burp Collaborator                                   |
| `--ssrf-callback HOST:PORT`| Self-hosted OOB SSRF listener (needs tester-reachable IP)                |
| `-v, --verbose`            | Verbose request logging                                                  |

TLS verification is always off (pentest default).

## What it tests

Every check below runs **unauthenticated**:

| Category               | Coverage                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| Fingerprinting         | Instance type (Author vs Publish), version hints, Sling / Day / CQ headers                        |
| Default credentials    | `admin`, `author`, `anonymous`, `replication-receiver`, Geometrixx demo users, `vgnadmin`, `audit`, `grios`, more |
| Exposed consoles       | Felix `/system/console/*` (bundles, components, services, configMgr, scr, JMX, threads, memoryusage, profiler, logs, healthcheck, events, slingauth, jcrresolver, depfinder, status-*), CRX DE, CRX Package Manager, CRX Explorer, Groovy Console, WebDAV, miscadmin, BulkEditor, Granite operations consoles (maintenance, healthreports, replicationqueue, systemoverview, diagnosistools) |
| QueryBuilder           | `/bin/querybuilder.json` exposure, feed.xml, selector bypasses, **`p.hits=selective&p.properties=rep:password` hash dump**, cross-type rep:User enum |
| Dispatcher bypass      | `.css`/`.js`/`.png`/`.html` selector tricks, `;` semicolon abuse, `..;/` Jetty normalization, `%2f`/`%00`/`%0a` quirks, double-slash, URL-encoding tricks, traversal+suffix combos (full set via `--aggressive`) |
| Sling info dump        | `.json`, `.1.json`, `.tidy.json`, `.infinity.json`, `.harray.4.json`, `.children.json`, `.feed.xml` on `/`, `/content`, `/etc`, `/apps`, `/libs`, `/var`, `/home`, `/tmp`, `/conf`, and many sub-paths |
| JCR enumeration        | `users.1.json`, `groups.1.json`, `currentuser.json`, infinity dumps, authorizables servlet                |
| Cloud services leak    | `/etc/cloudservices.infinity.json` — AWS / Salesforce / 3rd-party credentials leak               |
| Crypto key leak        | `/etc/key.infinity.json` master key (lets you decrypt `{...}` encrypted secrets offline)         |
| Anonymous user create  | `:operation=createUser` POST to `/libs/granite/security/post/authorizables`                       |
| SSRF (URL-confirmed)   | linkchecker, SalesforceSecretServlet (CVE-2018-5006), ReportingServicesServlet (CVE-2018-12809), DAM cloud proxy, OpenSocial proxy, SiteCatalyst, AutoProvisioning, Google OAuth fetcher |
| SSRF (out-of-band)     | Same set via Burp Collaborator (`--collaborator`) or self-hosted listener (`--ssrf-callback`)    |
| **2025 CVEs**          | CVE-2025-54253 (OGNL RCE Forms JEE), CVE-2025-54254 (XXE), CVE-2025-49533 (deserialization)      |
| **2024 CVEs**          | CVE-2024-43712, CVE-2024-43711, CVE-2024-32813, CVE-2024-32812, CVE-2024-32811, CVE-2024-26031, CVE-2024-26030, CVE-2024-20767 (Forms file read), CVE-2024-20736 |
| **2023 CVEs**          | CVE-2023-22368, CVE-2023-22366, CVE-2023-22365                                                   |
| **2022 CVEs**          | CVE-2022-30679, CVE-2022-30680, CVE-2022-23710 (SOAP XXE)                                        |
| **2021 CVEs**          | CVE-2021-44519 (Forms upload XXE baseline), CVE-2021-43762 (path traversal)                      |
| **2019 CVEs**          | CVE-2019-8088, CVE-2019-8087, CVE-2019-8086 (Forms XSS)                                          |
| **2018 CVEs**          | CVE-2018-5006, CVE-2018-12809, CVE-2018-19298, CVE-2018-19297                                    |
| **2017 / 2016 CVEs**   | CVE-2017-3104 (SSTI), CVE-2016-7882 (WCMDebugFilter reflected XSS), CVE-2016-1027                |
| Sling POST abuse       | Arbitrary node creation at `/content/usergenerated`, `/var/dam`, anonymous user creation         |
| Replication            | Transport credentials in `/etc/replication.infinity.json` — direct lateral-move primitives        |
| Source disclosure      | `.source` / `.servlet` selector tricks on JSP-backed paths                                       |
| Extra servlet exposure | GQLServlet, LoginStatusServlet (+ default-cred check), AuditLogServlet, CRXDE logs, Disk Usage, BackgroundServlet, MergeMetadata, dumplibs, nodetypes, ContentFinder suggestions |
| Reflected XSS          | ChildrenList selector, CRXDE setPreferences, WCMDebugFilter, WCMSuggestionsServlet, CQ UI widgets, designs/default `0.gif`, CVE-tagged XSS sinks, **exposed SWF reflected XSS** |
| Open redirect          | `resource=`, `redirect=`, `return=`, `next=`, login `resource=`, WCM page redirect (HTTP 30x + HTML/JS sinks) |
| GraphQL                | Endpoint enumeration + introspection (`{__schema{types{...}}}`)                                  |
| WebDAV methods         | `OPTIONS` to discover writable methods (PUT/DELETE/MKCOL/MOVE), PROPFIND XXE                     |
| ACS AEM Tools          | AEM Fiddle JSP-eval RCE, ACS Tools presence                                                      |
| Deserialization        | ExternalJobServlet Java untrusted-deserialization probe (`--exploit`)                            |
| Nuclei path set        | ~45 detections ported from projectdiscovery/nuclei-templates AEM set + Cappricio aem-xss         |

Much of the servlet/XSS/SSRF coverage is ported from
[0ang3el/aem-hacker](https://github.com/0ang3el/aem-hacker), re-implemented with
this tool's auth-wall suppression and reporting.

### Out-of-band SSRF — Burp Collaborator (`--collaborator`)

Blind SSRF in AEM's connector servlets is confirmed out-of-band. The
recommended way is **Burp Collaborator**:

```bash
python3 aem_hunter.py -u TARGET --proxy http://127.0.0.1:8080 --collaborator abc123.oastify.com
```

It fires one sub-domain per servlet (Salesforce / Reporting / SiteCatalyst /
AutoProvisioning / Opensocial / linkchecker). A DNS/HTTP hit on
`salesforcesecret<id>.abc123.oastify.com` in the Collaborator tab confirms SSRF
via SalesforceSecretServlet (CVE-2018-5006), etc. (The tool can't poll
Collaborator for you, so it reports the probes fired + the sub-domain→servlet
map for attribution.)

Alternatively, if you have a tester-reachable IP (VPS/tunnel, not via Burp),
use a self-hosted auto-confirming listener:

```bash
python3 aem_hunter.py -u TARGET --ssrf-callback 1.2.3.4:8000
```

### `--exploit` — end-to-end RCE PoC

By default the escalation module SAFELY confirms primitives (creates then
immediately deletes throwaway test artifacts). With `--exploit`, it also tries
the end-to-end JSP RCE PoC (drops + removes a canary JSP via the Sling POST
servlet / package install / `sling:resourceType` chain). The canary only prints
`System.getProperty("user.name")` — proves Java code execution without running
OS commands. Use `--exploit` only on systems you're authorized to actively
exploit.

## Accuracy — no "shell loaded = critical" noise

AEM author instances serve the **HTML/JSP shell** of consoles like CRXDE,
Package Manager and the Felix console to *anyone* (HTTP 200), while the actual
functionality stays behind login. Naive scanners flag that 200 as CRITICAL —
a false positive. This tool does not:

- **Login / auth-wall responses are suppressed.** A 200 that is really a login
  page (`j_security_check`, `granite.shell.login`, `QUICKSTART`, sign-in forms,
  auth redirects, 401/403) is never reported as access.
- **Consoles are verified functionally, not by their shell.** A CRITICAL only
  fires when a privileged operation actually succeeds — `bundles.json` returns
  the live OSGi inventory, the package service returns a real package listing,
  or a protected JCR node returns real `jcr:primaryType` JSON. If only the
  shell renders, you get a single **INFO** note, not a critical.
- **Data endpoints must return real JCR/JSON**, not an empty `{}` or an HTML
  page, and severity is upgraded only when the body actually contains
  secret-like material.

So on a locked-down author instance you'll see mostly INFO — which is the
honest answer.

## Reports

Each run produces:

- live console output with severity tags
- `report-<host>-unauthenticated-<ts>.json` — machine readable findings
- `report-<host>-unauthenticated-<ts>.html` — styled report with evidence,
  request/response snippets, references, and CVE badges

The HTML uses inline CSS, so it renders fine on an air-gapped box with no
internet access. Reports are git-ignored so findings never get committed.

## References

Built on top of public research from:

- 0ang3el/aem-hacker
- Assetnote / hopgoblin
- HackTricks AEM section
- Mikhail Egorov, "Hacking AEM" (adaptTo 2018)
- Adobe APSB advisories, CISA KEV (CVE-2025-54253)
- Various HackerOne disclosures (#1247163, #436555, #698991, …)
- projectdiscovery/nuclei-templates (http/misconfiguration/aem set)
- Cappricio-Securities/aem-xss

## License

MIT. Use responsibly.
