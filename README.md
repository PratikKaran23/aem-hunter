# AEM Hunter

Single-file Adobe Experience Manager (AEM) security audit tool for authorized
penetration testing and bug bounty work. Drop the script onto a box, run it,
and get a console + HTML + JSON report of misconfigurations, exposed admin
surfaces, dispatcher bypasses, and selected CVEs.

> **Authorization required.** Only run this against systems you own or have
> explicit written permission to test.

## Install

```bash
git clone https://github.com/PratikKaran23/aem-hunter.git
cd aem-hunter
pip install -r requirements.txt
```

Single dependency: `requests`. Everything else is standard library.

## Usage

The whole tool is just **URL + cookies**. Start it, and after every scan it
asks you to paste the next Cookie header — so you feed it one user role after
another and it keeps scanning. Press Enter on a blank prompt for an
unauthenticated scan, or type `q` to quit. Every scan writes its own report.

Start it (it will prompt for the URL if you don't pass one):

```bash
python3 aem_hunter.py
python3 aem_hunter.py https://aem.example.com
python3 aem_hunter.py -u https://aem.example.com
```

Pre-load the first role's cookies:

```bash
python3 aem_hunter.py -u https://aem.example.com \
  -c "login-token=...; cq-authoring-mode=TOUCH"
```

Route through Burp / mitmproxy:

```bash
python3 aem_hunter.py -u https://aem.example.com --proxy http://127.0.0.1:8080
```

### The workflow

```
$ python3 aem_hunter.py -u https://aem.example.com

[?] Paste Cookie header (Enter=unauth, q=quit): login-token=AAA...; cq-authoring-mode=TOUCH
[+] Loaded 2 cookie(s) -> cookie-set-1
[+] [cookie-set-1] authenticated as: content-editor@corp
... scan runs, report written ...

[?] Paste Cookie header (Enter=unauth, q=quit): login-token=BBB...     # next role
[+] Loaded 1 cookie(s) -> cookie-set-2
[+] [cookie-set-2] authenticated as: cpb-deployer@corp
... scan runs, report written ...

[?] Paste Cookie header (Enter=unauth, q=quit): q
```

Grab the Cookie header for each role from your browser DevTools (Network tab →
any request → Request Headers → `Cookie`) or from Burp, and paste it in when
prompted. You can also point at a file with `@`, e.g. `@/tmp/editor-cookies.txt`.

### All flags

| Flag                 | Purpose                                            |
| -------------------- | -------------------------------------------------- |
| `target` / `-u`      | Target URL (positional or `-u`; prompted if absent)|
| `-c, --cookie`       | Cookie header for the first scan (optional)        |
| `--proxy`            | Route through a proxy (optional, e.g. Burp)        |
| `-o, --output-dir`   | Where reports land (default: current dir)          |
| `-v, --verbose`      | Verbose request logging                            |

TLS verification is always off (pentest default). That's the entire surface —
no roles to configure, no module flags.

## What it tests

| Category             | Coverage                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------- |
| Fingerprinting       | Instance type (Author vs Publish), version hints, Sling / Day / CQ headers                        |
| Default credentials  | admin, author, anonymous, replication-receiver, Geometrixx demo users, vgnadmin, audit            |
| Exposed consoles     | Felix `/system/console`, CRX DE, CRX Package Manager, CRX Explorer, Groovy Console, WebDAV        |
| QueryBuilder         | `/bin/querybuilder.json` exposure + extension bypasses                                            |
| Dispatcher bypass    | `.css` / `.js` / `.png` / `.html` selector tricks, `;` semicolon abuse, `..;/` Jetty normalization |
| Sling info dump      | `.json`, `.1.json`, `.tidy.json`, `.infinity.json`, `.harray.4.json` on common roots              |
| JCR enumeration      | users.1.json, groups.1.json, currentuser.json, group memberships                                  |
| Cloud services leak  | `/etc/cloudservices.infinity.json` and friends – AWS / Salesforce / 3rd-party credentials leak    |
| SSRF                 | linkchecker, SalesforceSecretServlet (CVE-2018-5006), ReportingServicesServlet (CVE-2018-12809)   |
| 2025 CVE wave        | CVE-2025-54253 (OGNL RCE in Forms JEE), CVE-2025-54254 (XXE), CVE-2025-49533                      |
| Path-traversal CVE   | CVE-2021-43762                                                                                    |
| Sling POST abuse     | Arbitrary node creation, property manipulation, `:operation` and `:member` primitives             |
| Replication          | `/etc/replication.json` and agent transport credentials                                           |
| Source disclosure    | clientlib `.js.source` / `.source.json` quirks                                                    |
| Auth session testing | Re-runs the full battery with each pasted Cookie header + privilege-boundary checks               |

When you paste a Cookie header, the tool first hits
`/libs/granite/security/currentuser.json` and prints who you authenticated as,
so you immediately know whether the session is valid or expired before the scan
runs. Each authenticated scan also probes admin-only surfaces (CRXDE, OSGi
bundles, cloud-services tree, user/group trees, Groovy console) and flags any
that this session can reach as a privilege-boundary violation.

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
  or a protected JCR node returns real `jcr:primaryType` JSON. If only the shell
  renders, you get a single **INFO** note ("shell loads but no privileged
  access — retest with role cookies"), not a critical.
- **Data endpoints must return real JCR/JSON**, not an empty `{}` or an HTML
  page, and severity is upgraded only when the body actually contains
  secret-like material.

So on a locked-down author instance you'll see mostly INFO — which is the
honest answer. The real findings come from the authenticated passes: paste a
low-privilege role's cookies and the same functional checks reveal whether that
role can drive a console or read admin data it shouldn't.

## Reports

For **every** scan (each cookie set + the unauthenticated baseline) you get:

- live console output with severity tags
- `report-<host>-<scan>-<ts>.json` – machine readable findings
- `report-<host>-<scan>-<ts>.html` – styled report with evidence,
  request/response snippets, references and CVE badges

The HTML uses inline CSS, so it renders fine on an air-gapped box with no
internet access. Reports are git-ignored so findings never get committed.

## References

Built on top of public research from:

- 0ang3el/aem-hacker
- Assetnote / hopgoblin
- HackTricks AEM section
- Mikhail Egorov, "Hacking AEM" (adaptTo 2018)
- Adobe APSB advisories, CISA KEV (CVE-2025-54253)
- Various HackerOne disclosures (#1247163, #436555, #698991, ...)

## License

MIT.  Use responsibly.
