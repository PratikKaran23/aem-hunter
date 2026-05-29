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

## Quick start

Interactive mode (prompts for target, cookies, auth, output paths):

```bash
python3 aem_hunter.py
```

Non-interactive baseline scan:

```bash
python3 aem_hunter.py -u https://target.example.com
```

Authenticated scan with a captured Cookie header:

```bash
python3 aem_hunter.py -u https://target.example.com \
  --cookie "login-token=...; cq-authoring-mode=TOUCH"
```

Authenticated scan with HTTP Basic auth:

```bash
python3 aem_hunter.py -u https://target.example.com --basic-auth user:pass
```

Specific modules only:

```bash
python3 aem_hunter.py -u TARGET --modules dispatcher,querybuilder,cve
```

Through a Burp / mitmproxy listener:

```bash
python3 aem_hunter.py -u TARGET --proxy http://127.0.0.1:8080 --insecure
```

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
| Auth role testing    | Walks each authenticated role over the same surfaces and diffs results                            |

## Authenticated / multi-role testing

The Adobe Managed AEM role model has a fixed set of roles (Content Editor,
Content Reviewer and Publisher, Content Viewer, Self-Content Publish Reviewer,
CPB Site Support, CPB Content Package Deployer). Capture a Cookie header for
each role from the browser DevTools and feed them in:

```bash
python3 aem_hunter.py -u TARGET \
  --cookie-role "content-editor:login-token=...; cq-..." \
  --cookie-role "cpb-deployer:login-token=..."
```

Or use interactive mode and add roles one at a time when prompted.

## Reports

Three outputs every run:

- live console with severity tags
- `report-<host>-<ts>.json` – machine readable findings
- `report-<host>-<ts>.html` – styled report with evidence, request/response
  snippets, references and CVE badges

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
