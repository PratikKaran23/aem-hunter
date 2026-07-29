#!/usr/bin/env python3
# cp_patterns.py -- dump CP + URI patterns for a CSI ID into xlsx/csv.

import sys
import ssl
import json
import time
import zipfile
import xml.sax.saxutils as sx
from urllib import request as _urlreq
from urllib import parse as _urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

BASE_URL = "https://uat.citivelocity.com"
PAGE_SIZE = 50
REQUEST_TIMEOUT = 30
INTER_REQUEST_DELAY = 0.15

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) "
    "Gecko/20100101 Firefox/152.0"
)


def ts_ms():
    return int(time.time() * 1000)


class HttpClient:
    def __init__(self, cookie):
        self.cookie = cookie
        self.headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Cookie": cookie,
            "Referer": f"{BASE_URL}/",
            "Connection": "keep-alive",
        }
        if HAVE_REQUESTS:
            self._sess = requests.Session()
            self._sess.headers.update(self.headers)
            self._sess.verify = False
        else:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def get_json(self, url, params):
        if HAVE_REQUESTS:
            r = self._sess.get(url, params=params, timeout=REQUEST_TIMEOUT)
            status, body = r.status_code, r.text
        else:
            qs = _urlparse.urlencode(params)
            full = f"{url}?{qs}"
            req = _urlreq.Request(full, headers=self.headers)
            try:
                with _urlreq.urlopen(req, timeout=REQUEST_TIMEOUT, context=self._ctx) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8", errors="replace")
            except Exception as e:
                raise RuntimeError(f"HTTP error: {e}") from e

        if status != 200:
            raise RuntimeError(f"HTTP {status}. Body preview: {body[:300]}")

        try:
            return json.loads(body)
        except ValueError:
            raise RuntimeError(
                "Non-JSON response (probably a login redirect). "
                "Refresh your cookie and try again."
            )


def get_cps_for_csi(client, csi_id):
    url = f"{BASE_URL}/portal-admin-service/cp/query/getByCritAndPortal"
    page = 0
    all_cps = []
    while True:
        data = client.get_json(url, {
            "pageNo": page,
            "pageSize": PAGE_SIZE,
            "portal": "CitiVelocity",
            "criteria": "csiId",
            "critValue": csi_id,
            "timeStamp": ts_ms(),
        })
        if not isinstance(data, list):
            data = (data or {}).get("data") or (data or {}).get("result") or []
        if not data:
            break
        all_cps.extend(data)
        if len(data) < PAGE_SIZE:
            break
        page += 1
        time.sleep(INTER_REQUEST_DELAY)
    return all_cps


def get_patterns_for_cp(client, cp_id):
    url = f"{BASE_URL}/portal-admin-service/cpPattern/query/queryByCpId"
    data = client.get_json(url, {"cpId": cp_id, "timeStamp": ts_ms()})
    if not isinstance(data, list):
        data = (data or {}).get("data") or (data or {}).get("result") or []
    return data


STYLE_DEFAULT = 0
STYLE_TITLE = 1
STYLE_LABEL = 2
STYLE_HEADER = 3
STYLE_DATA = 4
STYLE_RISK = 5
STYLE_WARN = 6

STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="4">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="14"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
  </fonts>
  <fills count="5">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor rgb="FF1F4E78"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF8CBAD"/><bgColor rgb="FFF8CBAD"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/><bgColor rgb="FFFFF2CC"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border>
      <left style="thin"><color rgb="FFB0B0B0"/></left>
      <right style="thin"><color rgb="FFB0B0B0"/></right>
      <top style="thin"><color rgb="FFB0B0B0"/></top>
      <bottom style="thin"><color rgb="FFB0B0B0"/></bottom>
      <diagonal/>
    </border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="7">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
    <xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
    <xf numFmtId="0" fontId="3" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"/>
    <xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1"/>
    <xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0" applyFill="1" applyBorder="1"/>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""

_ILLEGAL_XML_CHARS = "".join(chr(c) for c in list(range(0, 9)) + [11, 12] + list(range(14, 32)))
_XML_CHAR_TRANS = str.maketrans("", "", _ILLEGAL_XML_CHARS)


def _xml_safe(s):
    if s is None:
        return ""
    return str(s).translate(_XML_CHAR_TRANS)


def _xml_escape(s):
    return sx.escape(_xml_safe(s), {'"': "&quot;"})


def _col_letter(n):
    r = ""
    while n > 0:
        n, rem = divmod(n - 1, 26)
        r = chr(65 + rem) + r
    return r


def _cell_xml(row_num, col_num, value, style):
    ref = f"{_col_letter(col_num)}{row_num}"
    style_attr = f' s="{style}"' if style else ""
    if value is None or value == "":
        return f'<c r="{ref}"{style_attr}/>'
    if isinstance(value, bool):
        value = str(value)
    if isinstance(value, (int, float)):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    return f'<c r="{ref}"{style_attr} t="inlineStr"><is><t xml:space="preserve">{_xml_escape(value)}</t></is></c>'


def _row_xml(row_num, cells):
    parts = [f'<row r="{row_num}">']
    for col_num, value, style in cells:
        parts.append(_cell_xml(row_num, col_num, value, style))
    parts.append("</row>")
    return "".join(parts)


def _worksheet_xml(cols_widths, rows, freeze_row=None):
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
    ]
    if freeze_row:
        parts.append(
            '<sheetViews><sheetView workbookViewId="0">'
            f'<pane ySplit="{freeze_row - 1}" topLeftCell="A{freeze_row}" '
            'activePane="bottomLeft" state="frozen"/>'
            '</sheetView></sheetViews>'
        )
    if cols_widths:
        parts.append("<cols>")
        for i, w in enumerate(cols_widths, 1):
            parts.append(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>')
        parts.append("</cols>")
    parts.append("<sheetData>")
    for row_num, cells in rows:
        parts.append(_row_xml(row_num, cells))
    parts.append("</sheetData></worksheet>")
    return "".join(parts)


def _content_types(num_sheets):
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for i in range(1, num_sheets + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        f'{overrides}'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '</Types>'
    )


def _root_rels():
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    )


def _workbook_xml(sheet_names):
    sheets = "".join(
        f'<sheet name="{_xml_escape(name)}" sheetId="{i}" r:id="rId{i}"/>'
        for i, name in enumerate(sheet_names, 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets>{sheets}</sheets>'
        '</workbook>'
    )


def _workbook_rels(num_sheets):
    rels = "".join(
        f'<Relationship Id="rId{i}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, num_sheets + 1)
    )
    styles_id = num_sheets + 1
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'{rels}'
        f'<Relationship Id="rId{styles_id}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        '</Relationships>'
    )


def write_xlsx(path, sheets):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        n = len(sheets)
        zf.writestr("[Content_Types].xml", _content_types(n))
        zf.writestr("_rels/.rels", _root_rels())
        zf.writestr("xl/workbook.xml", _workbook_xml([s["name"] for s in sheets]))
        zf.writestr("xl/_rels/workbook.xml.rels", _workbook_rels(n))
        zf.writestr("xl/styles.xml", STYLES_XML)
        for i, sheet in enumerate(sheets, 1):
            zf.writestr(
                f"xl/worksheets/sheet{i}.xml",
                _worksheet_xml(sheet.get("cols", []), sheet["rows"], sheet.get("freeze_row")),
            )


def write_csv(path, csi_id, cp_records):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([f"CSI ID: {csi_id}"])
        w.writerow([f"Total CPs: {len(cp_records)}"])
        w.writerow([])
        w.writerow(["CP ID", "CP Name", "URI Pattern", "Min Auth Level", "Expose Externally"])
        for rec in cp_records:
            if rec.get("error"):
                w.writerow([rec["cpId"], rec["cpName"], f"ERROR: {rec['error']}", "", ""])
                continue
            if not rec["patterns"]:
                w.writerow([rec["cpId"], rec["cpName"], "(no patterns)", "", ""])
                continue
            for p in rec["patterns"]:
                w.writerow([
                    rec["cpId"],
                    rec["cpName"],
                    p.get("uriPattern"),
                    p.get("minAuthenticationLevel"),
                    p.get("exposeExternally"),
                ])


def build_workbook(csi_id, cp_records):
    rows1 = []
    rows1.append((1, [(1, "CSI ID:", STYLE_TITLE), (2, csi_id, STYLE_TITLE)]))
    rows1.append((2, [(1, "Total CPs:", STYLE_LABEL), (2, len(cp_records), STYLE_LABEL)]))
    total_patterns = sum(len(r["patterns"]) for r in cp_records)
    rows1.append((3, [(1, "Total Patterns:", STYLE_LABEL), (2, total_patterns, STYLE_LABEL)]))

    header_row = 5
    rows1.append((header_row, [
        (1, "CP ID", STYLE_HEADER),
        (2, "CP Name", STYLE_HEADER),
        (3, "URI Pattern", STYLE_HEADER),
        (4, "Min Auth Level", STYLE_HEADER),
        (5, "Expose Externally", STYLE_HEADER),
    ]))

    r_idx = header_row + 1
    for rec in cp_records:
        cp_id = rec["cpId"]
        cp_name = rec["cpName"]

        if rec.get("error"):
            rows1.append((r_idx, [
                (1, cp_id, STYLE_DATA),
                (2, cp_name, STYLE_DATA),
                (3, f"ERROR: {rec['error']}", STYLE_DATA),
                (4, "", STYLE_DATA),
                (5, "", STYLE_DATA),
            ]))
            r_idx += 1
            continue

        if not rec["patterns"]:
            rows1.append((r_idx, [
                (1, cp_id, STYLE_DATA),
                (2, cp_name, STYLE_DATA),
                (3, "(no patterns)", STYLE_DATA),
                (4, "", STYLE_DATA),
                (5, "", STYLE_DATA),
            ]))
            r_idx += 1
            continue

        for p in rec["patterns"]:
            uri = p.get("uriPattern")
            min_auth = p.get("minAuthenticationLevel")
            expose = p.get("exposeExternally")

            weak_auth = str(min_auth).upper() in ("NONE", "0", "N", "NULL", "")
            externally_exposed = str(expose).upper() in ("Y", "YES", "TRUE")
            if weak_auth and externally_exposed:
                style = STYLE_RISK
            elif weak_auth or externally_exposed:
                style = STYLE_WARN
            else:
                style = STYLE_DATA

            rows1.append((r_idx, [
                (1, cp_id, style),
                (2, cp_name, style),
                (3, uri, style),
                (4, min_auth, style),
                (5, expose, style),
            ]))
            r_idx += 1

    rows2 = []
    rows2.append((1, [(1, "CSI ID:", STYLE_TITLE), (2, csi_id, STYLE_TITLE)]))
    rows2.append((3, [
        (1, "CP ID", STYLE_HEADER),
        (2, "CP Name", STYLE_HEADER),
        (3, "Pattern Count", STYLE_HEADER),
    ]))
    for i, rec in enumerate(cp_records, start=4):
        count = "ERR" if rec.get("error") else len(rec["patterns"])
        rows2.append((i, [
            (1, rec["cpId"], STYLE_DATA),
            (2, rec["cpName"], STYLE_DATA),
            (3, count, STYLE_DATA),
        ]))

    rows3 = []
    rows3.append((1, [(1, "Row Highlighting", STYLE_TITLE)]))
    rows3.append((3, [
        (1, "Orange", STYLE_RISK),
        (2, "Exposed externally AND minAuthenticationLevel is weak/NONE", STYLE_DEFAULT),
    ]))
    rows3.append((4, [
        (1, "Yellow", STYLE_WARN),
        (2, "Exposed externally OR minAuthenticationLevel is weak/NONE", STYLE_DEFAULT),
    ]))

    return [
        {"name": "Patterns",  "cols": [12, 32, 70, 20, 20], "rows": rows1, "freeze_row": header_row + 1},
        {"name": "CP Summary","cols": [12, 40, 15],         "rows": rows2, "freeze_row": 4},
        {"name": "Legend",    "cols": [14, 80],             "rows": rows3},
    ]


def read_cookie():
    print("Paste Cookie header (single line, or multi-line then empty line):")
    first = input("Cookie: ").strip()
    if not first:
        print("[!] Empty cookie, aborting.")
        sys.exit(1)
    lines = [first]
    try:
        while True:
            more = input()
            if not more.strip():
                break
            lines.append(more.strip())
    except EOFError:
        pass
    return " ".join(lines)


def main():
    csi_id = input("CSI ID: ").strip()
    if not csi_id:
        print("[!] CSI ID is required.")
        sys.exit(1)

    cookie = read_cookie()
    client = HttpClient(cookie)

    print(f"\n[*] Fetching CPs for CSI ID {csi_id} ...")
    try:
        cps = get_cps_for_csi(client, csi_id)
    except Exception as e:
        print(f"[!] {e}")
        sys.exit(1)

    if not cps:
        print("[!] No CPs returned. Check the CSI ID or the cookie.")
        sys.exit(1)

    print(f"[+] Found {len(cps)} CP(s):")
    for cp in cps:
        print(f"    - cpId={cp.get('cpId')}  name={cp.get('name')}")

    cp_records = []
    for i, cp in enumerate(cps, 1):
        cp_id = cp.get("cpId")
        cp_name = cp.get("name")
        print(f"\n[*] ({i}/{len(cps)}) Fetching patterns for cpId={cp_id} ({cp_name})")
        rec = {"cpId": cp_id, "cpName": cp_name, "patterns": [], "error": None}
        try:
            rec["patterns"] = get_patterns_for_cp(client, cp_id)
            print(f"    [+] {len(rec['patterns'])} pattern(s)")
        except Exception as e:
            rec["error"] = str(e)
            print(f"    [!] {e}")
        cp_records.append(rec)
        time.sleep(INTER_REQUEST_DELAY)

    stamp = int(time.time())
    xlsx_path = f"citivelocity_csi_{csi_id}_{stamp}.xlsx"
    csv_path = f"citivelocity_csi_{csi_id}_{stamp}.csv"

    write_xlsx(xlsx_path, build_workbook(csi_id, cp_records))
    write_csv(csv_path, csi_id, cp_records)

    print(f"\n[+] Done.")
    print(f"    Excel : {xlsx_path}")
    print(f"    CSV   : {csv_path}   (fallback / raw)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
