# -*- coding: utf-8 -*-
"""
SM_USER Bypass Scanner - Burp Suite extension (Jython)
======================================================

For every request pulled from a source (proxy history, site map, or
right-click selection), the extension:

  1. Strips every Cookie header from the original request.
  2. Adds a custom header (default: `SM_USER: pk32394`).
     If the target header already exists, its value is replaced.
  3. Sends the modified request through Burp's HTTP stack
     (no redirect following, so 302s stay visible).
  4. Classifies the response:
       - status in "working" list  (default 2xx)  -> saved to .txt + table row
       - status in "skip" list     (default 3xx)  -> silently dropped
       - anything else                             -> counted only
  5. Only working hits are exported. Each hit becomes one .txt file that
     contains the raw request bytes, a blank line, then the raw response
     bytes -- nothing else.

DESIGNED FOR LARGE HISTORY (60k+ requests)
------------------------------------------
  * Only working hits are added to the results table.
  * Response/request bytes for every hit are retained in memory so the
    double-click dialog always works (no cap). If your scans produce
    huge numbers of large-body hits, give Burp more heap.
  * Progress bar and log updates are throttled (4 Hz / 200 KB cap).
  * Worker submission runs on a background thread so a huge queue never
    stalls Burp's UI thread.
  * Give Burp extra heap if you plan to run 60k+ scans:
       ...\jre\bin\java.exe -Xmx4G -jar burpsuite_community.jar

LOADING
-------
1. Download `jython-standalone-2.7.x.jar` from https://www.jython.org/download
2. Burp -> Extensions -> Extensions -> Options -> Python Environment ->
       "Location of Jython standalone JAR file" -> point at the JAR
3. Burp -> Extensions -> Installed -> Add:
       Extension type : Python
       Extension file : <path>\\SMUserBypass.py
4. Open the "SM_USER Bypass" tab.

USAGE
-----
  * "Scan Proxy History"  - replays every proxy history item.
  * "Scan Site Map"       - same but from the site map.
  * Right-click request(s) anywhere in Burp -> "Test with SM_USER bypass".
  * Double-click a result row to open its exported .txt file.
"""

from burp import (
    IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener,
    IMessageEditorController,
)
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JTextField, JLabel, JTextArea,
    JCheckBox, JSplitPane, JFileChooser, SwingUtilities,
    JMenuItem, JPopupMenu, ListSelectionModel, BorderFactory, JProgressBar,
    BoxLayout, JDialog, JOptionPane, KeyStroke, JComponent, AbstractAction,
    RowFilter,
)
from javax.swing.table import DefaultTableModel, TableRowSorter
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, FlowLayout, Desktop, Toolkit,
)
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, MouseAdapter, KeyEvent
from java.util import ArrayList
from java.util.concurrent import Executors, TimeUnit
from java.util.concurrent.atomic import AtomicInteger, AtomicLong
from java.io import File, FileOutputStream
from java.lang import Runnable, Thread as JThread, String, System

from collections import OrderedDict
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

# Segments matching these patterns get replaced with a placeholder so that
# /users/1, /users/42, /users/9a3f-... all normalize to the same endpoint.
_UUID_RE    = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONGHEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def _s(text):
    """Python str -> Java byte[] (UTF-8)."""
    return String(text).getBytes("UTF-8")


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


def _endpoint_key(method, url, normalize):
    """Return a canonical (method, endpoint) string used for dedup.

    normalize=True  -> strip query/fragment, template numeric / UUID / long-hex
                        segments (so /users/1, /users/2, /users/<uuid> collapse
                        into one endpoint).
    normalize=False -> exact URL match (query preserved, no templating)."""
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
    return "%s %s://%s:%d%s" % (method, scheme, host, port, "/".join(out))


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
        add_row(r, "Header value:", self._header_value_field); r += 1

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
        gbc.gridx = 0; gbc.gridy = r; gbc.gridwidth = 4; gbc.weightx = 1
        cfg.add(opts, gbc); r += 1; gbc.gridwidth = 1

        # ---------- actions ----------
        act = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))
        act.setBorder(BorderFactory.createTitledBorder("Actions"))

        self._btn_scan_history = JButton("Scan Proxy History")
        self._btn_scan_history.addActionListener(self._al(self._on_scan_history))
        act.add(self._btn_scan_history)

        self._btn_scan_sitemap = JButton("Scan Site Map")
        self._btn_scan_sitemap.addActionListener(self._al(self._on_scan_sitemap))
        act.add(self._btn_scan_sitemap)

        self._btn_scan_both = JButton("Scan Both (History + Site Map)")
        self._btn_scan_both.setToolTipText(
            "Combines proxy history and site map into one scan. "
            "Dedup collapses any overlap so nothing is tested twice.")
        self._btn_scan_both.addActionListener(self._al(self._on_scan_both))
        act.add(self._btn_scan_both)

        self._btn_stop = JButton("Stop")
        self._btn_stop.setEnabled(False)
        self._btn_stop.addActionListener(self._al(self._on_stop))
        act.add(self._btn_stop)

        self._btn_clear = JButton("Clear Results")
        self._btn_clear.addActionListener(self._al(self._on_clear))
        act.add(self._btn_clear)

        self._btn_open_out = JButton("Open Output Folder")
        self._btn_open_out.addActionListener(self._al(self._on_open_output))
        act.add(self._btn_open_out)

        # ---------- progress ----------
        prog = JPanel(BorderLayout(5, 0))
        prog.setBorder(BorderFactory.createEmptyBorder(3, 5, 3, 5))
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setString("Idle")
        prog.add(self._progress_bar, BorderLayout.CENTER)

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.add(cfg)
        top.add(act)
        top.add(prog)

        # ---------- results table ----------
        cols = ["#", "Method", "URL",
                "Orig Status", "New Status", "Type", "New Length", "Diff",
                "Exported To"]
        self._table_model = DefaultTableModel(cols, 0)
        self._table = JTable(self._table_model)
        self._table_sorter = TableRowSorter(self._table_model)
        self._table.setRowSorter(self._table_sorter)
        self._table.setFillsViewportHeight(True)
        widths = [50, 60, 500, 90, 90, 60, 90, 60, 500]
        for i, w in enumerate(widths):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.addMouseListener(_TableRowAdapter(self))

        # Filter row (above the table): one checkbox per content-type bucket.
        filter_row = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        filter_row.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        filter_row.add(JLabel("Show response types:"))
        self._type_cbs = {}
        for t in CONTENT_TYPES:
            cb = JCheckBox(t, True)
            cb.addActionListener(self._al(lambda ev: self._refresh_type_filter()))
            filter_row.add(cb)
            self._type_cbs[t] = cb
        # All / None quick toggles
        all_btn = JButton("All")
        all_btn.addActionListener(self._al(
            lambda ev: self._set_all_type_cbs(True)))
        none_btn = JButton("None")
        none_btn.addActionListener(self._al(
            lambda ev: self._set_all_type_cbs(False)))
        filter_row.add(all_btn)
        filter_row.add(none_btn)

        table_area = JPanel(BorderLayout())
        table_area.add(filter_row,             BorderLayout.NORTH)
        table_area.add(JScrollPane(self._table), BorderLayout.CENTER)

        table_scroll = table_area  # keep the variable name used below

        # ---------- log ----------
        self._log_area = JTextArea(8, 80)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
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
        self._progress_bar.setValue(0)
        self._progress_bar.setString("Idle")

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

        in_scope_only = self._in_scope_only_cb.isSelected()
        dedup         = self._dedup_cb.isSelected()
        normalize     = self._normalize_cb.isSelected()
        strip_auth    = self._strip_auth_cb.isSelected()
        log_hits      = self._log_hits_cb.isSelected()
        skip_exts     = _parse_extensions(self._skip_ext_field.getText())

        self._log("Filtering %d source items..." % len(items))
        planned = []
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

        if not planned:
            self._log("Nothing to scan from %s (scope-skipped %d, static-skipped %d, dup-skipped %d)."
                      % (source_label, skipped_scope, skipped_static, skipped_dup))
            if in_scope_only:
                self._log('Hint: uncheck "In-scope items only" or add a Burp scope.')
            return

        self._log("Scanning %d requests from %s (scope-skipped %d, static-skipped %d, dup-skipped %d)"
                  % (len(planned), source_label, skipped_scope, skipped_static, skipped_dup))
        self._log("  Injected header : %s: %s" % (h_name, h_value))
        self._log("  Threads=%d  DelayMs=%d  InScopeOnly=%s  Dedup=%s  Normalize=%s  StripAuth=%s"
                  % (threads, delay, in_scope_only, dedup, normalize, strip_auth))
        self._log("  Working codes   : %s" % sorted(working_codes))
        self._log("  Skip codes      : %s" % sorted(skip_codes))
        self._log("  Output dir      : %s" % out_dir)

        self._cancel_flag.clear()
        self._is_running = True
        self._request_counter.set(0)
        self._working_counter.set(0)
        self._skipped_counter.set(0)
        self._other_counter.set(0)
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
            strip_auth, delay, threads, log_hits)
        runner.setDaemon(True)
        runner.start()

    def _begin_run_ui(self):
        self._btn_stop.setEnabled(True)
        self._btn_scan_history.setEnabled(False)
        self._btn_scan_sitemap.setEnabled(False)
        self._btn_scan_both.setEnabled(False)
        self._btn_clear.setEnabled(False)
        self._progress_bar.setValue(0)
        self._progress_bar.setString("Starting...")

    def _reset_buttons(self):
        self._btn_stop.setEnabled(False)
        self._btn_scan_history.setEnabled(True)
        self._btn_scan_sitemap.setEnabled(True)
        self._btn_scan_both.setEnabled(True)
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
            result["new_status"],
            result.get("content_type") or "NONE",
            result["new_length"],
            result["diff"] if result["diff"] is not None else "-",
            result.get("exported_to") or "",
        ]
        def add():
            self._table_model.addRow(row)
        SwingUtilities.invokeLater(_R(add))

    # ---- content-type filter --------------------------------------
    def _allowed_types(self):
        return set(t for t, cb in self._type_cbs.items() if cb.isSelected())

    def _refresh_type_filter(self):
        try:
            self._table_sorter.setRowFilter(_TypeRowFilter(self))
        except:
            traceback.print_exc()

    def _set_all_type_cbs(self, value):
        for cb in self._type_cbs.values():
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
                      method, url, new_status, orig_status, exported_path):
        """Retain the raw bytes so the double-click dialog can render them
        in a Burp message editor. No cap -- every hit stays in memory."""
        with self._hits_data_lock:
            self._hits_data[int(idx)] = {
                "service"      : service,
                "request"      : request,
                "response"     : response,
                "method"       : method,
                "url"          : url,
                "new_status"   : new_status,
                "orig_status"  : orig_status,
                "exported_path": exported_path,
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


class _RequestWorker(Runnable):
    def __init__(self, ext, item, h_name, h_value,
                 working_codes, skip_codes, strip_auth, delay_ms, log_hits):
        self.ext           = ext
        self.item          = item
        self.h_name        = h_name
        self.h_value       = h_value
        self.working_codes = working_codes
        self.skip_codes    = skip_codes
        self.strip_auth    = strip_auth
        self.delay_ms      = delay_ms
        self.log_hits      = log_hits

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

        # Rebuild headers: drop Cookie, add/replace target, optionally
        # strip Authorization.
        original_headers = list(info.getHeaders())
        new_headers      = []
        replaced_target  = False
        target_prefix    = self.h_name.lower() + ":"
        for h in original_headers:
            lower = h.lower()
            if lower.startswith("cookie:"):
                continue
            if self.strip_auth and lower.startswith("authorization:"):
                continue
            if lower.startswith(target_prefix):
                new_headers.append("%s: %s" % (self.h_name, self.h_value))
                replaced_target = True
                continue
            new_headers.append(h)
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

        result = {
            "index"              : idx,
            "method"             : method,
            "url"                : url.toString(),
            "orig_status"        : orig_status,
            "new_status"         : new_status,
            "new_length"         : new_len,
            "diff"               : diff,
            "content_type"       : content_type,
            "new_request_bytes"  : new_request,
            "new_response_bytes" : response,
            "exported_to"        : None,
        }

        ext._write_hit_file(result)

        # Retain bytes in a small in-memory cache so double-clicking the
        # row can render the request+response in a Burp dialog. Capped
        # at MAX_HITS_IN_MEMORY; older hits fall back to the .txt on disk.
        ext._add_hit_data(idx, service, new_request, response,
                          method, url.toString(), new_status, orig_status,
                          result.get("exported_to"))
        # Drop bytes from the result dict -- they now live in _hits_data.
        result["new_request_bytes"]  = None
        result["new_response_bytes"] = None

        ext._record_hit(result)
        if self.log_hits:
            ext._log("[+] HIT #%d %s -> %d  %s"
                     % (idx, method, new_status, result["url"]))


class _SubmitAndWatch(JThread):
    """Background thread that submits all workers, then waits for completion.
    Keeps submission off the EDT so a 60k queue doesn't stall Burp's UI."""

    def __init__(self, ext, planned, h_name, h_value,
                 working_codes, skip_codes, strip_auth, delay_ms,
                 threads, log_hits):
        JThread.__init__(self)
        self.ext           = ext
        self.planned       = planned
        self.h_name        = h_name
        self.h_value       = h_value
        self.working_codes = working_codes
        self.skip_codes    = skip_codes
        self.strip_auth    = strip_auth
        self.delay_ms      = delay_ms
        self.threads       = threads
        self.log_hits      = log_hits

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
                    self.strip_auth, self.delay_ms, self.log_hits)
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
    """Hides table rows whose Type column is not in the allowed set."""
    TYPE_COL = 5

    def __init__(self, ext):
        self._ext = ext

    def include(self, entry):
        try:
            t = entry.getValue(_TypeRowFilter.TYPE_COL)
            if t is None:
                return True
            return str(t) in self._ext._allowed_types()
        except:
            return True


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
            "path": model.getValueAt(model_row, 8),
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
