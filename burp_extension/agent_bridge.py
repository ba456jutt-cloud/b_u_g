# Bug Bounty Agent — Burp Suite Extension
# Written for Jython 2.7 (Burp Suite Community & Pro)
# 
# HOW TO INSTALL:
# 1. Open Burp Suite
# 2. Go to Extender (or Extensions) tab
# 3. Click "Add"
# 4. Set Extension Type: Python
# 5. Set Extension file: path to this agent_bridge.py
# 6. Click Next — extension loads automatically
#
# REQUIREMENTS:
# - Download Jython 2.7 standalone JAR from: https://www.jython.org/download
# - In Burp: Extender > Options > Python Environment > set Jython JAR path
#
# USAGE:
# - Right-click any request in Proxy/Repeater/Target → "Send to Bug Bounty Agent"
# - A new Burp tab "Agent Results" shows all findings
# - Extension connects to: http://localhost:8000

from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpListener
from javax.swing import (
    JPanel, JScrollPane, JTextArea, JSplitPane, JLabel,
    JButton, BoxLayout, BorderFactory, JComboBox, JTextField,
    SwingUtilities, JProgressBar
)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Dimension, Color, Font, FlowLayout
from java.net import URL, HttpURLConnection
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
from java.lang import Thread, Runnable, StringBuilder
import json
import sys

# ── Configuration ─────────────────────────────────────────────────────────────
AGENT_API_BASE = "http://localhost:8000"
SCAN_ENDPOINT = AGENT_API_BASE + "/burp/scan"
STATUS_ENDPOINT = AGENT_API_BASE + "/burp/status"
POC_ENDPOINT = AGENT_API_BASE + "/scan/poc"
TASKS_ENDPOINT = AGENT_API_BASE + "/tasks"

EXTENSION_NAME = "Bug Bounty Agent Bridge"
VERSION = "1.0.0"


# ── HTTP Helper ───────────────────────────────────────────────────────────────
def http_post(url_str, payload_dict):
    """Send POST request with JSON body, return response string."""
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("User-Agent", "BurpExtension/AgentBridge-1.0")
        conn.setDoOutput(True)
        conn.setConnectTimeout(5000)
        conn.setReadTimeout(60000)  # 60s for scan operations

        payload_str = json.dumps(payload_dict)
        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        writer.write(payload_str)
        writer.flush()
        writer.close()

        status = conn.getResponseCode()
        if status == 200:
            reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
        else:
            reader = BufferedReader(InputStreamReader(conn.getErrorStream(), "UTF-8"))

        sb = StringBuilder()
        line = reader.readLine()
        while line is not None:
            sb.append(line).append("\n")
            line = reader.readLine()
        reader.close()
        return status, sb.toString()
    except Exception as e:
        return 0, "Connection error: " + str(e)


def http_get(url_str):
    """GET request, return response string."""
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("GET")
        conn.setConnectTimeout(3000)
        conn.setReadTimeout(5000)
        status = conn.getResponseCode()
        if status == 200:
            reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
        else:
            return status, "HTTP " + str(status)
        sb = StringBuilder()
        line = reader.readLine()
        while line is not None:
            sb.append(line).append("\n")
            line = reader.readLine()
        reader.close()
        return status, sb.toString()
    except Exception as e:
        return 0, str(e)


# ── Background Scan Thread ────────────────────────────────────────────────────
class ScanRunner(Runnable):
    def __init__(self, url, vuln_type, output_area, status_bar):
        self.url = url
        self.vuln_type = vuln_type
        self.output_area = output_area
        self.status_bar = status_bar

    def run(self):
        self._set_status("Scanning: " + self.url + " ...")
        self._append("\n" + "=" * 70 + "\n")
        self._append("TARGET: " + self.url + "\n")
        self._append("VULN TYPE: " + self.vuln_type + "\n")
        self._append("=" * 70 + "\n\n")

        payload = {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "source": "burp_extension",
        }
        status_code, response = http_post(SCAN_ENDPOINT, payload)

        if status_code == 200:
            try:
                data = json.loads(response)
                result = data.get("result", response)
            except Exception:
                result = response
            self._append(result)
            self._set_status("[DONE] Scan complete for: " + self.url)
        else:
            self._append("[ERROR] Scan failed (HTTP " + str(status_code) + ")\n")
            self._append(response[:500])
            self._set_status("[ERROR] Scan failed — is the backend running?")

        self._append("\n\n")

    def _append(self, text):
        final_text = text
        def do_append():
            self.output_area.append(final_text)
            # Auto-scroll to bottom
            self.output_area.setCaretPosition(self.output_area.getDocument().getLength())
        SwingUtilities.invokeLater(do_append)

    def _set_status(self, msg):
        m = msg
        def do_status():
            self.status_bar.setText(m)
        SwingUtilities.invokeLater(do_status)


# ── Burp Results Tab UI ───────────────────────────────────────────────────────
class AgentResultsTab(ITab):
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._build_ui()

    def getTabCaption(self):
        return "🤖 Agent"

    def getUiComponent(self):
        return self.panel

    def _build_ui(self):
        self.panel = JPanel(BorderLayout())
        self.panel.setBackground(Color(15, 20, 30))

        # ── Top bar ──
        top_bar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        top_bar.setBackground(Color(10, 15, 25))
        top_bar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(30, 41, 59)))

        title_lbl = JLabel("  Bug Bounty Agent Bridge v" + VERSION)
        title_lbl.setForeground(Color(148, 163, 184))
        title_lbl.setFont(Font("Monospaced", Font.BOLD, 12))
        top_bar.add(title_lbl)

        self.status_label = JLabel("  ⬤ Not connected")
        self.status_label.setForeground(Color(239, 68, 68))
        self.status_label.setFont(Font("Monospaced", Font.PLAIN, 11))
        top_bar.add(self.status_label)

        check_btn = JButton("Check Connection")
        check_btn.setFont(Font("SansSerif", Font.PLAIN, 11))
        check_btn.addActionListener(lambda e: self._check_connection())
        top_bar.add(check_btn)

        clear_btn = JButton("Clear Output")
        clear_btn.setFont(Font("SansSerif", Font.PLAIN, 11))
        clear_btn.addActionListener(lambda e: self.output_area.setText(""))
        top_bar.add(clear_btn)

        self.panel.add(top_bar, BorderLayout.NORTH)

        # ── Manual scan input ──
        input_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        input_panel.setBackground(Color(12, 18, 30))
        input_panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(30, 41, 59)))

        url_lbl = JLabel("URL:")
        url_lbl.setForeground(Color(100, 116, 139))
        url_lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        input_panel.add(url_lbl)

        self.url_field = JTextField(35)
        self.url_field.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.url_field.setText("http://localhost:3001/rest/user/login?email=test")
        input_panel.add(self.url_field)

        vuln_lbl = JLabel("Type:")
        vuln_lbl.setForeground(Color(100, 116, 139))
        vuln_lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        input_panel.add(vuln_lbl)

        self.vuln_combo = JComboBox(["all", "sqli", "xss", "ssrf", "open_redirect", "path_traversal", "crlf", "cmdi", "ssti", "idor"])
        self.vuln_combo.setFont(Font("Monospaced", Font.PLAIN, 11))
        input_panel.add(self.vuln_combo)

        scan_btn = JButton("▶ Scan")
        scan_btn.setFont(Font("SansSerif", Font.BOLD, 11))
        scan_btn.setForeground(Color(250, 250, 250))
        scan_btn.setBackground(Color(29, 78, 216))
        scan_btn.addActionListener(lambda e: self._run_manual_scan())
        input_panel.add(scan_btn)

        self.panel.add(input_panel, BorderLayout.CENTER)

        # ── Output area ──
        self.output_area = JTextArea()
        self.output_area.setEditable(False)
        self.output_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.output_area.setBackground(Color(3, 7, 18))
        self.output_area.setForeground(Color(203, 213, 225))
        self.output_area.setCaretColor(Color(148, 163, 184))
        self.output_area.setText(
            "Bug Bounty Agent Bridge\n"
            + "=" * 50 + "\n"
            + "Backend: " + AGENT_API_BASE + "\n\n"
            + "USAGE:\n"
            + "  1. Right-click any request → 'Send to Bug Bounty Agent'\n"
            + "  2. Or enter URL manually above and click Scan\n"
            + "  3. Check 'Check Connection' to verify backend is running\n\n"
            + "SUPPORTED CHECKS:\n"
            + "  sqli, xss, ssrf, open_redirect, path_traversal, crlf, cmdi, ssti, idor\n\n"
        )
        scroll = JScrollPane(self.output_area)

        # Status bar at bottom
        self.status_bar = JLabel("  Ready — right-click a request to scan")
        self.status_bar.setForeground(Color(71, 85, 105))
        self.status_bar.setFont(Font("Monospaced", Font.PLAIN, 10))
        self.status_bar.setBorder(EmptyBorder(3, 8, 3, 8))

        south_panel = JPanel(BorderLayout())
        south_panel.setBackground(Color(10, 15, 25))
        south_panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color(30, 41, 59)))
        south_panel.add(self.status_bar, BorderLayout.CENTER)

        main_split = JPanel(BorderLayout())
        main_split.add(scroll, BorderLayout.CENTER)
        main_split.add(south_panel, BorderLayout.SOUTH)

        # Restructure: top_bar + input_panel (NORTH), output (CENTER)
        wrapper = JPanel(BorderLayout())
        wrapper.add(top_bar, BorderLayout.NORTH)

        content = JPanel(BorderLayout())
        content.add(input_panel, BorderLayout.NORTH)
        content.add(main_split, BorderLayout.CENTER)
        wrapper.add(content, BorderLayout.CENTER)

        self.panel.removeAll()
        self.panel.add(wrapper, BorderLayout.CENTER)

    def _check_connection(self):
        self.status_label.setText("  ⬤ Checking...")
        self.status_label.setForeground(Color(251, 191, 36))
        def check():
            status, resp = http_get(STATUS_ENDPOINT)
            if status == 200:
                SwingUtilities.invokeLater(lambda: (
                    self.status_label.setText("  ⬤ Connected to Backend"),
                    self.status_label.setForeground(Color(34, 197, 94)),
                    self.output_area.append("[✓] Backend connected: " + AGENT_API_BASE + "\n"),
                ))
            else:
                SwingUtilities.invokeLater(lambda: (
                    self.status_label.setText("  ⬤ Cannot reach backend"),
                    self.status_label.setForeground(Color(239, 68, 68)),
                    self.output_area.append("[✗] Cannot reach: " + AGENT_API_BASE + " — is the backend running?\n"),
                ))
        Thread(check).start()

    def _run_manual_scan(self):
        url = self.url_field.getText().strip()
        vuln_type = str(self.vuln_combo.getSelectedItem())
        if not url:
            self.status_bar.setText("  ⚠ Please enter a URL first")
            return
        runner = ScanRunner(url, vuln_type, self.output_area, self.status_bar)
        Thread(runner).start()

    def run_scan_for_url(self, url, vuln_type="all"):
        """Called by context menu to scan a specific URL."""
        runner = ScanRunner(url, vuln_type, self.output_area, self.status_bar)
        Thread(runner).start()


# ── Context Menu ──────────────────────────────────────────────────────────────
class AgentContextMenu(IContextMenuFactory):
    def __init__(self, callbacks, results_tab):
        self.callbacks = callbacks
        self.results_tab = results_tab

    def createMenuItems(self, invocation):
        from javax.swing import JMenuItem, JMenu
        messages = invocation.getSelectedMessages()
        if not messages:
            return None

        menu = JMenu("🤖 Bug Bounty Agent")

        for label, vuln_type in [
            ("🔍 Scan All Vulnerabilities", "all"),
            ("💉 SQL Injection", "sqli"),
            ("🌐 XSS Reflection", "xss"),
            ("🔄 SSRF", "ssrf"),
            ("📂 Path Traversal", "path_traversal"),
            ("⚡ Command Injection", "cmdi"),
            ("🎭 SSTI", "ssti"),
            ("🔑 IDOR", "idor"),
            ("↪ Open Redirect", "open_redirect"),
        ]:
            item = JMenuItem(label)
            vt = vuln_type  # capture for lambda
            msg = messages[0]

            def make_action(vtype, message):
                def action(e):
                    try:
                        req = message.getRequest()
                        analyzed = self.callbacks.analyzeRequest(message)
                        full_url = str(analyzed.getUrl())
                        self.results_tab.run_scan_for_url(full_url, vtype)
                        # Switch to Agent tab
                        self.callbacks.printOutput(
                            "[AgentBridge] Scanning: " + full_url + " [" + vtype + "]"
                        )
                    except Exception as ex:
                        self.callbacks.printError("AgentBridge error: " + str(ex))
                return action

            item.addActionListener(make_action(vt, msg))
            menu.add(item)

        from java.util import ArrayList
        result = ArrayList()
        result.add(menu)
        return result


# ── Main Extension Entry Point ────────────────────────────────────────────────
class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.printOutput("[AgentBridge] Loading " + EXTENSION_NAME + " v" + VERSION)
        callbacks.printOutput("[AgentBridge] Backend: " + AGENT_API_BASE)

        # Create results tab
        self._results_tab = AgentResultsTab(callbacks)

        # Register UI tab
        callbacks.addSuiteTab(self._results_tab)

        # Register context menu
        callbacks.registerContextMenuFactory(
            AgentContextMenu(callbacks, self._results_tab)
        )

        callbacks.printOutput("[AgentBridge] Extension loaded successfully!")
        callbacks.printOutput("[AgentBridge] Right-click any request to use.")
