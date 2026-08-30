# Bug Bounty Agent — Burp Suite Extension

## Overview

This extension connects **Burp Suite Community/Pro** directly to your Bug Bounty
Copilot backend. From any request in Burp, you can right-click and instantly
run PoC vulnerability verification tests.

---

## Prerequisites

### 1. Download Jython (Required for Python extensions in Burp)

Burp's Python extension support runs on **Jython 2.7** (Python on the JVM).

```
Download: https://www.jython.org/download
File: jython-standalone-2.7.3.jar
```

### 2. Configure Jython in Burp

1. Open Burp Suite
2. Go to: **Extender** → **Options** (or **Extensions** → **Extension Settings**)
3. Under **Python Environment** → set path to: `jython-standalone-2.7.3.jar`
4. Click OK

---

## Installation

1. Open Burp Suite
2. Go to **Extender** → **Extensions** (or **Extensions** tab)
3. Click **"Add"**
4. Set:
   - **Extension Type:** `Python`
   - **Extension File:** `/path/to/Agent/burp_extension/agent_bridge.py`
5. Click **Next** → Extension loads
6. A new **"🤖 Agent"** tab appears in Burp

---

## Usage

### Right-Click Menu (Automatic from any Burp tab)

1. In **Proxy**, **Repeater**, **Target** — right-click any request
2. Select **🤖 Bug Bounty Agent** →
   - 🔍 Scan All Vulnerabilities
   - 💉 SQL Injection
   - 🌐 XSS Reflection
   - 🔄 SSRF
   - 📂 Path Traversal
   - ⚡ Command Injection
   - 🎭 SSTI
   - 🔑 IDOR
   - ↪ Open Redirect
3. Results appear in the **🤖 Agent** tab in real-time

### Manual Scan (Agent Tab)

1. Click the **🤖 Agent** tab in Burp
2. Enter URL in the text field
3. Select vulnerability type from dropdown
4. Click **▶ Scan**

### Check Connection

Click **"Check Connection"** in the Agent tab to verify the backend is reachable.

---

## Backend Endpoints Used

| Endpoint | Purpose |
|---|---|
| `GET http://localhost:8000/burp/status` | Connection health check |
| `POST http://localhost:8000/burp/scan` | PoC scan via extension |
| `POST http://localhost:8000/scan/poc` | Direct PoC verification |

---

## Testing with Juice Shop

```bash
# Start backend (from Agent/ directory):
uvicorn api.main:app --reload --port 8000

# Start Juice Shop (from ~/juice-shop):
node app

# In Burp, proxy Juice Shop traffic through 127.0.0.1:8080
# Navigate to http://localhost:3001 in browser through Burp proxy
# Right-click login/search requests → Send to Bug Bounty Agent → SQLi
```

---

## Troubleshooting

**Extension won't load:**
- Make sure Jython JAR is set in Burp's Python Environment settings
- Check Burp's Extension output tab for errors

**"Cannot reach backend":**
- Ensure backend is running: `uvicorn api.main:app --port 8000`
- Check firewall isn't blocking localhost connections

**Scan takes too long:**
- Reduce `max_payloads` in the extension config (default: 5)
- Use specific vuln type instead of "all"
