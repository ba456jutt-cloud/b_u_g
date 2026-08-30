#!/usr/bin/env python3
"""
Tool Execution Test Script — using ToolExecutor (correct way)
Sirf check karta hai ke har tool ACTUALLY execute ho raha hai ya nahi.
Test target: scanme.nmap.org (publicly allowed scan target)
Koi agent nahi, koi LLM nahi, koi report nahi — sirf raw tool execution.
"""
import sys, time, json
sys.path.insert(0, '/home/ahmad/Documents/Agent')

# Import via ToolExecutor — same way agents call tools
from tools.registry import ToolRegistry
ToolRegistry._instance = None
from tools.registry import registry  # singleton re-init
from tools.executor import ToolExecutor

# Test target — scanme.nmap.org is officially allowed for testing
TEST_DOMAIN = "scanme.nmap.org"
TEST_URL    = "http://scanme.nmap.org"
TEST_IP     = "45.33.32.156"

results = {}

def run_tool(tool_name, args, description):
    print(f"\n{'='*60}")
    print(f"🔧 {tool_name}")
    print(f"   {description}")
    print(f"   Args: {args}")

    if tool_name not in registry.tools:
        print(f"   ❌ NOT IN REGISTRY")
        results[tool_name] = "NOT REGISTERED"
        return

    start = time.time()
    try:
        raw = ToolExecutor.execute(tool_name, args)
        elapsed = time.time() - start
        data = json.loads(raw)
        status = data.get("status", "?")
        output = str(data.get("output", ""))

        if status == "success" and output and len(output) > 10:
            preview = output[:300].replace("\n", " | ")
            print(f"   ✅ OK ({elapsed:.1f}s) — {preview}")
            results[tool_name] = f"OK ({elapsed:.1f}s)"
        elif status == "error":
            print(f"   ❌ ERROR ({elapsed:.1f}s): {output[:200]}")
            results[tool_name] = f"ERROR: {output[:80]}"
        else:
            print(f"   ⚠️  EMPTY/UNKNOWN ({elapsed:.1f}s): {output[:100]}")
            results[tool_name] = f"EMPTY ({elapsed:.1f}s)"
    except Exception as e:
        elapsed = time.time() - start
        print(f"   ❌ EXCEPTION ({elapsed:.1f}s): {e}")
        results[tool_name] = f"EXCEPTION: {e}"

# ─────────────────────────────────────────────────────────
print("\n" + "█"*60)
print(f"  TOOL TEST — Target: {TEST_DOMAIN}")
print(f"  Total tools in registry: {len(registry.tools)}")
print("█"*60)

# 1. DNS & PASSIVE
print("\n📡 PHASE 1: DNS & PASSIVE RECON")
run_tool("dns_lookup",        {"domain": TEST_DOMAIN, "record_type": "A"},    "dig A record")
run_tool("whois_lookup",      {"domain": TEST_DOMAIN},                         "WHOIS info")
run_tool("dns_recon",         {"domain": TEST_DOMAIN, "mode": "std"},          "DNS records")
run_tool("curl_headers",      {"url": TEST_URL},                                "HTTP headers")

# 2. FINGERPRINT
print("\n🔎 PHASE 2: WEB FINGERPRINTING")
run_tool("whatweb_fingerprint",{"url": TEST_URL, "aggression": "1"},           "Technology stack")
run_tool("waf_detect",         {"url": TEST_URL},                               "WAF detection")
run_tool("fetch_url",          {"url": TEST_URL},                               "Page content")

# 3. PORT SCAN
print("\n🔍 PHASE 3: PORT SCANNING")
run_tool("nmap_scan",  {"target": TEST_IP, "flags": "-T4 --top-ports 20 -sV --open"}, "Top 20 ports")
run_tool("httpx_probe",{"targets": TEST_URL, "options": "fast"},                       "HTTP probe")

# 4. WEB VULN
print("\n🌐 PHASE 4: WEB SCANNING")
run_tool("web_security_audit",{"url": TEST_URL, "check_common_paths": True},  "OWASP headers check")
run_tool("ssl_check",         {"target": TEST_DOMAIN},                         "SSL/TLS check")
run_tool("nikto_scan",        {"url": TEST_URL, "tuning": "123"},              "Nikto scan")

# 5. DIRECTORY
print("\n📁 PHASE 5: DIRECTORY DISCOVERY")
run_tool("gobuster_scan", {"url": TEST_URL, "wordlist_type": "small"},         "gobuster small")
run_tool("ffuf_fuzz",     {"url": f"{TEST_URL}/FUZZ", "wordlist": "small"},   "ffuf small")

# 6. OSINT
print("\n🕵️  PHASE 6: OSINT")
run_tool("theharvester_osint",{"domain": TEST_DOMAIN, "sources": "bing,crtsh"},"theHarvester OSINT")

# 7. CVE
print("\n🐛 PHASE 7: CVE LOOKUP")
run_tool("nvd_cve_lookup",{"keyword": "Apache 2.4", "max_results": 3},        "NVD CVE search")

# ─────────────────────────────────────────────────────────
print("\n\n" + "█"*60)
print("  RESULTS SUMMARY")
print("█"*60)

ok    = [(t,r) for t,r in results.items() if r.startswith("OK")]
fail  = [(t,r) for t,r in results.items() if not r.startswith("OK")]

print(f"\n✅ WORKING ({len(ok)}/{len(results)}):")
for t,r in ok:
    print(f"   ✅ {t:<32} {r}")

print(f"\n❌ ISSUES ({len(fail)}/{len(results)}):")
for t,r in fail:
    print(f"   ❌ {t:<32} {r}")

print(f"\n📊 Registry total: {len(registry.tools)} tools")
print("   " + ", ".join(sorted(registry.tools.keys())))
