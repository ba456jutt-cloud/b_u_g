"""
CVEResearchAgent — Elite Threat Intelligence & CVE Research Analyst

Enhanced with:
 • CISA Known Exploited Vulnerabilities (KEV) catalog lookup
 • EPSS (Exploit Prediction Scoring System) score fetching
 • SHA-256 deterministic finding keys (fixed from hash())
"""
import json
import hashlib
import logging
import time
import re
from typing import Optional
from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

# ── CISA KEV + EPSS cache (in-memory, refreshed every 6 hours) ──────────────
_KEV_CACHE: dict = {}
_KEV_CACHE_TS: float = 0.0
_KEV_CACHE_TTL: float = 6 * 3600  # 6 hours

_EPSS_CACHE: dict = {}  # cve_id -> {"score": float, "percentile": float}


def _fetch_cisa_kev() -> dict:
    """Fetch the CISA Known Exploited Vulnerabilities catalog (JSON feed).
    Returns a dict keyed by CVE ID for O(1) lookups.
    """
    global _KEV_CACHE, _KEV_CACHE_TS
    now = time.time()
    if _KEV_CACHE and (now - _KEV_CACHE_TS) < _KEV_CACHE_TTL:
        return _KEV_CACHE

    try:
        import urllib.request
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        kev_map = {}
        for entry in data.get("vulnerabilities", []):
            cve_id = entry.get("cveID", "")
            if cve_id:
                kev_map[cve_id.upper()] = {
                    "vendorProject": entry.get("vendorProject", ""),
                    "product": entry.get("product", ""),
                    "vulnerabilityName": entry.get("vulnerabilityName", ""),
                    "dateAdded": entry.get("dateAdded", ""),
                    "dueDate": entry.get("dueDate", ""),
                    "requiredAction": entry.get("requiredAction", ""),
                }
        _KEV_CACHE = kev_map
        _KEV_CACHE_TS = now
        logger.info(f"[KEV] Loaded {len(kev_map)} CISA KEV entries.")
        return kev_map
    except Exception as e:
        logger.warning(f"[KEV] Failed to fetch CISA KEV catalog: {e}")
        return _KEV_CACHE or {}


def _fetch_epss_scores(cve_ids: list) -> dict:
    """Fetch EPSS scores for a list of CVE IDs from the FIRST-EPSS API."""
    if not cve_ids:
        return {}

    results = {}
    # Check cache first
    uncached = [c for c in cve_ids if c.upper() not in _EPSS_CACHE]
    cached_hits = {c.upper(): _EPSS_CACHE[c.upper()] for c in cve_ids if c.upper() in _EPSS_CACHE}
    results.update(cached_hits)

    if not uncached:
        return results

    try:
        import urllib.request, urllib.parse
        cve_param = ",".join(uncached)
        url = f"https://api.first.org/data/1.0/epss?cve={urllib.parse.quote(cve_param)}&envelope=true"
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        for item in data.get("data", []):
            cve_id = item.get("cve", "").upper()
            score_data = {
                "score": float(item.get("epss", 0)),
                "percentile": float(item.get("percentile", 0)),
            }
            _EPSS_CACHE[cve_id] = score_data
            results[cve_id] = score_data
    except Exception as e:
        logger.warning(f"[EPSS] Failed to fetch EPSS scores: {e}")

    return results


def _enrich_cve_output(raw_output: str) -> str:
    """Extract CVE IDs from agent output and append CISA KEV + EPSS enrichment."""
    if not raw_output:
        return raw_output

    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    found_cves = list(set(m.upper() for m in cve_pattern.findall(raw_output)))
    if not found_cves:
        return raw_output

    # Fetch intelligence
    kev_catalog = _fetch_cisa_kev()
    epss_scores = _fetch_epss_scores(found_cves)

    enrichment_lines = [
        "\n\n═══════════════════════════════════════════════════════════",
        "🔴 THREAT INTELLIGENCE ENRICHMENT (CISA KEV + EPSS)",
        "═══════════════════════════════════════════════════════════",
    ]

    kev_hits = 0
    for cve_id in sorted(found_cves):
        kev_info = kev_catalog.get(cve_id)
        epss_info = epss_scores.get(cve_id, {})
        epss_score = epss_info.get("score", None)
        epss_pct = epss_info.get("percentile", None)

        line = f"\n📌 {cve_id}"
        if kev_info:
            kev_hits += 1
            line += f"\n   ⚠️  IN CISA KEV — ACTIVELY EXPLOITED IN THE WILD!"
            line += f"\n   Product: {kev_info.get('vendorProject', '')} {kev_info.get('product', '')}"
            line += f"\n   Added to KEV: {kev_info.get('dateAdded', 'N/A')} | Remediation Due: {kev_info.get('dueDate', 'N/A')}"
            line += f"\n   Required Action: {kev_info.get('requiredAction', 'N/A')}"
        else:
            line += "\n   ✅ Not in CISA KEV (no known active exploitation confirmed)"

        if epss_score is not None:
            risk_label = "🔴 CRITICAL" if epss_score >= 0.7 else "🟠 HIGH" if epss_score >= 0.4 else "🟡 MEDIUM" if epss_score >= 0.1 else "🟢 LOW"
            line += f"\n   EPSS Score: {epss_score:.4f} ({epss_pct*100:.1f}th percentile) — Exploitation Likelihood: {risk_label}"
        else:
            line += "\n   EPSS: N/A"

        enrichment_lines.append(line)

    if kev_hits > 0:
        enrichment_lines.insert(3, f"\n⚠️  {kev_hits} CVE(s) found in CISA KEV — IMMEDIATE PATCHING REQUIRED!\n")

    return raw_output + "\n".join(enrichment_lines)


class CVEResearchAgent(BaseAgent):
    def _build_prompt(self, task: str, task_type: str) -> str:
        tool_descriptions = "\n".join([f"- {t.name}: {t.description}" for t in self.tools.values()])

        prompt = f"""You are an Elite AI Threat Intelligence & CVE Research Analyst.
Your current task is: "{task}"

Your objective is to deeply analyze CVE identifiers, decipher vulnerability root causes, evaluate business impact, map to CWEs, and formulate highly effective mitigation and remediation strategies.

CRITICAL RULES:
1. You MUST NOT provide functional exploits or instructions on how to weaponize the CVE.
2. For `nvd_cve_lookup`: pass `keyword` as the specific software product name & version (e.g. 'WordPress', 'LiteSpeed', 'MariaDB', 'ProFTPD'). NEVER pass the target URL or domain!
3. ONLY report CVEs returned by actual tool outputs. Do NOT invent or hallucinate CVE numbers.
4. Your analysis must be structured, professional, and actionable.
5. After identifying CVE IDs, note: they will be automatically cross-referenced against CISA KEV and EPSS.

THREAT INTELLIGENCE METHODOLOGY:
1. Analyze the core mechanics of the vulnerability.
2. Identify the affected software versions and specific configurations.
3. Determine the Attack Vector, Attack Complexity, and required Privileges.
4. Formulate concrete, step-by-step mitigation advice (e.g., patches, configuration changes, network rules).

Available Tools:
{tool_descriptions}

Respond with a JSON object containing:
- thought: Your deep reasoning about the vulnerability, potential impact, and next steps for gathering data.
- action: The EXACT name of the tool to use, or 'none' if you are ready to provide the final report.
- result: The tool arguments OR your final structured research report.
"""
        return prompt

    def run(self, task: str, max_steps: int = 8, task_id: str = "local-test"):
        final_output = super().run(task, max_steps=max_steps, task_id=task_id)
        if final_output and isinstance(final_output, str) and not final_output.startswith("Error"):
            # Auto-enrich with CISA KEV + EPSS before saving
            enriched_output = _enrich_cve_output(final_output)
            key = f"cve_research_{hashlib.sha256(task.encode()).hexdigest()[:16]}"
            self.memory.save_finding(key, enriched_output, task_id=task_id)
            return enriched_output
        return final_output
