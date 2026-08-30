"""
NVD CVE Lookup Tool
Searches the NIST National Vulnerability Database (NVD) API v2.0 for real CVE data
based on a product name and version. Returns CVE IDs, CVSS scores, and descriptions.
"""
import requests
import json
from tools.base import Tool


class NVDCVELookupTool(Tool):
    name = "nvd_cve_lookup"
    description = (
        "Searches the NIST National Vulnerability Database (NVD) for real CVEs "
        "based on a product or software name and version. Returns CVE IDs, CVSS v3 "
        "severity scores, and descriptions. Use after identifying software versions "
        "from port scans or HTTP headers."
    )
    parameters = {
        "keyword": "Product name or software keyword to search (e.g. 'OpenSSH 6.6', 'Apache 2.4.7', 'Werkzeug')",
        "max_results": "Maximum number of CVEs to return (default: 10, max: 20)"
    }

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def execute(self, keyword: str, max_results: int = 10, **kwargs) -> str:
        try:
            max_results = min(int(max_results), 20)

            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results,
                "startIndex": 0,
            }

            resp = requests.get(
                self.NVD_API_URL,
                params=params,
                timeout=15,
                headers={"Accept": "application/json"}
            )

            if resp.status_code == 403:
                return (
                    "NVD API rate limit hit. The public NVD API allows 5 requests/30s "
                    "without an API key. Please wait 30 seconds and retry."
                )
            if resp.status_code != 200:
                return f"NVD API error: HTTP {resp.status_code} - {resp.text[:200]}"

            data = resp.json()
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                return f"No CVEs found in NVD for keyword: '{keyword}'"

            lines = [
                f"=== NVD CVE Results for: '{keyword}' ===",
                f"Total results in database: {total_results}  |  Showing: {len(vulnerabilities)}\n"
            ]

            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                published = cve_data.get("published", "N/A")[:10]

                # Description (English)
                descriptions = cve_data.get("descriptions", [])
                desc = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    "No description available."
                )
                desc_short = desc[:300] + ("..." if len(desc) > 300 else "")

                # CVSS Score
                metrics = cve_data.get("metrics", {})
                cvss_score = "N/A"
                severity = "N/A"
                cvss_vector = "N/A"

                # Try CVSS v3.1 first, then v3.0, then v2
                for key in ["cvssMetricV31", "cvssMetricV30"]:
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_score = m.get("baseScore", "N/A")
                        severity = m.get("baseSeverity", "N/A")
                        cvss_vector = m.get("vectorString", "N/A")
                        break
                else:
                    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                        m = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss_score = m.get("baseScore", "N/A")
                        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")
                        cvss_vector = m.get("vectorString", "N/A")

                # Severity emoji
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                    str(severity).upper(), "⚪"
                )

                lines.append(f"{emoji} {cve_id}  |  CVSS: {cvss_score} ({severity})  |  Published: {published}")
                lines.append(f"   Vector: {cvss_vector}")
                lines.append(f"   Description: {desc_short}")
                lines.append("")

            return "\n".join(lines)

        except requests.exceptions.Timeout:
            return "NVD API request timed out. Try again in a moment."
        except Exception as e:
            return f"NVD CVE lookup error: {type(e).__name__}: {str(e)}"
