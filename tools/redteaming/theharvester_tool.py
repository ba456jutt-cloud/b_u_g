"""
theHarvester — OSINT Email, Subdomain & Host Enumeration Tool
Used in professional bug bounty for passive reconnaissance:
- Email addresses (for phishing attack surface)
- Subdomains (expand attack surface)
- IPs and virtual hosts
Sources: Google, Bing, Certspotter, Crtsh, URLScan, etc.
"""
import subprocess
import json
from tools.base import Tool


class TheHarvesterTool(Tool):
    name = "theharvester_osint"
    description = (
        "Performs OSINT (passive reconnaissance) using theHarvester to find email addresses, "
        "subdomains, IPs, and hosts associated with a target domain. "
        "Uses multiple sources: Google, Bing, CertSpotter, crt.sh, URLScan, DNSDumpster. "
        "Essential first step in bug bounty recon — NO active scanning of the target."
    )
    parameters = {
        "domain": "Target domain to enumerate (e.g. example.gov.pk, target.com)",
        "sources": "Comma-separated sources to use (default: google,bing,certspotter,crtsh,urlscan)"
    }

    def execute(self, domain: str, sources: str = "google,bing,certspotter,crtsh,urlscan", **kwargs) -> str:
        try:
            # Strip protocol if given
            domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

            cmd = [
                "theHarvester",
                "-d", domain,
                "-b", sources,
                "-l", "100",   # Limit results
                "-f", "/tmp/theharvester_output"
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )

            output = result.stdout or result.stderr or "No output"

            # Parse key findings
            lines = output.split("\n")
            emails = [l.strip() for l in lines if "@" in l and domain in l]
            subdomains = [l.strip() for l in lines if l.strip().endswith(f".{domain}") or f".{domain}" in l.strip()]
            ips = [l.strip() for l in lines if l.strip() and l.strip()[0].isdigit() and "." in l.strip()]

            report = [f"=== theHarvester OSINT Report: {domain} ===\n"]
            report.append(f"Sources queried: {sources}")
            report.append(f"\n📧 EMAILS FOUND ({len(emails)}):")
            report.extend(emails[:20] or ["  None found"])
            report.append(f"\n🌐 SUBDOMAINS FOUND ({len(subdomains)}):")
            report.extend(subdomains[:30] or ["  None found"])
            report.append(f"\n🖥️ IPs FOUND ({len(ips)}):")
            report.extend(ips[:20] or ["  None found"])
            report.append(f"\n--- Raw Output (first 2000 chars) ---\n{output[:2000]}")

            return "\n".join(report)

        except subprocess.TimeoutExpired:
            return f"theHarvester timed out after 120 seconds for domain: {domain}"
        except FileNotFoundError:
            return "Error: theHarvester not installed. Install with: sudo apt install theharvester"
        except Exception as e:
            return f"theHarvester error: {type(e).__name__}: {str(e)}"
