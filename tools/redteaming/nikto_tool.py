import subprocess
from tools.base import Tool

class NiktoTool(Tool):
    name = "nikto_scan"
    description = (
        "Runs Nikto web server vulnerability scanner against a target URL. "
        "Detects: dangerous files, outdated server software, insecure headers, "
        "SSL problems, default credentials exposure, and common web vulnerabilities. "
        "Provides CVE/OSVDB references for found issues."
    )
    parameters = {
        "url": "Target URL (e.g. https://example.com or http://192.168.1.1:8080)",
        "tuning": "Scan tuning numbers (default: '123456789' for all checks). "
                  "1=XSS, 2=File upload, 3=Misconfig, 4=Injection, 5=InfoDisclosure, "
                  "6=Interesting files, 7=SQL, 8=Bypass, 9=Headers"
    }

    def execute(self, url: str = None, target: str = None, tuning: str = "123456789", **kwargs) -> str:
        # Accept 'target' or 'url'
        url = url or target or ""
        if not url:
            return "Error: provide 'url' parameter"
        try:
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url

            # Do NOT use -output /dev/stdout — it causes empty output
            # Capture stdout directly via subprocess
            cmd = [
                "nikto",
                "-h", url,
                "-Tuning", tuning,
                "-nointeractive",
                "-maxtime", "120s",
                "-ask", "no",
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=150
            )

            # Nikto writes to stderr when no -output is given — check both
            output = ""
            if result.stdout and len(result.stdout.strip()) > 20:
                output = result.stdout
            elif result.stderr and len(result.stderr.strip()) > 20:
                output = result.stderr

            if not output.strip():
                return (
                    f"=== Nikto Web Scan: {url} ===\n"
                    f"No output received. Nikto may have been blocked by WAF/firewall.\n"
                    f"returncode={result.returncode}"
                )

            lines = output.split("\n")

            # Key findings: lines with + prefix (nikto findings), OSVDB, CVE refs
            findings = [
                l.strip() for l in lines
                if l.strip().startswith("+") or "OSVDB" in l or "CVE" in l
            ]
            info_lines = [l for l in lines if l.strip().startswith("-")]

            report = [
                f"=== Nikto Web Scan: {url} ===",
                f"Key findings: {len(findings)}",
                "",
            ]
            if findings:
                report.append("--- Findings ---")
                report.extend(findings[:60])
            else:
                report.append("No specific vulnerabilities found.")
                report.append("(Site may have WAF, or be very well configured)")
                report.append("\n--- Scan Info ---")
                report.extend(info_lines[:10])

            return "\n".join(report)

        except subprocess.TimeoutExpired:
            return f"Nikto scan timed out (150s) for: {url}"
        except FileNotFoundError:
            return "Error: nikto not installed. Run: sudo apt install nikto"
        except Exception as e:
            return f"Nikto error: {type(e).__name__}: {str(e)}"
