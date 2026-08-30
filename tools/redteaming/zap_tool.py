import subprocess
from tools.base import Tool

class ZAPScanTool(Tool):
    name = "zap_scan"
    description = "Runs an OWASP ZAP baseline scan against a target URL. Requires ZAP installed natively."

    def execute(self, target_url: str = None, url: str = None, target: str = None, **kwargs) -> str:
        target_url = target_url or url or target or kwargs.get('target_url') or ""
        if not target_url:
            return "Error: No target URL provided for ZAP scan."
        # We assume ZAP is installed and `zaproxy` is in PATH
        # -cmd: Command line mode
        # -quickurl: Run quick scan
        # -quickout: Save output to a file
        
        output_file = "/tmp/zap_report.xml"
        
        cmd = [
            "zaproxy",
            "-cmd",
            "-quickurl", target_url,
            "-quickout", output_file,
            "-quickprogress"
        ]
        
        try:
            # ZAP scans can take a while. We set a 10-minute timeout.
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            # Read the output file
            try:
                with open(output_file, "r") as f:
                    report = f.read()
                return f"ZAP Scan Completed. Report Summary:\n\n{report[:2000]}...\n(Truncated for length)"
            except FileNotFoundError:
                return f"Scan executed, but report file was not found. Output: {result.stdout}"
                
        except subprocess.TimeoutExpired:
            return "Error: OWASP ZAP scan timed out after 10 minutes."
        except Exception as e:
            return f"Error executing ZAP: {str(e)}"
