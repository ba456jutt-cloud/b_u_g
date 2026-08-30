"""
HTML Report Generator for Bug Bounty Copilot.
Generates professional security assessment reports from task execution logs.
"""
from datetime import datetime

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

def generate_html_report(task_id: str, logs: list, findings: list = None) -> str:
    """Generate a styled HTML security report from execution logs."""
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Parse log content for key findings
    recon_data = []
    vulnerabilities = []
    tool_outputs = []
    
    for log in logs:
        content = log.get("content", "")
        log_type = log.get("log_type", "")
        agent = log.get("agent_name", "")
        
        if log_type == "Result" and "Tool [" in content:
            tool_outputs.append({"agent": agent, "content": content})
        elif log_type == "Result" and content:
            recon_data.append({"agent": agent, "content": content})
    
    # Build the HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report - {task_id[:8]}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4c1d95 100%); padding: 40px; text-align: center; border-bottom: 3px solid #6366f1; }}
  .header h1 {{ font-size: 2.5rem; color: #fff; letter-spacing: 2px; }}
  .header p {{ color: #a5b4fc; margin-top: 8px; font-size: 1rem; }}
  .badge {{ display: inline-block; background: #4f46e5; color: #fff; padding: 4px 14px; border-radius: 20px; font-size: 0.75rem; margin-top: 12px; letter-spacing: 1px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 20px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 24px 0; }}
  .meta-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; text-align: center; }}
  .meta-card .label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }}
  .meta-card .value {{ font-size: 1.3rem; font-weight: bold; color: #f1f5f9; margin-top: 4px; }}
  .section {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; margin: 20px 0; overflow: hidden; }}
  .section-header {{ background: #0f172a; padding: 16px 24px; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 10px; }}
  .section-header h2 {{ font-size: 1.1rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }}
  .section-body {{ padding: 24px; }}
  .log-entry {{ background: #0f172a; border-left: 3px solid #334155; border-radius: 4px; padding: 12px 16px; margin: 10px 0; font-family: 'Courier New', monospace; font-size: 0.85rem; }}
  .log-entry.thought {{ border-color: #3b82f6; }}
  .log-entry.action {{ border-color: #f59e0b; }}
  .log-entry.result {{ border-color: #10b981; }}
  .log-entry.error {{ border-color: #ef4444; }}
  .log-entry .meta {{ font-size: 0.7rem; color: #64748b; margin-bottom: 6px; }}
  .log-entry .content {{ color: #cbd5e1; white-space: pre-wrap; word-break: break-word; }}
  .agent-tag {{ display: inline-block; background: #1d4ed8; color: #93c5fd; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; margin-right: 8px; }}
  .footer {{ text-align: center; color: #475569; font-size: 0.8rem; padding: 30px; border-top: 1px solid #1e293b; }}
  .icon {{ font-size: 1.2rem; }}
  @media print {{
    body {{ background: white; color: black; }}
    .section {{ border: 1px solid #ccc; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ SECURITY ASSESSMENT REPORT</h1>
  <p>Bug Bounty Copilot - AI-Powered Security Analysis</p>
  <span class="badge">CONFIDENTIAL</span>
</div>

<div class="container">

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Task ID</div>
      <div class="value" style="font-size:0.9rem;">{task_id[:16]}...</div>
    </div>
    <div class="meta-card">
      <div class="label">Generated</div>
      <div class="value" style="font-size:0.9rem;">{now}</div>
    </div>
    <div class="meta-card">
      <div class="label">Total Log Entries</div>
      <div class="value">{len(logs)}</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="icon">📋</span>
      <h2>Executive Summary</h2>
    </div>
    <div class="section-body">
      <p style="color:#94a3b8;">
        This report contains the findings from an automated security assessment performed by the Bug Bounty Copilot AI system.
        The analysis was conducted using a multi-agent pipeline including reconnaissance, vulnerability analysis, 
        and reporting agents. Total of <strong style="color:#f1f5f9;">{len(logs)} events</strong> were logged during execution.
      </p>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="icon">🔍</span>
      <h2>Execution Timeline</h2>
    </div>
    <div class="section-body">
"""

    # Add log entries
    for log in logs:
        log_type = log.get("log_type", "System").lower()
        agent = log.get("agent_name", "System")
        content = log.get("content", "")
        timestamp = log.get("timestamp", "")
        
        css_class = log_type if log_type in ["thought", "action", "result", "error"] else ""
        
        html += f"""
      <div class="log-entry {css_class}">
        <div class="meta">
          <span class="agent-tag">{agent}</span>
          <span>{timestamp}</span>
          <span style="margin-left:8px; color:#6366f1;">[{log_type.upper()}]</span>
        </div>
        <div class="content">{content[:1000]}</div>
      </div>"""

    html += """
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="icon">⚠️</span>
      <h2>Remediation Recommendations</h2>
    </div>
    <div class="section-body">
      <ul style="color:#94a3b8; padding-left: 20px; line-height: 2;">
        <li>Review all open ports and disable unnecessary services</li>
        <li>Ensure all software components are updated to latest stable versions</li>
        <li>Implement proper HTTP security headers (CSP, HSTS, X-Frame-Options)</li>
        <li>Enable TLS 1.2+ only, disable SSLv3, TLSv1.0, TLSv1.1</li>
        <li>Review and restrict directory listing on web servers</li>
        <li>Implement Web Application Firewall (WAF) rules</li>
        <li>Set up intrusion detection and monitoring alerts</li>
        <li>Conduct regular penetration testing and vulnerability assessments</li>
      </ul>
    </div>
  </div>

</div>

<div class="footer">
  <p>Generated by Bug Bounty Copilot AI Security Platform</p>
  <p style="margin-top: 4px;">This report is confidential and intended for authorized personnel only.</p>
</div>

</body>
</html>"""

    return html
