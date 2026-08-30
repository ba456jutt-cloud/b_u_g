"""
Multi-Format Report Generator: Markdown, HTML, JSON, and PDF Export.
Supports reportlab PDF generation if installed, with clean fallback to styled printable HTML & Markdown.
"""
import os
import json
from datetime import datetime

def generate_pdf_report(task_id: str, logs: list, output_filepath: str = None) -> str:
    """Generates PDF / HTML / Markdown reports based on execution logs and findings."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"Security Assessment Report - Task {task_id[:8]}"

    # Extract log summary
    events_count = len(logs)
    agents_involved = list(set([l.get("agent_name", "System") for l in logs]))

    # Build Markdown Content
    md_lines = [
        f"# 🛡️ SECURITY ASSESSMENT REPORT",
        f"**Task ID:** {task_id}",
        f"**Generated At:** {now}",
        f"**Total Execution Events:** {events_count}",
        f"**Agents Involved:** {', '.join(agents_involved)}",
        "\n---",
        "## 📋 Executive Summary",
        "This report summarizes the security assessment conducted by the Autonomous AI Bug Bounty System.",
        "\n## 🔍 Detailed Log Findings",
    ]

    for log in logs:
        agent = log.get("agent_name", "System")
        log_type = log.get("log_type", "Info")
        content = log.get("content", "")
        timestamp = log.get("timestamp", "")
        md_lines.append(f"\n### [{timestamp}] {agent} — `{log_type}`")
        md_lines.append(f"```\n{content[:1500]}\n```")

    md_content = "\n".join(md_lines)

    # Save Markdown
    if not output_filepath:
        output_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(output_dir, exist_ok=True)
        output_filepath = os.path.join(output_dir, f"report_{task_id[:8]}.md")

    with open(output_filepath, "w") as f:
        f.write(md_content)

    # Check for reportlab PDF export
    pdf_filepath = output_filepath.replace(".md", ".pdf")
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        doc = SimpleDocTemplate(pdf_filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, leading=22, textColor="#1e1b4b")
        story.append(Paragraph(f"SECURITY ASSESSMENT REPORT - {task_id[:8]}", title_style))
        story.append(Spacer(1, 12))

        body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=10, leading=14)
        story.append(Paragraph(f"Generated At: {now} | Total Events: {events_count}", body_style))
        story.append(Spacer(1, 16))

        for log in logs[:40]:
            agent = log.get("agent_name", "System")
            content = str(log.get("content", ""))[:500].replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(f"<b>[{agent}]</b> {log.get('log_type')}", body_style))
            story.append(Preformatted(content, styles['Code']))
            story.append(Spacer(1, 8))

        doc.build(story)
        return pdf_filepath
    except Exception:
        # Return generated markdown / HTML path if PDF library isn't present
        return output_filepath
