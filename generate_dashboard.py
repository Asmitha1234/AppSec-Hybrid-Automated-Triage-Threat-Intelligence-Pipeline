# generate_dashboard.py
import json
import os
import sys
import webbrowser
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import threading

REPORT_PATH = "reports/ai_verified_report_sample.json" # Updated default fallback target path string
REPORTS_DIR = "reports"
DASHBOARD_FILE = "dashboard.html"
DASHBOARD_PATH = os.path.join(REPORTS_DIR, DASHBOARD_FILE)

# Weights to enable strict sorting by risk criticality
SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

def get_normalized_severity(issue):
    """Safely extracts severity prioritizing AI-verified fields, fallback to local scanner fields."""
    sev = issue.get("real_cvss_severity") or issue.get("severity") or "MEDIUM"
    return str(sev).upper()

def generate_ui():
    if not os.path.exists(REPORT_PATH):
        print(f"[-] Ledger source path {REPORT_PATH} missing. Run pipeline first.")
        return False

    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        findings = json.load(f)

    # 1. Calculate Origin Metrics
    appsec_count = sum(1 for item in findings if item.get("origin") == "appsec")
    iac_count = sum(1 for item in findings if item.get("origin") == "iac")

    # 2. Calculate Severity and Validity Metrics
    total_count = len(findings)
    critical_count = sum(1 for item in findings if get_normalized_severity(item) == "CRITICAL" and item.get("is_true_positive") != False)
    high_count = sum(1 for item in findings if get_normalized_severity(item) == "HIGH" and item.get("is_true_positive") != False)
    medium_count = sum(1 for item in findings if get_normalized_severity(item) == "MEDIUM" and item.get("is_true_positive") != False)
    low_count = sum(1 for item in findings if get_normalized_severity(item) == "LOW" and item.get("is_true_positive") != False)
    fp_count = sum(1 for item in findings if item.get("is_true_positive") == False)
    
    # 3. Sort Findings by Criticality Priority (False Positives pushed to the bottom)
    def get_sort_key(x):
        if x.get("is_true_positive") == False:
            return -1
        return SEVERITY_WEIGHTS.get(get_normalized_severity(x), 0)

    sorted_findings = sorted(findings, key=get_sort_key, reverse=True)

    # Generate Dynamic Table Rows
    table_rows = ""
    for issue in sorted_findings:
        is_fp = issue.get("is_true_positive") == False
        sev = get_normalized_severity(issue)
        
        if is_fp:
            sev_badge = '<span class="badge badge-fp">FALSE POSITIVE</span>'
        else:
            sev_badge = f'<span class="badge badge-{sev.lower()}">{sev}</span>'
            
        origin_label = "Application Security" if issue.get("origin") == "appsec" else "Cloud Infrastructure (IaC)"
        origin_class = "badge-appsec" if issue.get("origin") == "appsec" else "badge-iac"
        
        # Pull threat intelligence identifiers (CVE / CIS / CWE)
        vuln_id = issue.get("cve_id")
        id_badge = f'<span class="cve-tag">{vuln_id}</span>' if vuln_id else ''
        
        # Pull dynamic remediation fix or AI verification patch
        reremediation_text = issue.get("reremediation_patch") or issue.get("remediation_patch") or issue.get("recommended_fix") or "No patch code supplied."
        
        # Escape any raw script brackets inside the code snippet window to prevent browser parsing errors
        suspicious_raw = str(issue.get('suspicious_code', '')).replace('<', '&lt;').replace('>', '&gt;')
        remediation_clean = str(reremediation_text).replace('<', '&lt;').replace('>', '&gt;')

        # Using python's 'or' evaluation bypasses empty strings or missing keys seamlessly
        vulnerability_narrative = issue.get('ai_taint_explanation') or issue.get('explanation') or 'No diagnostic tracking details available.'

        # 🟢 PHASE 2 REMEDIATION LOG TRACKER LOOKUPS
        rem_status = issue.get("remediation_status")
        ver_notes = issue.get("verification_notes")
        
        remediation_html_block = ""
        if rem_status:
            # Assign dynamic color states to the UI cards depending on compilation/audit results
            if rem_status == "REMEDIATED_AND_VERIFIED":
                status_class = "patch-status-success"
                status_label = "🟢 Remediation Verified Safe"
            elif rem_status == "REMEDIATION_FAILED_AI_REJECTION":
                status_class = "patch-status-fail"
                status_label = "❌ Fix Rejected By AI (Rolled Back)"
            elif rem_status == "REMEDIATION_FAILED_SYNTAX_ERROR":
                status_class = "patch-status-warn"
                status_label = "⚠️ Syntax Compilation Failed (Rolled Back)"
            else:
                status_class = "patch-status-pending"
                status_label = "⏳ Remediation Pending"
                
            remediation_html_block = f"""
            <div class="patch-status-card {status_class}">
                <div class="patch-status-header">{status_label}</div>
                <div class="patch-status-notes">"{ver_notes if ver_notes else 'No verification summary log submitted.'}"</div>
            </div>
            """

        table_rows += f"""
        <tr class="{"row-fp" if is_fp else ""}">
            <td>{sev_badge}</td>
            <td><span class="badge {origin_class}">{origin_label}</span></td>
            <td>
                <strong>{issue.get('vulnerability_type')}</strong> {id_badge}
                <div style="margin-top: 5px; font-size: 12px; color: #64748b; line-height: 1.5;">
                    {vulnerability_narrative}
                </div>
                {remediation_html_block}
            </td>
            <td><code>{os.path.basename(str(issue.get('file_name')))}:line {issue.get('line_number')}</code></td>
            <td>
                <div class="snippet-title">Flagged Snippet:</div>
                <pre class="code-box"><code>{suspicious_raw}</code></pre>
                
                <div class="patch-title">Suggested Remediation Patch:</div>
                <pre class="patch-box"><code>{remediation_clean}</code></pre>
            </td>
        </tr>
        """

    # HTML Layout Structural Template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AppSec & IaC Security Ledger Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; margin: 0; padding: 30px; color: #333; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .origin-container {{ display: flex; gap: 20px; margin-bottom: 25px; justify-content: center; }}
        .origin-card {{ background: #fff; border-radius: 8px; padding: 20px; width: 45%; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.05); border-top: 5px solid #4a90e2; }}
        .origin-card.iac {{ border-top-color: #f5a623; }}
        .origin-card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
        .origin-card .count {{ font-size: 32px; font-weight: bold; color: #222; }}
        .summary-strip {{ display: flex; background: #1e293b; color: #fff; padding: 15px; border-radius: 8px; justify-content: space-around; margin-bottom: 30px; font-weight: bold; text-align: center; }}
        .summary-strip div {{ flex: 1; border-right: 1px solid #334155; }}
        .summary-strip div:last-child {{ border-right: none; }}
        .summary-strip span {{ display: block; font-size: 20px; margin-top: 5px; }}
        
        table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #eee; vertical-align: top; }}
        th {{ background: #f8fafc; color: #475569; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
        
        .badge {{ padding: 6px 12px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; display: inline-block; }}
        .badge-critical {{ background: #f87171; color: #7f1d1d; }}
        .badge-high {{ background: #fb923c; color: #7c2d12; }}
        .badge-medium {{ background: #facc15; color: #713f12; }}
        .badge-low {{ background: #94a3b8; color: #1e293b; }}
        .badge-fp {{ background: #e2e8f0; color: #475569; border: 1px dashed #cbd5e1; }}
        .badge-appsec {{ background: #e0f2fe; color: #0369a1; }}
        .badge-iac {{ background: #fef3c7; color: #b45309; }}
        
        .cve-tag {{ background: #6366f1; color: white; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 5px; }}
        .row-fp {{ background-color: #f8fafc; opacity: 0.70; }}
        
        /* Code Box and Remediation Patch Styling */
        .snippet-title, .patch-title {{ font-size: 11px; font-weight: bold; text-transform: uppercase; color: #64748b; margin-bottom: 4px; }}
        .patch-title {{ color: #10b981; margin-top: 10px; }}
        .code-box, .patch-box {{ margin: 0; padding: 10px; border-radius: 6px; font-family: Courier, monospace; font-size: 12px; overflow-x: auto; max-width: 500px; }}
        .code-box {{ background: #f1f5f9; color: #db2777; border-left: 4px solid #cbd5e1; }}
        .patch-box {{ background: #ecfdf5; color: #065f46; border-left: 4px solid #34d399; white-space: pre-wrap; }}
        
        /* 🟢 AUTOMATED REMEDIATION BADGE STYLING CLASSES */
        .patch-status-card {{ margin-top: 12px; padding: 12px; border-radius: 6px; border: 1px solid transparent; font-size: 12px; }}
        .patch-status-header {{ font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; margin-bottom: 4px; }}
        .patch-status-notes {{ font-style: italic; line-height: 1.4; }}
        
        .patch-status-success {{ background: #f0fdf4; border-color: #bbf7d0; color: #166534; }}
        .patch-status-fail {{ background: #fef2f2; border-color: #fca5a5; color: #991b1b; }}
        .patch-status-warn {{ background: #fffbeb; border-color: #fde68a; color: #92400e; }}
        .patch-status-pending {{ background: #f8fafc; border-color: #e2e8f0; color: #475569; }}

        code {{ font-family: Consolas, Monaco, monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>AppSec & IaC Automated Security Registry</h2>
        <p>Phase 2 Hybrid Scanning Diagnostics Summary Ledger</p>
    </div>
    <div class="origin-container">
        <div class="origin-card">
            <h3>Application Security Vulnerabilities</h3>
            <div class="count">{appsec_count}</div>
        </div>
        <div class="origin-card iac">
            <h3>Infrastructure as Code (IaC) Flaws</h3>
            <div class="count">{iac_count}</div>
        </div>
    </div>
    <div class="summary-strip">
        <div>Total Findings <span>{total_count}</span></div>
        <div style="color: #f87171;">Critical <span>{critical_count}</span></div>
        <div style="color: #fb923c;">High <span>{high_count}</span></div>
        <div style="color: #facc15;">Medium <span>{medium_count}</span></div>
        <div style="color: #cbd5e1;">Low <span>{low_count}</span></div>
        <div style="color: #94a3b8;">False Positives <span>{fp_count}</span></div>
    </div>
    <h3>Prioritized Risk Registry</h3>
    <table>
        <thead>
            <tr>
                <th style="width: 10%;">Severity</th>
                <th style="width: 15%;">Origin Domain</th>
                <th style="width: 25%;">Vulnerability Details</th>
                <th style="width: 15%;">Location Context</th>
                <th style="width: 35%;">Code Context & Remediation Patch</th>
            </tr>
        </thead>
        <tbody>
            {table_rows}
        </tbody>
    </table>
</body>
</html>
"""

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(DASHBOARD_PATH, "w", encoding="utf-8") as df:
        df.write(html_content)
    
    with open(os.path.join(REPORTS_DIR, "index.html"), "w", encoding="utf-8") as index_f:
        index_f.write(html_content)
        
    print(f"[SUCCESS] Dashboard interface successfully updated with Remediation Columns.")
    return True

def serve_localhost(port=8085):
    os.chdir(os.path.abspath(REPORTS_DIR))
    
    class CustomHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass 

    try:
        TCPServer.allow_reuse_address = True
        with TCPServer(("", port), CustomHandler) as httpd:
            localhost_url = f"http://localhost:{port}/"
            print(f"[*] Localhost Live Dashboard Server established at: {localhost_url}")
            print("[*] Press Ctrl+C inside the terminal process sequence to spin down.")
            
            threading.Thread(target=lambda: webbrowser.open(localhost_url)).start()
            httpd.serve_forever()
    except Exception as e:
        print(f"[-] Localhost server initialization exception: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        REPORT_PATH = sys.argv[1]
        
    print(f"[*] Compiling HTML dashboard using database target: {REPORT_PATH}")
    generate_ui()