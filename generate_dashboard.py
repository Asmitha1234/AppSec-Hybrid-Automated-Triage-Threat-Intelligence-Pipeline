import os
import json
import http.server
import socketserver
import webbrowser

PORT = 8085
REPORT_PATH = "reports/ai_verified_report_pygoat_2.0.json" # Match ledger name shared by tracker paths

def html_escape(text):
    if not isinstance(text, str):
        text = str(text)
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')

def generate_html():
    if not os.path.exists(REPORT_PATH):
        return """
        <html><body style='font-family:sans-serif; text-align:center; padding-top:100px; color:#e53e3e;'>
        <h2>[-] Error: Data Triage Ledger File Not Found</h2>
        <p>Please execute 'python run_pipeline.py' to generate the security baseline visualization tables.</p>
        </body></html>
        """
    
    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as e:
        return f"<html><body><h2>[-] Error loading JSON: {html_escape(str(e))}</h2></body></html>"

    def is_true(val, default=True):
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes")

    total_alerts = len(findings)
    critical_count = sum(1 for x in findings if isinstance(x, dict) and str(x.get("real_cvss_severity", "")).upper() == "CRITICAL" and is_true(x.get("is_true_positive", True)))
    high_count = sum(1 for x in findings if isinstance(x, dict) and str(x.get("real_cvss_severity", "")).upper() == "HIGH" and is_true(x.get("is_true_positive", True)))
    medium_count = sum(1 for x in findings if isinstance(x, dict) and str(x.get("real_cvss_severity", "")).upper() == "MEDIUM" and is_true(x.get("is_true_positive", True)))
    low_count = sum(1 for x in findings if isinstance(x, dict) and str(x.get("real_cvss_severity", "")).upper() == "LOW" and is_true(x.get("is_true_positive", True)))
    fp_count = sum(1 for x in findings if isinstance(x, dict) and not is_true(x.get("is_true_positive", True)))

    table_rows = ""
    for idx, item in enumerate(findings, 1):
        if not isinstance(item, dict):
            continue
        is_tp = is_true(item.get("is_true_positive", True))
        cve_tag = item.get("cve_id", "N/A")
        
        if not is_tp:
            cve_style = "background-color: #edf2f7; color: #718096; border: 1px solid #cbd5e0;"
            severity = "FALSE POSITIVE"
            sev_class = "badge-fp"
            score_string = "0.0"
        elif "MOCK" in str(cve_tag).upper() or cve_tag == "N/A":
            cve_style = "background-color: #ebf8ff; color: #2b6cb0; border: 1px solid #bee3f8; font-style: italic;"
            severity = str(item.get("real_cvss_severity", "Medium")).upper()
            sev_class = f"badge-{severity.lower()}"
            score_string = str(item.get("real_cvss_score", 0.0))
        else:
            cve_style = "background-color: #feebc8; color: #c05621; border: 1px solid #fbd38d; font-weight: bold;"
            severity = str(item.get("real_cvss_severity", "Medium")).upper()
            sev_class = f"badge-{severity.lower()}"
            score_string = str(item.get("real_cvss_score", 0.0))
            
        file_short = os.path.basename(item.get("file_name", "unknown")) + f" (Line {item.get('line_number', 0)})"
        explanation = item.get("ai_taint_explanation", "No explanation compiled.")
        patch = item.get("remediation_patch", "# No patch available.")

        table_rows += f"""
        <tr class="{'row-fp' if not is_tp else ''}">
            <td>{idx}</td>
            <td>
                <span class="cve-badge" style="{cve_style}">{html_escape(cve_tag)}</span>
                <strong style="display: block; margin-top: 8px; font-size: 14px; color: #1a202c;">
                    {html_escape(item.get("vulnerability_type", "Unknown Indicator"))}
                </strong>
                {'' if is_tp else '<span class="dismissed-tag">[DISMISSED]</span>'}
            </td>
            <td><span class="badge {sev_class}">{severity} ({score_string})</span></td>
            <td><span class="file-path" title="{html_escape(item.get('file_name', ''))}">{file_short}</span></td>
            <td>
                <div class="desc-text"><strong>Risk Analysis:</strong> {html_escape(explanation)}</div>
                {"" if not is_tp else f'''
                <div class="patch-header">Suggested Remediation Patch:</div>
                <pre class="code-block"><code>{html_escape(patch)}</code></pre>
                '''}
            </td>
        </tr>
        """

    html_template = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AppSec Vulnerability Assessment Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f7fafc; color: #2d3748; margin: 0; padding: 20px; }}
            .container {{ max-width: 1400px; margin: 0 auto; }}
            .header {{ background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header h1 {{ margin: 0; font-size: 28px; font-weight: 600; letter-spacing: -0.5px; }}
            .header p {{ margin: 8px 0 0 0; color: #a0aec0; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
            .metrics-bar {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px; }}
            .metric-card {{ background-color: white; border: 1px solid #e2e8f0; padding: 20px; text-align: center; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }}
            .metric-card .num {{ font-size: 32px; font-weight: bold; color: #2b6cb0; }}
            .metric-card .num.crit {{ color: #e53e3e; }}
            .metric-card .num.high {{ color: #dd6b20; }}
            .metric-card .num.med {{ color: #b7791f; }}
            .metric-card .num.fp {{ color: #718096; }}
            .metric-card .lbl {{ font-size: 11px; text-transform: uppercase; color: #718096; font-weight: 600; margin-top: 5px; }}
            table {{ width: 100%; border-collapse: separate; border-spacing: 0; background-color: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.02); border: 1px solid #e2e8f0; overflow: hidden; }}
            th {{ background-color: #edf2f7; padding: 15px; font-weight: 600; text-align: left; border-bottom: 2px solid #cbd5e0; font-size: 13px; color: #4a5568; }}
            td {{ padding: 15px; border-bottom: 1px solid #e2e8f0; vertical-align: top; font-size: 14px; }}
            tr:last-child td {{ border-bottom: none; }}
            tr:hover {{ background-color: #f8fafc; }}
            .row-fp {{ background-color: #fcfcfc; opacity: 0.85; }}
            .cve-badge {{ display: inline-block; font-family: 'Consolas', monospace; font-size: 11px; padding: 3px 7px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
            .dismissed-tag {{ display: inline-block; margin-top: 4px; font-size: 10px; color: #e53e3e; font-weight: bold; letter-spacing: 0.5px; }}
            .badge {{ display: inline-block; padding: 4px 8px; font-size: 11px; font-weight: bold; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
            .badge-critical {{ background-color: #fff5f5; color: #c53030; border: 1px solid #feb2b2; }}
            .badge-high {{ background-color: #fffaf0; color: #dd6b20; border: 1px solid #fbd38d; }}
            .badge-medium {{ background-color: #fffbeb; color: #b7791f; border: 1px solid #fef3c7; }}
            .badge-low {{ background-color: #f7fafc; color: #4a5568; border: 1px solid #e2e8f0; }}
            .badge-fp {{ background-color: #edf2f7; color: #4a5568; border: 1px solid #cbd5e0; }}
            .code-block {{ font-family: 'Consolas', 'Courier New', monospace; background-color: #1a202c; color: #f7fafc; padding: 12px; border-radius: 6px; white-space: pre-wrap; word-break: break-all; font-size: 12.5px; margin: 8px 0 0 0; line-height: 1.5; box-shadow: inset 0 2px 4px rgba(0,0,0,0.1); }}
            .file-path {{ font-family: 'Consolas', monospace; color: #4a5568; background-color: #edf2f7; padding: 3px 6px; border-radius: 4px; font-size: 12px; font-weight: 500; }}
            .desc-text {{ line-height: 1.6; color: #4a5568; font-size: 13.5px; }}
            .patch-header {{ font-size: 11px; font-weight: bold; text-transform: uppercase; color: #319795; margin-top: 12px; letter-spacing: 0.5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>AppSec Vulnerability Assessment Dashboard</h1>
                <p>Phase 2 Hybrid Automated Triage & Threat Intelligence Registry Logs</p>
            </div>
            <div class="metrics-bar">
                <div class="metric-card"><div class="num">{total_alerts}</div><div class="lbl">Total Indicators</div></div>
                <div class="metric-card"><div class="num crit">{critical_count}</div><div class="lbl">Critical Risks</div></div>
                <div class="metric-card"><div class="num high">{high_count}</div><div class="lbl">High Risks</div></div>
                <div class="metric-card"><div class="num med">{medium_count + low_count}</div><div class="lbl">Medium / Low</div></div>
                <div class="metric-card"><div class="num fp">{fp_count}</div><div class="lbl">False Positives</div></div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 3%;">#</th>
                        <th style="width: 22%;">Vulnerability & Threat Identifier</th>
                        <th style="width: 15%;">CVSS Severity</th>
                        <th style="width: 20%;">Target Workspace File Location</th>
                        <th style="width: 40%;">Remediation Matrix Triage Analysis & Fix Script</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return html_template

class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            response_content = generate_html()
            self.wfile.write(response_content.encode("utf-8"))
        else:
            super().do_GET()

def run_dashboard_server():
    os.makedirs("reports", exist_ok=True)
    handler = DashboardRequestHandler
    socketserver.TCPServer.allow_reuse_address = True
    
    print(f"[*] Initializing local presentation layer socket server on port {PORT}...")
    try:
        with socketserver.TCPServer(("", PORT), handler) as httpd:
            dashboard_url = f"http://localhost:{PORT}"
            print(f"[SUCCESS] Dashboard actively hosted at location: {dashboard_url}")
            print("[*] Press CTRL + C inside this console window to terminate the server.")
            webbrowser.open(dashboard_url)
            httpd.serve_forever()
    except Exception as e:
        print(f"[-] Execution Server Halt Encountered: {str(e)}")

if __name__ == "__main__":
    run_dashboard_server()