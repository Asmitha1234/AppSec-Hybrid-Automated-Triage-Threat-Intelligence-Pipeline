import os
import json
from fpdf import FPDF

class ExecutiveAppSecReport(FPDF):
    def header(self):
        # Top banner styling
        self.set_fill_color(26, 32, 44)  # Dark slate header bar
        self.rect(0, 0, 210, 35, 'F')
        
        self.set_xy(15, 10)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, "Application Security Assessment Report", ln=True)
        
        self.set_x(15)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(160, 174, 192)
        self.cell(0, 5, "PHASE 2 AUTOMATED TRIAGE & REMEDIATION LOG", ln=True)
        self.ln(15)

    def footer(self):
        # Bottom page layout boundary counters
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(113, 128, 150)
        self.cell(100, 10, "Internal Confidential - AppSec Pipeline Audit Report", 0, 0, "L")
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "R")

def clean_text(text):
    """Encodes text characters cleanly for safe standard PDF rendering matrices."""
    if not isinstance(text, str):
        text = str(text)
    # Map special unicode quotes to basic string characters
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report():
    input_path = "reports/ai_verified_report2.json"
    output_pdf = "reports/Executive_Security_Analysis_Report.pdf"
    
    if not os.path.exists(input_path):
        print(f"[-] Data layer missing: {input_path}. Run 'python scanner/ai_triage.py' first.")
        return

    with open(input_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    # Dynamic KPI math transformations
    total = len(findings)
    critical = sum(1 for x in findings if str(x.get("real_cvss_severity", "")).upper() == "CRITICAL")
    high = sum(1 for x in findings if str(x.get("real_cvss_severity", "")).upper() == "HIGH")
    medium = sum(1 for x in findings if str(x.get("real_cvss_severity", "")).upper() == "MEDIUM")
    low = total - (critical + high + medium)

    # Instantiate PDF engine
    pdf = ExecutiveAppSecReport(orientation="P", unit="mm", format="A4")
    pdf.set_margins(15, 20, 15)
    pdf.add_page()
    
    # --- METRICS BLOCK SUMMARY BAR ---
    pdf.set_fill_color(247, 250, 252)
    pdf.set_draw_color(226, 232, 240)
    pdf.rect(15, 40, 180, 18, 'DF')
    
    pdf.set_xy(15, 42)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(43, 108, 176)
    
    # Calculate spacing evenly
    pdf.cell(36, 6, f" {total}", align="C")
    pdf.cell(36, 6, f"{critical}", align="C")
    pdf.cell(36, 6, f"{high}", align="C")
    pdf.cell(36, 6, f"{medium}", align="C")
    pdf.cell(36, 6, f"{low}", align="C", ln=True)
    
    pdf.set_x(15)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(113, 128, 150)
    pdf.cell(36, 4, "TOTAL ALERTS", align="C")
    pdf.cell(36, 4, "CRITICAL", align="C")
    pdf.cell(36, 4, "HIGH RISK", align="C")
    pdf.cell(36, 4, "MEDIUM RISK", align="C")
    pdf.cell(36, 4, "LOW / INFO", align="C", ln=True)
    pdf.ln(12)

    # --- RENDER FINDINGS CARDS ---
    for idx, item in enumerate(findings, 1):
        vuln_type = item.get("vulnerability_type", "Vulnerability Indicator")
        severity = str(item.get("real_cvss_severity", "MEDIUM")).upper()
        score = item.get("real_cvss_score", 0.0)
        file_name = os.path.basename(item.get("file_name", "unknown"))
        line_no = item.get("line_number", 0)
        explanation = item.get("ai_taint_explanation", "No manual validation metadata compiled.")
        patch = item.get("remediation_patch", "# Fix script unavailable.")

        # Check for page space dynamically to prevent awkward single-line page splits
        if pdf.get_y() > 220:
            pdf.add_page()
            pdf.ln(10)

        # Header bar for the card box
        pdf.set_fill_color(237, 242, 247)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(26, 32, 44)
        pdf.cell(0, 8, clean_text(f" Finding #{idx}: {vuln_type}  |  [{severity} - Score: {score}]"), border=1, ln=True, fill=True)
        
        # Meta Row Info
        pdf.set_fill_color(255, 255, 255)
        pdf.set_font("Courier", "B", 9)
        pdf.set_text_color(44, 82, 130)
        pdf.cell(0, 6, clean_text(f" Target File: {file_name} (Line row: {line_no})"), border="LR", ln=True, fill=True)
        
        # Risk Explanation Header
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(43, 108, 176)
        pdf.cell(0, 4, " RISK ANALYSIS SUMMARY:", border="LR", ln=True, fill=True)
        
        # Risk Explanation Content
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(74, 85, 104)
        pdf.multi_cell(0, 5, clean_text(f" {explanation}"), border="LR", fill=True)
        
        # Patch Header
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(49, 151, 149)
        pdf.cell(0, 4, " SUGGESTED REMEDIATION REPLACEMENT PATCH:", border="LR", ln=True, fill=True)
        
        # --- FIXED BLOCK START: Code Patch Block alignment fix ---
        pdf.set_x(17)                  # Move right slightly to create an inner indent inside the card
        pdf.set_font("Courier", "", 8.5)
        pdf.set_fill_color(26, 32, 44)  # Dark background terminal look
        pdf.set_text_color(247, 250, 252)
        
        # Print the patch text cleanly inside the 176mm wide box
        pdf.multi_cell(176, 5, clean_text(f"{patch}"), border=0, fill=True)
        
        # CRITICAL FIX: Reset the x-coordinate back to the main alignment grid line (15mm)
        pdf.set_x(15)
        # --- FIXED BLOCK END ---
        
        # Empty closure spacer row box
        pdf.set_fill_color(255, 255, 255)
        pdf.cell(0, 2, "", border="LRB", ln=True, fill=True)
        pdf.ln(6)

    # Output generation
    os.makedirs(os.path.dirname(output_pdf), exist_ok=True)
    pdf.output(output_pdf)
    print(f"[✓] Executive PDF Report compiled successfully using native engine: {output_pdf}")

if __name__ == '__main__':
    generate_pdf_report()