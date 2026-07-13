# app_ui.py
import streamlit as st
import streamlit.components.v1 as components
import os
import json
import subprocess
import sys
import shutil
import datetime

st.set_page_config(
    page_title="Studio | AppSec & IaC Triage",
    page_icon="",
    layout="wide"
)

# Minimalist Global CSS Overrides
st.markdown("""
    <style>
        .stApp { background-color: #fafbfc; }
        h1, h2, h3 { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important; font-weight: 600 !important; color: #1e293b !important; }
        div[data-testid="stMetricSimpleValue"] { font-size: 24px !important; font-weight: 600 !important; color: #0f172a !important; }
        div[data-testid="metric-container"] { background: #ffffff; padding: 16px; border-radius: 6px; border: 1px solid #e2e8f0; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.02); }
        .stButton>button { border-radius: 4px !important; font-weight: 500 !important; transition: all 0.2s ease; border: 1px solid #cbd5e1 !important; background-color: #ffffff !important; color: #334155 !important; }
        .stButton>button:hover { border-color: #94a3b8 !important; color: #0f172a !important; background-color: #f8fafc !important; box-shadow: 0 1px 3px rgba(0,0,0,0.05) !important; }
        div.stAlert { border-radius: 4px !important; border: 1px solid #e2e8f0 !important; background-color: #ffffff !important; }
    </style>
""", unsafe_allow_html=True)

# Central Data Registry Alignment
REPORTS_DIR = "reports"
DASHBOARD_PATH = os.path.join(REPORTS_DIR, "dashboard.html")
SANDBOX_DIR = "./sandbox_uploader"  
WORKSPACE_DIR = "./src"              

os.makedirs(SANDBOX_DIR, exist_ok=True)
os.makedirs(WORKSPACE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

def get_available_repos():
    if not os.path.exists(WORKSPACE_DIR):
        return []
    return [d for d in os.listdir(WORKSPACE_DIR) if os.path.isdir(os.path.join(WORKSPACE_DIR, d))]

def execute_scanner(command_list, status_message):
    log_placeholder = st.container()
    
    with st.spinner(status_message):
        if isinstance(command_list, list):
            cmd_str = " ".join(command_list)
        else:
            cmd_str = command_list
            
        current_env = os.environ.copy()
        current_workspace = os.getcwd()
        
        result = subprocess.run(
            cmd_str, 
            capture_output=True, 
            text=True, 
            shell=True, 
            env=current_env,
            cwd=current_workspace  
        )
        
        if result.returncode != 0:
            with log_placeholder:
                st.error(f"❌ CRITICAL PROCESS FAILURE: {status_message}")
                st.code(result.stderr if result.stderr else "No STDERR reported.")
            return False
            
        return True

# ==========================================
# ⬅️ SIDEBAR CONTROL PANEL
# ==========================================
st.sidebar.title("Studio Control")
st.sidebar.markdown("<br>", unsafe_allow_html=True)

if "nav_state" not in st.session_state:
    st.session_state.nav_state = "Orchestrator"

page_navigation = st.sidebar.radio(
    "Workspace Navigation", 
    ["Orchestrator", "Threat Ledger"],
    index=["Orchestrator", "Threat Ledger"].index(st.session_state.nav_state)
)
st.session_state.nav_state = page_navigation

st.sidebar.markdown("---")

# 🟢 DYNAMIC SWITCHER: Changes the database path parameter processed throughout both pipeline loops
st.sidebar.caption("🔧 Ledger Operating Mode")
ledger_mode = st.sidebar.selectbox(
    "Select Target Ledger",
    ["Production Engine", "Isolated Testing Mode"],
    index=1  # Default directly to your isolated workspace
)

if ledger_mode == "Isolated Testing Mode":
    REPORT_PATH = "reports/mock_triage_report2.json"
    st.sidebar.info("Active: `reports/mock_triage_report2.json`")
else:
    REPORT_PATH = "reports/ai_verified_report_sample.json"
    st.sidebar.caption("Active: `reports/ai_verified_report_sample.json`")

st.sidebar.markdown("---")
st.sidebar.caption("Target Selection")

upload_mode = st.sidebar.selectbox(
    "Ingestion Mode",
    ["Scan Local Repository Folder", "Upload Individual Files"],
    label_visibility="collapsed"
)

target_scan_path = None
has_targets = False

if upload_mode == "Upload Individual Files":
    uploaded_files = st.sidebar.file_uploader(
        "Upload workspace files", 
        accept_multiple_files=True,
        label_visibility="collapsed"
    )
    if uploaded_files:
        shutil.rmtree(SANDBOX_DIR, ignore_errors=True)
        os.makedirs(SANDBOX_DIR, exist_ok=True)
        for u_file in uploaded_files:
            target_file_path = os.path.join(SANDBOX_DIR, u_file.name)
            with open(target_file_path, "wb") as f:
                f.write(u_file.read())
        target_scan_path = SANDBOX_DIR
        has_targets = True
        st.sidebar.success(f"{len(uploaded_files)} files staged.")

elif upload_mode == "Scan Local Repository Folder":
    available_repos = get_available_repos()
    if not available_repos:
        custom_path = st.sidebar.text_input("Manual Path Target:", value="./src/vulnerable_flask_app")
        target_scan_path = custom_path
        has_targets = True
    else:
        selected_repo = st.sidebar.selectbox("Select Target Repository", available_repos, label_visibility="collapsed")
        target_scan_path = os.path.join(WORKSPACE_DIR, selected_repo)
        has_targets = True
        st.sidebar.caption(f"Armed Target: `{target_scan_path}`")


# ==========================================
# 🚀 ROUTING PAGE 1: ORCHESTRATOR
# ==========================================
if page_navigation == "Orchestrator":
    st.title("Orchestrator Control Center")
    st.markdown("<p style='color: #64748b; font-size: 14px; margin-top: -10px;'>Execute security pipelines and manage headless verification workflows.</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    col_left, col_right = st.columns(2, gap="large")
    is_disabled = not has_targets
    
    with col_left:
        st.markdown("### Pipeline 1: Audit & Triage")
        st.markdown("<p style='color: #64748b; font-size: 13px; min-height: 45px;'>Runs static analysis engines (SAST/IaC) and pipes contexts via LLM nodes to filter noise and map industrial CWE/CVE benchmarks.</p>", unsafe_allow_html=True)
        run_audit_pipeline = st.button("Initialize Threat Scan", use_container_width=True, disabled=is_disabled)

    with col_right:
        st.markdown("### Pipeline 2: Remediate & Verify")
        st.markdown("<p style='color: #64748b; font-size: 13px; min-height: 45px;'>Ingests the active ledger, rewrites disk code line-by-line via reverse indexing algorithms, and executes local compiler and zero-trust verification checks.</p>", unsafe_allow_html=True)
        run_remediation_pipeline = st.button("Trigger Self-Healing Loop", use_container_width=True, disabled=is_disabled)

    st.markdown("<br><br>", unsafe_allow_html=True)

    # 🔍 INSIDE PIPELINE 1 BLOCK
    if run_audit_pipeline and target_scan_path:
        st.info("Executing isolated multi-engine vulnerability analysis...")
        
        sast_raw = "reports/raw_sast_report.json"
        iac_raw = "reports/raw_iac_report.json"
        
        # Explicitly delete stale temporary artifacts before beginning scan passes
        for stale_file in [sast_raw, iac_raw, REPORT_PATH]:
            if os.path.exists(stale_file):
                try:
                    os.remove(stale_file)
                except Exception as e:
                    st.warning(f"Unable to clear stale pipeline lock: {e}")

        # 🟢 FIX: Remove the manual string quote interpolation wrappers around target_scan_path
        sast_ok = execute_scanner([sys.executable, "scanner.py", target_scan_path, sast_raw], "Auditing Application Source Code (SAST)...")
        iac_ok = execute_scanner([sys.executable, "checkov_scanner.py", target_scan_path, iac_raw], "Auditing Infrastructure Layouts (IaC)...")
        # 🟢 SYNCHRONIZED HANDOFF: Pass REPORT_PATH as argument 3 down into your triage processor
        triage_ok = execute_scanner([sys.executable, "scanner/ai_triage_github.py", sast_raw, iac_raw, REPORT_PATH], "Executing Master AI Matrix Triage Merge...")
        
        if sast_ok or iac_ok or triage_ok:
            execute_scanner([sys.executable, "generate_dashboard.py", REPORT_PATH], "Synchronizing threat ledger data matrices...")
            st.success("Pipeline 1 processing sequence finalized. Click on 'Threat Ledger' via the sidebar menu to view results.")

    # 🛠️ INSIDE PIPELINE 2 BLOCK
    if run_remediation_pipeline:
        st.warning("Active codebase repair track initialized...")
        
        reremediation_ok = execute_scanner(
            [sys.executable, "auto_patch.py", REPORT_PATH], 
            "Modifying source structures & resolving AI validation hooks..."
        )
        
        if reremediation_ok:
            execute_scanner(
                [sys.executable, "generate_dashboard.py", REPORT_PATH], 
                "Synchronizing threat ledger data matrices..."
            )
            st.success("Self-healing loop completed on disk files. Click on 'Threat Ledger' via the sidebar menu to view updates.")


# ==========================================
# 📊 ROUTING PAGE 2: THREAT LEDGER (WITH EXPORT FEATURES)
# ==========================================
elif page_navigation == "Threat Ledger":
    st.title("Threat Intelligence Ledger Matrix")
    st.markdown("---")

    if os.path.exists(REPORT_PATH):
        # 🟢 NEW UTILITY: Add Download and Export Functionality Panel
        st.markdown("### Export Threat Diagnostics")
        col_pdf, col_json = st.columns(2)

        # 📄 1. NATIVE PDF EXPORT ENGINE GENERATION
        with col_pdf:
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib import colors
                
                def generate_pdf_bytes(json_source_path):
                    import io
                    buffer = io.BytesIO()
                    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
                    story = []
                    
                    styles = getSampleStyleSheet()
                    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=24, spaceAfter=12, textColor=colors.HexColor("#0f172a"))
                    sub_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontSize=10, spaceAfter=20, textColor=colors.HexColor("#64748b"))
                    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, spaceBefore=10, spaceAfter=6, textColor=colors.HexColor("#1e293b"))
                    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, leading=12, textColor=colors.HexColor("#334155"))
                    
                    # Document Header
                    story.append(Paragraph("🛡️ Enterprise Threat Ledger Audit Report", title_style))
                    story.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target Ledger: {json_source_path}", sub_style))
                    story.append(Spacer(1, 10))
                    
                    with open(json_source_path, "r", encoding="utf-8") as f:
                        records = json.load(f)
                    
                    if not records:
                        story.append(Paragraph("No security anomalies registered inside this ledger data frame.", body_style))
                    else:
                        for idx, record in enumerate(records, 1):
                            story.append(Paragraph(f"<b>Issue #{idx}: {record.get('vulnerability_type', 'Unknown')}</b>", h2_style))
                            
                            # Build quick metrics grid data array
                            status = record.get('remediation_status', 'PENDING')
                            is_tp = "True Positive" if record.get('is_true_positive') else "False Positive/Noise"
                            
                            data = [
                                [Paragraph("<b>Target Asset Path:</b>", body_style), Paragraph(record.get('file_name', 'N/A'), body_style)],
                                [Paragraph("<b>Line Coordinates:</b>", body_style), Paragraph(str(record.get('line_number', 'N/A')), body_style)],
                                [Paragraph("<b>Triage Verdict:</b>", body_style), Paragraph(is_tp, body_style)],
                                [Paragraph("<b>AI Explanation:</b>", body_style), Paragraph(record.get('ai_taint_explanation', 'N/A'), body_style)],
                                [Paragraph("<b>Remediation Status:</b>", body_style), Paragraph(f"<b>{status}</b>", body_style)]
                            ]
                            
                            t = Table(data, colWidths=[120, 420])
                            t.setStyle(TableStyle([
                                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ffffff")),
                                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
                                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                                ('TOPPADDING', (0,0), (-1,-1), 6),
                                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                            ]))
                            story.append(t)
                            story.append(Spacer(1, 15))
                            
                    doc.build(story)
                    buffer.seek(0)
                    return buffer.getvalue()
                
                # Fetch PDF data stream dynamically
                pdf_data = generate_pdf_bytes(REPORT_PATH)
                st.download_button(
                    label="Export Executive PDF Report",
                    data=pdf_data,
                    file_name=f"threat_ledger_report_{ledger_mode.lower().replace(' ', '_')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception as pdf_err:
                st.error(f"Could not initialize PDF compilation engine: {pdf_err}")

        # 🗄️ 2. RAW JSON DATA EXPORT
        with col_json:
            with open(REPORT_PATH, "r", encoding="utf-8") as json_file:
                raw_json_data = json_file.read()
            st.download_button(
                label="Export Raw JSON Ledger",
                data=raw_json_data,
                file_name=f"threat_ledger_matrix_{ledger_mode.lower().replace(' ', '_')}.json",
                mime="application/json",
                use_container_width=True
            )

        st.markdown("<br><br>", unsafe_allow_html=True)

        # 3. RENDER THE INTERACTIVE WEB DASHBOARD COMPONENT
        if os.path.exists(DASHBOARD_PATH):
            with open(DASHBOARD_PATH, "r", encoding="utf-8") as html_file:
                rendered_html = html_file.read()
            components.html(rendered_html, height=900, scrolling=True)
        else:
            st.error("HTML rendering interface stream unavailable.")
            
    else:
        st.info(f"No compiled scan data discovered at `{REPORT_PATH}`. Arm targets on control frame and initiate an Orchestrator pass.")