# Autonomous Security Posture Mesh (SPM): Full-Stack Vulnerability Triage & Self-Healing Pipeline

An advanced, enterprise-grade Application Security Posture Management (ASPM) framework. This architecture orchestrates multi-domain security scanners, extracts deep source-code execution context, isolates false positives via cloud-hosted Large Language Models (LLMs), and triggers a deterministic, dual-gated automated remediation loop to heal vulnerabilities at machine speed.

---

## Core Features & Architectural Breakthroughs

* **Multi-Domain Security Telemetry Ingest:** Seamlessly runs and unifies child-process executions of application source code scanners (SAST) and infrastructure configuration checkers (Checkov IaC).
* **Universal Subprocess Encoding Resilience:** Natively stabilizes Windows/Linux file subsystems using forced UTF-8 execution layers (`PYTHONUTF8=1`), passing cleanly through special-character encoding traps.
* **Context-Aware Zero-Trust Triage:** Automatically captures a $\pm$12-line sliding code window around raw alert coordinates, passing the complete operational layout to an LLM running specialized triage mandates.
* **Dual-Gate Self-Healing Remediation:** Surgically updates files on disk while fully preserving original indentation blocks, using a strict validation engine before final commits:
    * **Gate 1 (Deterministic Syntax Validation):** Compiles code locally via `py_compile`. Instantly rolls back the state to a pre-patch memory snapshot if a `SyntaxError` is detected.
    * **Gate 2 (Probabilistic Architectural Audit):** Executes an independent cloud AI security code review to guarantee that database parameterization aligns properly with target system drivers (e.g., `?` vs `%s`).
* **Compliance-Ready Executive Reporting:** Features an interactive Streamlit console allowing engineers to download high-fidelity **Executive Audit PDFs** and raw **JSON Data Ledgers** at the press of a button.

---

## System Architecture Blueprint

The framework separates scanning telemetry from fix generation using a decoupled multi-phase pipeline topology:

[Phase 1: Multi-Domain Scan]  ---> [Phase 2: Contextual AI Triage] ---> [Phase 3: Dual-Gate Self-Healing]

SAST Application Engine         - Sliding Context Windows          - Surgical Line Overwrites

Checkov IaC Infrastructure      - Azure Inference Filtering        - Local Syntax Check (Gate 1)

Normalized UTF-8 Subprocesses   - Strict JSON Schema Output        - Zero-Trust AI Audit (Gate 2)
- Safe Automated Rollback

---

## Repository Structure Matrix

This repository acts strictly as the **Core Engine Management Core**. All temporary diagnostic run ledgers, reporting outputs, and target mock repositories are strictly isolated via exclusive repository allow-list protocols.

```text
├── app_ui.py                    # Interactive Streamlit Enterprise Control Dashboard
├── checkov_scanner.py           # Multi-platform IaC and sandboxed Checkov execution script
├── auto_patch.py                # Line-alignment compiler validation and healing logic runner
├── generate_dashboard.py        # Analytics compiling utility for raw reporting logs
├── run_pipeline.py              # Master headless orchestrator script for pipeline execution
├── scanner.py                   # Global entrypoint configuration manager
├── scanner/
│   ├── __init__.py              # Scanner module initialization configuration boundary
│   ├── ai_triage_github.py      # Azure Cloud Inference client prompt and triage engine
│   └── rules.py                 # Structured vulnerability filters and severity definitions
├── .gitignore                   # Exclusive Allow-List definition matrix
└── README.md                    # Core system documentation
```
---

## Setup & Quickstart Installation
### 1. System Dependencies & Environment Provisioning
Ensure you have Python 3.10+ installed on your host Windows or Linux VM environment.

Provision the underlying Checkov virtual runtime mapping and install required dashboard and orchestration libraries:
```text
# Install core orchestration, formatting, and UI libraries
pip install streamlit reportlab azure-ai-inference azure-core

# Ensure pipx or python virtual environments are linked for checkov executions
# Path variable configuration defaults look inside:
# C:\Users\<USER>\pipx\venvs\checkov\Scripts\python.exe
```

### 2. Configure Environment Security Tokens
The triage and auditing modules communicate via secure channels using the Azure AI Inference API layer. Set your authorization keys inside your local active terminal session before launching:

--> Windows PowerShell:
```text
$env:GITHUB_TOKEN="your_enterprise_github_inference_token_here"
```
---> Linux/macOS Bash:
```text
export GITHUB_TOKEN="your_enterprise_github_inference_token_here"
```

### 3. Execution Workflows
**Headless Automation Mode:**
Trigger the end-to-end security matrix ingest, automated intelligence filter triage, and healing loop via the master orchestrator script:
```text
python run_pipeline.py
```
**Interactive Dashboard UI Panel**
Launch the responsive enterprise compliance management interface control console:
```text
streamlit run app_ui.py
```

---

## Real-World Mitigation Snapshot: SQL Injection (CWE-89)
**Ingest State (Vulnerable Snippet)**
```text
# target_vulnerable.py (Line 5)
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```
**Scanner Finding:** Dynamic variable compiled directly inside a database query execution payload. Critical severity risk of data extraction.

**Remediated State (Self-Healed Snippet)**
```text
# target_vulnerable.py (Line 5)
query = 'SELECT * FROM users WHERE id = %s'
cursor.execute(query, (user_id,))
```
**Pipeline Action Ledger:** Patch surgically applied, structure validated via native compiler checkpoints, certified by the Zero-Trust Auditor, and ledger updated status marked as *REMEDIATED_AND_VERIFIED*.

---

## Enterprise Business Relevence & Impact Matrix
**Lifecycles Accelerated (MTTR):** Drastically compresses Mean Time to Remediate from weeks down to milliseconds per codebase anomaly.

**0x Developer Friction:** Maximizes software engineer focus by filtering out alert noise and providing pre-compiled, syntax-safe patches waiting for a one-click pull request review.

**Zero Technical Security Debt:** Prevents vulnerabilities from expanding downstream into live production environments, keeping organizations audit-ready and compliant.
