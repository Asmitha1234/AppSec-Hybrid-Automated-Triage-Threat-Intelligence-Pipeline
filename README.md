# AppSec Hybrid Automated Triage & Threat Intelligence Pipeline

An enterprise-grade, two-phase Hybrid Static Application Security Testing (SAST) orchestration engine and AI-assisted vulnerability triage registry. This system sweeps target applications locally via signature pattern diagnostics, processes findings through Cloud AI (`gpt-4o-mini`) via GitHub Models using high-resiliency network loop controls, maps historical upstream CVE data, and serves an interactive web dashboard matrix.

---

## System Pipeline Architecture

```text
  [ Target Workspace ] 
           │
           ▼
   ( Phase 1 Engine )  ──► compiles local signature alerts (scanner.py)
           │
           ▼
   ( Phase 2 Engine )  ──► processes context windows + strict timeout guards (ai_triage_github.py)
           │
           ▼
 [ Presentation Layer ] ──► serves real-time visualization analytics on port 8085 (generate_dashboard.py)
```
1. Phase 1 (Local Scanner Engine): Traverses the targeted codebase recursively to isolate suspect structural patterns, writing a raw baseline database to disk.
2. Phase 2 (Cloud AI Triage Engine):  Extracts precise plus or minus 12 line source code context windows, queries cloud threat intelligence with client-side connection timeout limits (timeout=10) to eliminate backend freezes, handles JSON string syntax repair dynamically, and drops into local rule fallbacks on true quota drops.
3. Presentation Layer (Dashboard):  Launches a local multi-threaded socket server hosting an interactive dashboard displaying deep data-flow threat reviews, risk classifications, and production-ready remediation patches.

## Installation and Virtual Environment Setup
Follow these steps to clone the repository, isolate your dependencies in a virtual environment, and install all required pipeline packages.

### 1. Clone the repository 
Open your terminal an clone the project workspace down to your machine:
```text
git clone [https://github.com/Asmitha1234/AppSec-Hybrid-Automated-Triage-Threat-Intelligence-Pipeline.git](https://github.com/Asmitha1234/AppSec-Hybrid-Automated-Triage-Threat-Intelligence-Pipeline.git)
cd AppSec-Hybrid-Automated-Triage-Threat-Intelligence-Pipeline
```
### 2. Initialize and Activate the Virtual Environment
Create a localized virtual environment (.venv) to protect your global Python workspace from dependency conflicts:
```text
<!-- initialize the isolated environment -->
python -m venv .venv
```
Activate the environment based on your current operating system and active terminal console:
--> Windows (Command Prompt/cmd):
```text
.venv\Scripts\activate
```
--> Windows (PowerShell):
```text
.venv\Scripts\Activate.ps1
```
--> Linux/ macOS (Terminal):
```text
source .venv/bin/activate
```
(Once activated, you will see (.venv) prepend your terminal prompt indicator).
### 3. Install Requirements
With your virtual environment successfully active, run the baseline dependency mapping installer:
```text
pip install -r requirements.txt
```

## Execution Manual
Before kicking off the master pipeline runner, populate your active session's context with a valid GitHub Personal Access Token (PAT). This credential is required by the Phase 2 triage module to safely handshake with the cloud models.

Provide the token using the format matching your operating environment:
--> Windows Command Prompt (cmd)
```text
set GITHUB_TOKEN=github_pat_your_token_here
python run_pipeline.py
```
--> Windows PowerShell
```text
$env:GITHUB_TOKEN="github_pat_your_token_here"
python run_pipeline.py
```
--> Linux/ macOS Terminal
```text
export GITHUB_TOKEN="github_pat_your_token_here"
python -u run_pipeline.py
```

## Target Workspace Reconfiguration 
The execution framework uses a Single Source of Truth configuration design. You do not need to modify paths across multiple files. To point the automated scanner to any project, open run_pipeline.py and modify the SCAN_TARGET parameter string near the top:
```text
<!-- run_pipeline.py (Line 5) -->
SCAN_TARGET = "./src/pygoat_master"  # Update this value to target any directory or folder
```
The pipeline automatically flows this configuration down to the signature engines, updates intermediate logs, and extracts the correct context windows without manual path matching.

## Operational Fail-Safe Mechanisms 
1. Indefinite Freeze Elimination: Standard cloud network requests can drop or hang if rate limits are reached. This pipeline enforces a strict client-side connection cutoff (timeout=10) inside the Azure inference runtime loop to snap dead sockets and trigger immediate, structured error recovery.
2. Incremental Cache Saving: Triage results are saved immediately to reports/(otuput_file _name) on every single loop iteration. If the operation is interrupted, your progress is safely written to disk.
3. Token Exhaustion Resiliency: If a true HTTP 429 rate limit or quota block is detected, the script automatically triggers a safe exit, preserves all processed entries, and successfully hands over control back to the master runner to instantly load your dashboard with partial results.

## Repository Directory Structure
```text
AppSec-Hybrid-Automated-Triage-Threat-Intelligence-Pipeline/
│
├── scanner/
│   └── ai_triage_github.py      # Phase 2 Cloud AI Engine (with timeout & fallback loop)
│
├── reports/                      # Auto-generated scan outputs (Ignored by Git)
│   ├── security_report_samples.json
│   └── ai_verified_report_pygoat_2.0.json
│
├── .gitignore                    # Git inclusion rules
├── generate_dashboard.py         # Local web UI visualization dashboard framework
├── requirements.txt              # Project library dependencies
├── README.md                     # Documentation framework
├── run_pipeline.py               # Master orchestration controller pipeline
└── scanner.py                    # Phase 1 Local SAST Signature engine
```