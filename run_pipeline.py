import os
import sys
import subprocess

SCAN_TARGET = "./samples"
REPORTS_DIR = "reports"
FINAL_AI_REPORT = os.path.join(REPORTS_DIR, "ai_verified_report_sample.json")

def run_command(command, description):
    print(f"\n[*] Starting Phase: {description}...")
    print(f"[#] Executing: {' '.join(command)}")
    try:
        # Appending shell=True to fix executable lookup on Windows environments
        result = subprocess.run(command, check=True, text=True, capture_output=True, shell=True)
        print(f"[SUCCESS] Successfully completed: {description}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during {description}:", file=sys.stderr)
        print(e.stderr, file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"[-] Command failed: Execution target missing or not installed.", file=sys.stderr)
        return None

# Updated segment in run_pipeline.py
def main():
    print("="*70)
    print("      APPSEC & IAC HYBRID AUTOMATED TRIAGE PIPELINE")
    print("="*70)
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(SCAN_TARGET, exist_ok=True)

    # 1. Run Application Code Vulnerability Analysis
    sast_command = [sys.executable, "scanner.py", SCAN_TARGET]
    run_command(sast_command, "Source Workspace Code Scan (SAST)")

    # 2. Run Infrastructure Code Vulnerability Analysis (NEW)
    iac_command = [sys.executable, "checkov_scanner.py", SCAN_TARGET]
    run_command(iac_command, "Cloud Infrastructure Target Manifest Scan (IaC Security)")

    # 3. Process All Collected Findings using AI Triage
    triage_command = [sys.executable, "scanner/ai_triage_github.py"]
    run_command(triage_command, "AI Filtering, Context Analysis & Threat Intelligence Verification")

    if os.path.exists(FINAL_AI_REPORT):
        print("\n[SUCCESS] Final security triage payload resolved successfully.")
        print("[*] Spawning localized Presentation Layer Dashboard Server...")
        
        # FIX: Pointed directly to generate_dashboard.py execution mapping target
        dashboard_command = [sys.executable, "generate_dashboard.py"]
        try:
            process = subprocess.Popen(dashboard_command, shell=True)
            process.wait()
        except KeyboardInterrupt:
            print("\n[*] Pipeline execution context terminated by user request.")
            process.terminate()
    else:
        print(f"\n[-] Critical Pipeline Failure: Missing final triage ledger at {FINAL_AI_REPORT}", file=sys.stderr)
        print("[-] Ensure 'scanner/ai_triage_github.py' executes cleanly.", file=sys.stderr)

if __name__ == "__main__":
    # Force system terminal context to safely pass Unicode encoding on Windows boxes
    os.environ["PYTHONIOENCODING"] = "utf-8"
    main()