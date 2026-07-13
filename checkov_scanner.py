# checkov_scanner.py
import os
import json
import sys
import subprocess
import datetime

def run_checkov_scan(target_path: str, output_file_path: str = "reports/raw_iac_report.json"):
    print("   CHECKOV INTEGRATED APPMAPPER - PHASE 1 ACTIVE")
    
    # 1. Clean and normalize directory strings for the Windows environment
    clean_target_path = os.path.abspath(target_path.strip("'\"")).replace("/", "\\")
    print(f"[*] Target Directory Target: {clean_target_path}")
    
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    
    # Preserve existing findings
    existing_findings = []
    if os.path.exists(output_file_path):
        try:
            with open(output_file_path, "r", encoding="utf-8") as jf:
                loaded_data = json.load(jf)
                if isinstance(loaded_data, list):
                    existing_findings = [item for item in loaded_data if item.get("origin") != "iac"]
        except Exception as e:
            print(f"[-] Warning reading master ledger: {e}", file=sys.stderr)

    # 🟢 WINDOWS FIX: Pin directly to the virtual environment python engine 
    checkov_bin = r"C:\Users\asmitha.chilukuri.c\pipx\venvs\checkov\Scripts\python.exe"
    
    # 🟢 MODULE METHOD: Use "-m checkov.main" and remove nested quotes around the clean target path.
    # Added "--framework dockerfile kubernetes" to force engine engagement.
    checkov_cmd = [
        checkov_bin, "-m", "checkov.main",
        "-d", clean_target_path,
        "--framework", "dockerfile", "kubernetes", "ansible",
        "--output", "json",
        "--soft-fail"
    ]
    
    print(f"[#] Executing Base Command: {' '.join(checkov_cmd)}")
    
    pipeline_findings = []
    current_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        # 🟢 WINDOWS FIX: Pass command as a singular string block to protect argument spacing strings
        cmd_string = " ".join(checkov_cmd)
        result = subprocess.run(cmd_string, capture_output=True, text=True, shell=True)
        
        raw_json_str = result.stdout.strip()
        
        # Capture raw error blocks if the output remains hidden
        if result.returncode != 0 and not raw_json_str:
            print(f"[!] Checkov Process Error Output (STDERR):\n{result.stderr}", file=sys.stderr)
        
        if raw_json_str:
            # Handle situations where multiple json frameworks return wrapped arrays
            if raw_json_str.startswith("["):
                checkov_data = json.loads(raw_json_str)
            else:
                checkov_data = [json.loads(raw_json_str)]
                
            for report in checkov_data:
                failed_checks = report.get("results", {}).get("failed_checks", [])
                
                for check in failed_checks:
                    mapped_finding = {
                        "vulnerability_type": f"{check.get('check_id')} : {check.get('check_name')}",
                        "severity": check.get("severity", "MEDIUM"), 
                        "file_name": os.path.normpath(os.path.join(clean_target_path, check.get("file_path").lstrip("/"))),
                        "line_number": check.get("file_line_range", [1, 1])[0],
                        "suspicious_code": "".join([line[1] for line in check.get("code_block", [])]),
                        "explanation": f"Guidance: {check.get('guideline')}. Description: Insecure infrastructure deployment configuration flagged.",
                        "recommended_fix": "Pending Phase 2 Cloud AI infrastructure remediation patch design.",
                        "origin": "iac",
                        "scan_epoch_signature": current_timestamp
                    }
                    pipeline_findings.append(mapped_finding)
        else:
            print("[-] Warning: Checkov returned empty response structure. 0 entries extracted.", file=sys.stderr)
            
    except Exception as e:
        print(f"[-] Checkov execution failed or crashed: {str(e)}", file=sys.stderr)

    # 2. Complete the secure merge process
    combined_findings = existing_findings + pipeline_findings
    
    with open(output_file_path, "w", encoding="utf-8") as jf:
        json.dump(combined_findings, jf, indent=4)
        
    print(f"[SUCCESS] Combined ledger updated. Total consolidated entries now on disk: {len(combined_findings)}")

if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "./src"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "reports/raw_iac_report.json"
    
    run_checkov_scan(target_dir, output_file)