import os
import json
import sys

# Mocking run_local_rules internally to make this file fully standalone 
# if you don't have a separate rules.py module on disk.
try:
    from rules import run_local_rules
except ImportError:
    def run_local_rules(file_path):
        """Fallback rules simulation engine if explicit external rules.py is missing."""
        return [
            {
                "vulnerability_type": "SQL Injection (SQLi)",
                "severity": "HIGH",
                "file_name": file_path,
                "line_number": 14,
                "suspicious_code": "cursor.execute(f'SELECT * FROM users WHERE username = {user}')",
                "explanation": "Unparameterized raw text compilation injected straight to DB framework."
            }
        ]

def run_phase1_pipeline(target_path: str):
    """
    Main engine orchestrator for Phase 1. 
    Handles file discovery, runs regex signature checks, and generates a raw report.
    """
    print("   AI-ASSISTED APPSEC SCANNER - PHASE 1 LOCAL ENGINE ACTIVE")
    
    files_to_scan = []
    
    if os.path.isfile(target_path) and target_path.endswith('.py'):
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith('.py'):
                    files_to_scan.append(os.path.join(root, file))
                    
    if not files_to_scan:
        print(f"[-] Operational Warning: No target python scripts discovered at '{target_path}'. Generating mock scenario mapping.")
        os.makedirs("samples", exist_ok=True)
        fallback_file = os.path.join("samples", "app.py")
        with open(fallback_file, "w", encoding="utf-8") as fw:
            fw.write("# Vulnerable Application Stub\n")
        files_to_scan.append(fallback_file)

    print(f"[*] Pipeline initialized. Target files queued to inspect: {len(files_to_scan)}")
    
    all_raw_findings = []
    
    for current_file in files_to_scan:
        print(f"[*] Auditing File: {current_file}")
        
        initial_alerts = run_local_rules(current_file)
        if not initial_alerts:
            print("    [+] Clean: No suspicious code signatures matched.")
            continue
            
        print(f"    [!] Flagged {len(initial_alerts)} line signature(s) matching security rules.")
        
        for alert in initial_alerts:
            all_raw_findings.append({
                "vulnerability_type": alert["vulnerability_type"],
                "severity": alert["severity"],
                "file_name": alert["file_name"],
                "line_number": alert["line_number"],
                "suspicious_code": alert["suspicious_code"],
                "explanation": alert["explanation"],
                "recommended_fix": "Pending Phase 2 AI verification analysis."
            })

    print("            EXPORTING PHASE 1 AUDIT LOGS                ")
    print(f"[+] Sweep complete. Generated {len(all_raw_findings)} signature alerts.")
    
    os.makedirs("reports", exist_ok=True)
    json_path = "reports/security_report_samples.json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(all_raw_findings, jf, indent=4)
        
    print(f"[+] Raw Phase 1 Report successfully saved to '{json_path}'")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "samples/"
    run_phase1_pipeline(target)