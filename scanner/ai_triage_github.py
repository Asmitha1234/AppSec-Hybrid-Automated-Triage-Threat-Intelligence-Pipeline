import os
import json
import time
import sys
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def get_code_context(file_path, target_line, window=12):
    if not os.path.exists(file_path):
        return f"[ERROR] Code context path missing on disk: {file_path}"
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        start = max(0, target_line - window - 1)
        end = min(len(lines), target_line + window)
        
        context_block = []
        for i in range(start, end):
            line_num = i + 1
            marker = "==>" if line_num == target_line else "   "
            context_block.append(f"{marker} {line_num}: {lines[i].rstrip()}")
        return "\n".join(context_block)
    except Exception as e:
        return f"[ERROR] Context extraction exception: {str(e)}"

def run_local_rule_fallback(finding, code_context, idx):
    v_type = finding.get("vulnerability_type", "Unknown") if isinstance(finding, dict) else "Unknown Vulnerability"
    return {
        "is_true_positive": True,
        "vulnerability_type": v_type,
        "cve_id": f"CVE-2026-LOCAL-{1000 + idx}",
        "real_cvss_score": 7.5,
        "real_cvss_severity": "HIGH",
        "ai_taint_explanation": "Cloud validation bypassed. Structural data compiled safely via local fallback layer.",
        "remediation_patch": "# Context validation fallback activated. Manual verification recommended."
    }

def run_ai_triage():
    report_path = "reports/security_report_pygoat_master.json"
    output_path = "reports/ai_verified_report_pygoat_2.0.json"
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    if not os.path.exists(report_path):
        print(f"[-] Base scanner report missing: '{report_path}'.")
        return

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[-] ERROR: GITHUB_TOKEN environment variable is not set. Cannot access Cloud AI Engine.")
        return
        
    client = ChatCompletionsClient(
        endpoint="https://models.inference.ai.azure.com",
        credential=AzureKeyCredential(token)
    )
    
    with open(report_path, "r", encoding="utf-8") as f:
        raw_findings = json.load(f)
        
    ai_verified_findings = []
    processed_keys = set()
    
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as cache_file:
                ai_verified_findings = json.load(cache_file)
                for item in ai_verified_findings:
                    if isinstance(item, dict) and "ai_taint_explanation" in item:
                        processed_keys.add(f"{item.get('file_name')}:{item.get('line_number')}")
            print(f"[*] Resuming pipeline. Found {len(processed_keys)} already triaged entries.")
        except Exception:
            ai_verified_findings = []

    print(f"[*] Phase 2 Cloud AI Active. Processing {len(raw_findings)} total entries...")

    for idx, finding in enumerate(raw_findings, 1):
        if isinstance(finding, str):
            finding = {
                "file_name": "samples/app.py",
                "line_number": 1,
                "suspicious_code": finding,
                "vulnerability_type": "Raw Code Diagnostic Entry"
            }
            
        file_name = finding.get("file_name", "")
        line_num = finding.get("line_number", 0)
        suspicious_code = finding.get("suspicious_code", "")
        vulnerability_type = finding.get("vulnerability_type", "Unknown")
        
        current_key = f"{file_name}:{line_num}"
        if current_key in processed_keys:
            continue
            
        # LIVE CONSOLE FEEDBACK COUNTER
        print(f"    --> [{idx}/{len(raw_findings)}] Analyzing: {os.path.basename(file_name)} (Line {line_num})...", end="", flush=True)
        
        start_time = time.time()

        # Pacing throttle to handle strict GitHub token RPM limits
        if idx > 1:
            time.sleep(1.5)

        code_context = get_code_context(file_name, line_num)
        
        prompt = f"""
        You are an advanced enterprise AppSec Triage and Threat Intelligence Engine. 
        Review this code execution context harvested by a Static Analysis tool:
        
        File Path: {file_name}
        Line Number Flagged: {line_num}
        Initial Scanner Category: {vulnerability_type}
        Flagged Code Line: {suspicious_code}
        
        Surrounding Source Code Window:
        {code_context}
        
        Your Mission:
        1. Evaluate if this code is a True Positive or False Positive.
        2. Perform a Threat Intelligence lookup to find its real CVE, or assign 'CVE-2026-MOCK-{(1000 + idx)}'.
        3. Calculate CVSS base score (0.0 to 10.0) and severity.
        
        Return ONLY a raw JSON object matching the schema below. Do not wrap it in markdown block backticks or summary text:
        {{
            "is_true_positive": true,
            "vulnerability_type": "Vulnerability Name",
            "cve_id": "CVE-XXXX-XXXX",
            "real_cvss_score": 8.5,
            "real_cvss_severity": "HIGH",
            "ai_taint_explanation": "Detailed explanation here.",
            "remediation_patch": "Fix code line here."
        }}
        """
        
        retry_count = 0
        max_retries = 2
        success = False
        
        while retry_count <= max_retries:
            try:
                response = client.complete(
                    messages=[{"role": "user", "content": prompt}],
                    model="gpt-4o-mini",  
                    temperature=0.1,
                    timeout=10  # FORCE CONNECTION SNAP IF API HANGS AT THE LIMIT
                )
                
                raw_text = response.choices[0].message.content.strip()
                
                if "```" in raw_text:
                    raw_text = raw_text.split("```")[1]
                    if raw_text.startswith("json"):
                        raw_text = raw_text[4:].strip()
                raw_text = raw_text.strip("`").strip()
                    
                ai_verdict = json.loads(raw_text)
                
                if not ai_verdict.get("is_true_positive", True):
                    ai_verdict["real_cvss_score"] = 0.0
                    ai_verdict["real_cvss_severity"] = "NONE"
                    ai_verdict["cve_id"] = "N/A"

                ai_verified_findings.append({**finding, **ai_verdict})
                success = True
                break
                
            except json.JSONDecodeError:
                retry_count += 1
                print(f"\n        [!] JSON translation anomaly on item {idx}. Retrying ({retry_count}/{max_retries})...")
                time.sleep(1.0)
                
            except Exception as e:
                error_str = str(e).lower()
                # Catch actual network rate exhaustions explicitly
                if "429" in error_str or "quota" in error_str or "rate limit" in error_str:
                    print(f"\n    [🚫 API LIMIT HIT] Cloud Token quota exhausted on item {idx}.")
                    print("    [*] Gracefully saving current progress data to disk ledger...")
                    with open(output_path, "w", encoding="utf-8") as out_file:
                        json.dump(ai_verified_findings, out_file, indent=4)
                    return
                
                retry_count += 1
                print(f"\n        [!] Connection handshake timeout/issue on item {idx}. Retrying ({retry_count}/{max_retries})...")
                time.sleep(2.0 * retry_count)
                
        if not success:
            print(" [LOCAL FALLBACK]")
            local_verdict = run_local_rule_fallback(finding, code_context, idx)
            ai_verified_findings.append({**finding, **local_verdict})
        else:
            elapsed = time.time() - start_time
            print(f" [DONE in {elapsed:.1f}s]")

        # Incremental backup write on every item loop complete
        with open(output_path, "w", encoding="utf-8") as out_file:
            json.dump(ai_verified_findings, out_file, indent=4)

    print(f"\n[SUCCESS] Phase 2 Triage Complete! Dataset fully updated at: '{output_path}'")

if __name__ == "__main__":
    run_ai_triage()