# auto_patch.py
import os
import sys
import json
import py_compile
from collections import defaultdict
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

def apply_remediation_patch(file_path, line_number, remediation_patch):
    """Surgically overwrites a specific line while preserving scope indentation and layout safety boundaries."""
    if not os.path.exists(file_path):
        return

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if line_number <= 0 or line_number > len(lines):
        return

    target_index = line_number - 1
    original_line = lines[target_index]
    
    # Extract leading whitespace to preserve structural Python code alignment
    indentation = original_line[:len(original_line) - len(original_line.lstrip())]
    
    # 🟢 SANITIZATION GATE: Catch structural flaws from legacy ledger entries
    # Convert literal string '\n' text into actual line feeds
    remediation_patch = remediation_patch.replace("\\n", "\n")
    
    # Check for squashed statements that cause syntax violations
    if "query =" in remediation_patch and "cursor.execute" in remediation_patch and "\n" not in remediation_patch:
        remediation_patch = remediation_patch.replace(" cursor.execute", "\ncursor.execute")
        
    patched_lines = []
    raw_patch_lines = remediation_patch.splitlines()
    
    for idx, p_line in enumerate(raw_patch_lines):
        # Clean spacing uniformly without dropping relative inner logic indent layouts
        clean_line = p_line.strip() if idx == 0 else p_line.rstrip()
        if clean_line:
            # Reapply correct architectural indentation mapping
            patched_lines.append(f"{indentation}{clean_line}\n")
        else:
            patched_lines.append("\n")

    lines[target_index] = "".join(patched_lines)

    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

def verify_syntax_safety(file_path):
    """Compiles target python components, skipping cloud orchestration files."""
    if not file_path.endswith('.py'):
        return True
    try:
        py_compile.compile(file_path, doraise=True)
        return True
    except py_compile.PyCompileError:
        return False

def ask_ai_to_verify_fix(file_path, vulnerability_type, applied_patch, origin_domain):
    """PHASE 3 VERIFICATION: Direct Azure Cloud Chat API compilation check."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return {
            "fix_verified_safe": False, 
            "verification_notes": "API Check Skipped: GITHUB_TOKEN environment variable is not set."
        }

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        updated_code = f.read()

    # Inside auto_patch.py -> ask_ai_to_verify_fix()
    prompt_template = """
You are an advanced enterprise AppSec Verification and Cloud IaC Compliance Auditor.
An automated security patch has been applied to a file on disk. Your mandate is to execute a zero-trust code review of the entire updated file to certify that the vulnerability has been completely eliminated without introducing secondary flaws.

TARGET VULNERABILITY ARCHETYPE: {vulnerability_type}
ORIGIN DOMAIN: {origin_domain} (Expected values: APPSEC or IAC)
THE SECURITY PATCH THAT WAS APPLIED:
-----------------------------------------------------
{applied_patch}
-----------------------------------------------------

FULL UPDATED FILE CONTENT FOR AUDIT:
-----------------------------------------------------
{updated_code}
-----------------------------------------------------

YOUR EVALUATION MANDATES & CHECKBOXES:
1. IF THE ORIGIN IS 'APPSEC' (Application Code):
   - Verify that raw dynamic string concatenations have been eliminated.
   - 🟢 AUDIT EXEMPTION: Standard parameterization syntax using placeholder arrays (like passing values inside a secondary tuple tuple layer using '%s' or '?') is explicitly CERTIFIED AS SAFE. Do not reject patches simply for utilizing generic '%s' binding syntax.

Return ONLY a raw JSON object matching the exact schema below. Do not wrap it in markdown code blocks or backticks:
{{
    "fix_verified_safe": true,
    "verification_notes": "Provide a detailed, critical engineering analysis explaining why this file is now safe or what flaws remain unmitigated."
}}
"""

    prompt = prompt_template.format(
        vulnerability_type=vulnerability_type,
        origin_domain=origin_domain.upper(),
        applied_patch=applied_patch,
        updated_code=updated_code
    )

    try:
        client = ChatCompletionsClient(
            endpoint="https://models.inference.ai.azure.com",
            credential=AzureKeyCredential(token)
        )

        response = client.complete(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o-mini",  
            temperature=0.1,
            timeout=15
        )

        raw_text = response.choices[0].message.content.strip()
        
        if "```" in raw_text:
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:].strip()
        raw_text = raw_text.strip("`").strip()

        return json.loads(raw_text)

    except Exception as e:
        return {
            "fix_verified_safe": False, 
            "verification_notes": f"Azure Inference API Failure or Token Exhaustion: {str(e)}"
        }

def run_remediation_and_verification_loop(final_report_path):
    print(f"[*] Targeting report source ledger: {final_report_path}")
    
    if not os.path.exists(final_report_path):
        print(f"[-] CRITICAL FAILURE: Ledger target path '{final_report_path}' does not exist.")
        return

    with open(final_report_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    true_positives = [i for i in findings if i.get("is_true_positive") == True and i.get("remediation_patch")]
    
    print(f"[*] Analysis: Loaded {len(findings)} total records. Found {len(true_positives)} active actionable vulnerabilities.")

    if not true_positives:
        print("[+] Process Completed: No active remediation tasks matched the ingestion filters.")
        return

    file_groups = defaultdict(list)
    for issue in true_positives:
        file_groups[issue["file_name"]].append(issue)

    for file_path, issues in file_groups.items():
        print(f"\n[*] Processing Remediations for File: {file_path}")
        
        if not os.path.exists(file_path):
            print(f"    [-] Skipped: Target file '{file_path}' not found on drive disk.")
            continue

        issues.sort(key=lambda x: x["line_number"], reverse=True)
        
        for issue in issues:
            line_num = issue["line_number"]
            patch_code = issue["remediation_patch"]
            v_type = issue["vulnerability_type"]
            domain = issue.get("origin", "appsec")

            with open(file_path, "r", encoding="utf-8", errors="ignore") as current_state_file:
                pre_patch_checkpoint = current_state_file.read()
            
            print(f"    -> Applying patch on line {line_num}...", end="")
            apply_remediation_patch(file_path, line_num, patch_code)
            print(" [PATCH APPLIED]")

            if verify_syntax_safety(file_path):
                print("    [*] Local syntax validated. Submitting updated code to AI for re-verification...")
                
                ai_verdict = ask_ai_to_verify_fix(file_path, v_type, patch_code, domain)
                
                if ai_verdict.get("fix_verified_safe") == True:
                    print("    [+ AI VERIFIED] The AI has certified this file as SAFE!")
                    issue["remediation_status"] = "REMEDIATED_AND_VERIFIED"
                    issue["verification_notes"] = ai_verdict.get("verification_notes")
                else:
                    print(f"    [-] AI REJECTION: {ai_verdict.get('verification_notes')}")
                    print("    [*] Safety Trigger: Rolling back file to pre-patch state...")
                    with open(file_path, "w", encoding="utf-8") as r_file:
                        r_file.write(pre_patch_checkpoint)
                    issue["remediation_status"] = "REMEDIATION_FAILED_AI_REJECTION"
            else:
                print("    [-] CRITICAL: Local compilation syntax broke. Rolling back file instantly...")
                with open(file_path, "w", encoding="utf-8") as r_file:
                    r_file.write(pre_patch_checkpoint)
                issue["remediation_status"] = "REMEDIATION_FAILED_SYNTAX_ERROR"

    with open(final_report_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)
        
    print("\n[SUCCESS] Auto-Remediation and AI Verification loop completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        chosen_ledger_path = sys.argv[1]
    else:
        chosen_ledger_path = "reports/test_remediation_report.json"

    run_remediation_and_verification_loop(chosen_ledger_path)