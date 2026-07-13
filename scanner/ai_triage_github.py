# scanner/ai_triage_github.py
import os
import json
import time
import sys
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

def get_code_context(file_path, target_line, window=12):
    if not os.path.exists(file_path):
        return f"[ERROR] Reference tracking workspace location missing on local drive disk asset: {file_path}"
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
        return f"[ERROR] Context reading tracking failure exception: {str(e)}"

def run_ai_triage():
    # Set default fallback paths
    sast_input = "reports/raw_sast_report.json"
    iac_input = "reports/raw_iac_report.json"
    output_database = "reports/ai_verified_report_sample.json"
    
    # 🟢 CLI INTERCEPTOR: Maps exactly to arguments passed from the Orchestrator UI
    if len(sys.argv) > 3:
        sast_input = sys.argv[1]
        iac_input = sys.argv[2]
        output_database = sys.argv[3]

    combined_findings = []

    # Parse SAST entries
    if os.path.exists(sast_input):
        try:
            with open(sast_input, "r", encoding="utf-8") as f:
                sast_data = json.load(f)
                if isinstance(sast_data, list):
                    combined_findings.extend(sast_data)
        except Exception as e:
            print(f"[-] Failed parsing SAST staging log: {e}")

    # Parse IaC entries
    if os.path.exists(iac_input):
        try:
            with open(iac_input, "r", encoding="utf-8") as f:
                iac_data = json.load(f)
                if isinstance(iac_data, list):
                    combined_findings.extend(iac_data)
        except Exception as e:
            print(f"[-] Failed parsing IaC staging log: {e}")

    print(f"[*] Aggregated Engine Matrix: Loaded {len(combined_findings)} total issues for AI triage processing.")

    if not combined_findings:
        print("[-] No raw vulnerabilities found across staging registers.")
        os.makedirs(os.path.dirname(output_database), exist_ok=True)
        with open(output_database, "w", encoding="utf-8") as f:
            json.dump([], f)
        return
        
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[-] ERROR: GITHUB_TOKEN environment variable is not set.")
        return
        
    client = ChatCompletionsClient(
        endpoint="https://models.inference.ai.azure.com",
        credential=AzureKeyCredential(token)
    )
    
    ai_verified_findings = []
    print(f"[*] Phase 2 Threat Intelligence Mapping Active. Processing {len(combined_findings)} issues...")

    for idx, finding in enumerate(combined_findings, 1):
        if isinstance(finding, str):
            continue
            
        file_name = finding.get("file_name", "")
        line_num = finding.get("line_number", 0)
        suspicious_code = finding.get("suspicious_code", "")
        vulnerability_type = finding.get("vulnerability_type", "Unknown")
        
        print(f"    --> [{idx}/{len(combined_findings)}] Analyzing Threat Matrix: {os.path.basename(file_name)} (Line {line_num})...", end="", flush=True)
        start_time = time.time()

        if idx > 1:
            time.sleep(1.5)

        code_context = get_code_context(file_name, line_num)
        
        # 🟢 UPDATED PROMPT: Strict architectural mandates forcing structural line formatting
        prompt_template = """
You are an advanced enterprise AppSec Triage, Threat Intelligence, and Cloud IaC Compliance Engine.
Your core priority is to act as an objective filter that separates genuine security threats from harmless static analysis noise.

Review this flaw harvested from static analysis:
- File Target: {file_name}
- Line Number Flagged: {line_num}
- Scanner Category Identifier: {vulnerability_type}
- Flagged Source Snippet: {suspicious_code}

CRITICAL DATA - Surrounding Context Code Window (+/- 12 lines):
{code_context}

YOUR REMEDIATION FORMATTING MANDATES:
1. The "remediation_patch" value MUST be perfectly valid Python execution blocks.
2. NEVER cram independent execution statements onto a single line separated by spaces. If you assign a variable and execute a query, they MUST be separated by an actual physical newline character context.
3. For SQL Injection fixes, use standard parameterization syntax arrays. Do NOT use string interpolation formats like `% (user_id,)`.
4. Ensure you do not emit structural escape characters like raw text '\\n' text blocks; use actual multiline formatting blocks inside your JSON assignment string value payload definitions.

Return ONLY a raw JSON object matching this schema template profile. Do not wrap it in markdown code blocks or backticks:
{{
    "is_true_positive": true,
    "vulnerability_type": "Official Security Flaw Industry Name, CWE Category, or Compliance Violation ID",
    "cve_id": "CWE-250",
    "real_cvss_score": 7.5,
    "real_cvss_severity": "HIGH",
    "ai_taint_explanation": "Provide a detailed justification of why this code context window represents an active configuration vulnerability or real code-level flaw.",
    "remediation_patch": "query = 'SELECT * FROM users WHERE id = %s'\\ncursor.execute(query, (user_id,))"
}}
"""

        prompt = prompt_template.format(
            file_name=file_name,
            line_num=line_num,
            vulnerability_type=vulnerability_type,
            suspicious_code=suspicious_code,
            code_context=code_context
        )
        
        try:
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
            
            ai_verdict = json.loads(raw_text)
            ai_verified_findings.append({**finding, **ai_verdict})
            print(f" [DONE in {time.time() - start_time:.1f}s -> Mapped to: {ai_verdict.get('cve_id')}]")
            
        except Exception as e:
            print(f" [SKIPPED - Error: {e}]")
            continue

    os.makedirs(os.path.dirname(output_database), exist_ok=True)
    with open(output_database, "w", encoding="utf-8") as out_file:
        json.dump(ai_verified_findings, out_file, indent=4)
    print(f"\n[SUCCESS] Pipeline Complete! Ledger stored at: '{output_database}'")

if __name__ == "__main__":
    run_ai_triage()