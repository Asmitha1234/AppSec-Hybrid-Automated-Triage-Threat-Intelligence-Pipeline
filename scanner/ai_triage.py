import os
import json
import time 
from google import genai
from google.genai import types
from typing_extensions import TypedDict  # Import this to handle strict JSON schemas cleanly
from google.genai.errors import APIError

# 1. Initialize the official GenAI SDK client
# The client automatically searches for the $env:GEMINI_API_KEY environment variable.
client = genai.Client()

def get_code_context(file_path, target_line, window=12):
    """
    Safely reads target files from disk and extracts the surrounding window block.
    This gives the LLM precise context to follow data flows without hitting token limits.
    """
    if not os.path.exists(file_path):
        return f"[ERROR] Absolute target path could not be mapped to disk: {file_path}"
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        start = max(0, target_line - window - 1)
        end = min(len(lines), target_line + window)
        
        context_lines = []
        for idx in range(start, end):
            curr_line_num = idx + 1
            # Add a clear pointer marker on the exact signature match line row
            marker = "==> " if curr_line_num == target_line else "    "
            context_lines.append(f"{marker}{curr_line_num}: {lines[idx].rstrip()}")
            
        return "\n".join(context_lines)
    except Exception as e:
        return f"[ERROR] Context extractor exception occurred: {str(e)}"

# 2. Enforce an immutable structured return schema structure using Pydantic Types
# Use a clear, serializable TypedDict instead of types.BaseModel
class SecurityTriageSchema(TypedDict):
    is_true_positive: bool
    vulnerability_type: str
    real_cvss_score: float
    real_cvss_severity: str  # Critical, High, Medium, Low
    ai_taint_explanation: str
    remediation_patch: str

def run_ai_triage():
    report_path = "reports/security_report.json"
    output_path = "reports/ai_verified_report.json"
    
    if not os.path.exists(report_path):
        print(f"[-] Local pipeline file log missing. Please execute Phase 1 first.")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        raw_findings = json.load(f)
        
    print(f"[*] Phase 2 Engine Active. Ingesting {len(raw_findings)} raw structural indicators...")
    ai_verified_findings = []
    
    # Configuration boundaries for the retry policy
    MAX_RETRIES = 5
    INITIAL_BACKOFF = 1.0
    MAX_BACKOFF_CAP = 4.0 # Prevents individual wait durations from growing excessively large
    
    # TIP: For testing out your massive 260 PyGoat triggers without hitting rate limits, 
    # you can slice this loop execution to `raw_findings[:15]` during initial debugging.
    for idx, finding in enumerate(raw_findings[:5], 1):
        file_name = finding["file_name"]
        line_num = finding["line_number"]
        suspicious_code = finding["suspicious_code"]
        
        print(f"    [{idx}/{len(raw_findings)}] Auditing: {os.path.basename(file_name)} (Line {line_num})...")
        code_context = get_code_context(file_name, line_num)
        
        prompt = f"""
        You are an automated AppSec Static Application Security Testing (SAST) Triage Engine.
        Review the following source code context where a regex engine flagged a potential execution sink.
        
        TARGET WORKSPACE LOCATION: {file_name}
        FLAGGED CODE ROW NUMBER: {line_num}
        FLAGGED SNIPPET SIGNATURE: {suspicious_code}
        
        SURROUNDING SOURCE WORKSPACE WINDOW:
        ```python
        {code_context}
        ```
        
        AUDITING PROTOCOLS:
        1. Perform semantic taint-tracking analysis. Check if source inputs are validated or parameterized.
        2. Identify False Positives: If the line is an 'import' wrapper statement, or located inside an isolated testing asset directory framework, flag 'is_true_positive' as false.
        3. Compute dynamic, real-world CVSS v3 scoring attributes based on impact risk.
        4. Draft an elite, secure, production-ready replacement script snippet to fix the vulnerability.
        """
        
        success = False
        current_backoff = INITIAL_BACKOFF
        
        # 3. Fault-Tolerant Resilient Triage Loop with strict exit parameters
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # Generate structured content with explicit time execution limits
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=SecurityTriageSchema,
                        temperature=0.1
                    ),
                    # Add a client-side timeout limit (15 seconds) so individual requests won't hang indefinitely 
                    http_options={'timeout': 15.0} 
                )
                
                ai_verdict = json.loads(response.text)
                merged_payload = {**finding, **ai_verdict}
                ai_verified_findings.append(merged_payload)
                
                success = True
                # Add a brief comfortable rest to comfortably respect free-tier rate limitations
                time.sleep(0.5)
                break  # Operational success. Break out of the retry loop.
                
            except (APIError, Exception) as e:
                # If we haven't hit the hard boundary limit, apply exponential wait tracking
                if attempt < MAX_RETRIES:
                    sleep_duration = min(MAX_BACKOFF_CAP, current_backoff)
                    print(f"        [!] Attempt {attempt}/{MAX_RETRIES} encountered an issue (Server Load/Timeout). Retrying in {sleep_duration}s...")
                    time.sleep(sleep_duration)
                    current_backoff *= 2.0  # Double the baseline backoff exponential factor
                else:
                    # Hard boundary hit. The execution strategy forces a forward move.
                    pass

        # 4. Fallback execution mechanism if all 5 retries fail
        if not success:
            print(f"    Failed to triage index {idx} after {MAX_RETRIES} strict attempts. Applying graceful fallback mapping.")
            fallback_payload = {
                **finding,
                "is_true_positive": True,
                "real_cvss_score": 5.0, # Default safe baseline rating
                "real_cvss_severity": finding.get("severity", "Medium"),
                "ai_taint_explanation": f"Skipped dynamic AI triage pass due to ongoing service load limits after {MAX_RETRIES} attempts. Original signature: {suspicious_code}",
                "remediation_patch": "# Secure parameterization patch compilation skipped due to network load constraints."
            }
            ai_verified_findings.append(fallback_payload)

    # 5. Export finalized AI Triage logs database
    with open(output_path, "w", encoding="utf-8") as out_file:
        json.dump(ai_verified_findings, out_file, indent=4)
        
    print(f"\n[✓] Phase 2 Semantic Sweep Complete!")
    print(f"[✓] Triage Report safely written to workspace layer: '{output_path}'")

if __name__ == "__main__":
    run_ai_triage()