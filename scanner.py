# scanner.py
import os
import json
import sys
import ast
import re

# 1. FIX PATHS: Locate where rules.py lives (inside the scanner folder)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_SUBDIR = os.path.join(SCRIPT_DIR, "scanner")

# Inject both paths to ensure seamless cross-folder importing
for path in [SCRIPT_DIR, SCANNER_SUBDIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

REPORT_PATH = "reports/raw_sast_report.json"

SIGNATURE_RULES = {
    "SQLi": {
        "vulnerability_type": "SQL Injection (SQLi)",
        "severity": "HIGH",
        "explanation": "Dynamic variables, f-strings, or string concatenations compiled directly inside a database query execution payload."
    },
    "XSS": {
        "vulnerability_type": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "explanation": "Unescaped HTML inputs compiled via Flask rendering wrappers expose the client session context."
    },
    "CmdInj": {
        "vulnerability_type": "Command Injection",
        "severity": "CRITICAL",
        "explanation": "Direct OS command execution handling with string formatting opens unauthorized system terminal privileges."
    }
}

# 2. IMPORT CHECK: Attempt to bind with your rules engine sub-asset
try:
    import rules
    run_local_rules = rules.run_local_rules
    print("[+] SUCCESS: Successfully bound to scanner/rules.py engine component!")
except ImportError as e:
    print(f"[!] PATH ERROR: Could not find rules.py. Checked paths: {sys.path}")
    print(f"[!] Error details: {e}")
    def run_local_rules(file_path):
        return []

class SystemSyntaxAuditor(ast.NodeVisitor):
    def __init__(self, file_path, lines):
        self.file_path = file_path
        self.lines = lines
        self.findings = []
        self.local_tainted_vars = set()

    def _get_line(self, line_num):
        return self.lines[line_num - 1].strip() if 1 <= line_num <= len(self.lines) else "Unknown Context"

    def visit_Assign(self, node):
        if isinstance(node.value, (ast.JoinedStr, ast.BinOp, ast.Call)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.local_tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        is_dangerous_arg = False
        if node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.JoinedStr, ast.BinOp, ast.Call)):
                is_dangerous_arg = True
            elif isinstance(first_arg, ast.Name) and first_arg.id in self.local_tainted_vars:
                is_dangerous_arg = True

        if is_dangerous_arg:
            if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                meta = SIGNATURE_RULES["SQLi"]
                self.findings.append({**meta, "file_name": self.file_path, "line_number": node.lineno, "suspicious_code": self._get_line(node.lineno)})
            
            elif (isinstance(node.func, ast.Name) and node.func.id in ["render_template_string", "Markup"]) or \
                 (isinstance(node.func, ast.Attribute) and node.func.attr in ["render_template_string", "Markup"]):
                meta = SIGNATURE_RULES["XSS"]
                self.findings.append({**meta, "file_name": self.file_path, "line_number": node.lineno, "suspicious_code": self._get_line(node.lineno)})

            elif isinstance(node.func, ast.Attribute) and node.func.attr in ["system", "Popen", "run"]:
                meta = SIGNATURE_RULES["CmdInj"]
                self.findings.append({**meta, "file_name": self.file_path, "line_number": node.lineno, "suspicious_code": self._get_line(node.lineno)})

        self.generic_visit(node)

# Update the main function definition in scanner.py
def run_phase1_pipeline(target_path: str, output_file_path: str = "reports/raw_sast_report.json"):
    print("   AI-ASSISTED APPSEC SCANNER - HYBRID ENGINE ACTIVE")
    files_to_scan = []
    
    if os.path.isfile(target_path) and target_path.endswith('.py'):
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith('.py'):
                    files_to_scan.append(os.path.join(root, file))

    all_raw_findings = []
    for current_file in files_to_scan:
        try:
            with open(current_file, "r", encoding="utf-8", errors="ignore") as f:
                raw_code = f.read()
            lines = raw_code.splitlines()
            
            extended_alerts = run_local_rules(current_file)
            for alert in extended_alerts:
                all_raw_findings.append({
                    "vulnerability_type": alert.get("vulnerability_type"),
                    "severity": alert.get("severity", "Medium"),
                    "file_name": current_file,
                    "line_number": alert.get("line_number"),
                    "suspicious_code": alert.get("suspicious_code"),
                    "explanation": alert.get("explanation"),
                    "recommended_fix": "Pending Phase 2 AI verification analysis."
                })
            
            try:
                tree = ast.parse(raw_code, filename=current_file)
                visitor = SystemSyntaxAuditor(current_file, lines)
                visitor.visit(tree)
                all_raw_findings.extend(visitor.findings)
                print(f"    [+] Audited: {current_file} (Rules Found: {len(extended_alerts)} | AST Found: {len(visitor.findings)})")
            except SyntaxError:
                print(f"    [!] Parser error on AST tracking for {current_file}.")
                
        except Exception as e:
            print(f"    [-] Access violation on asset {current_file}: {e}")

    for finding in all_raw_findings:
        finding["origin"] = "appsec"

    # 🟢 CHANGED: Create directory for the dynamic file path parameter
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    
    existing_findings = []
    if os.path.exists(output_file_path):
        try:
            with open(output_file_path, "r", encoding="utf-8") as jf:
                loaded_data = json.load(jf)
                if isinstance(loaded_data, list):
                    existing_findings = [item for item in loaded_data if item.get("origin") != "appsec"]
        except Exception as e:
            print(f"[-] Warning reading master ledger: {e}")

    combined_findings = existing_findings + all_raw_findings
    
    # 🟢 CHANGED: Save directly to the dynamic path argument
    with open(output_file_path, "w", encoding="utf-8") as jf:
        json.dump(combined_findings, jf, indent=4)
    print(f"[SUCCESS] AppSec Scanner finalized. Saved {len(combined_findings)} total entries to ledger.")


# Update the bottom execution entry block of scanner.py
if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "./src"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "reports/raw_sast_report.json"
    
    # 🟢 CHANGED: Pass output_file into your pipeline runner execution
    run_phase1_pipeline(target_dir, output_file)