import re

RULES = {
    "SQL Injection": {
        # Broadened: Flags ANY execute/executemany call that passes a variable query name, 
        # or inline string formatting/concatenation symbols.
        "pattern": re.compile(r"\.execute\(\s*[A-Za-z0-9_]+\s*\)|\.execute\(.*(\+|f[\"']|\.format|%|SELECT)", re.IGNORECASE),
        "severity": "High",
        "description": "Database execution driver invoked with a dynamic variable parameter or raw string formatting."
    },
    "Command Injection": {
        # Broadened: Catches os.system, os.popen, or ANY subprocess tool processing dynamic variables
        "pattern": re.compile(r"os\.(system|popen)\(|subprocess\.(Popen|run|call|check_output|getoutput)\(", re.IGNORECASE),
        "severity": "High",
        "description": "Operating system command utility executed. Vulnerable if parameter strings contain unsanitized inputs."
    },
"Hardcoded Secrets": {
        # Handles standalone variables, dictionary string keys, and configurations perfectly
        "pattern": re.compile(r"['\"]?(api_key|secret|password|passwd|token|aws_|stripe|jwt)['\"]?\s*[:=]\s*['\"].*?['\"]", re.IGNORECASE),
        "severity": "Critical",
        "description": "Plaintext configuration credential or authentication token discovered inside code structures."
    },
    "Cross-Site Scripting (XSS)": {
        # Captures strings returning formatted variables wrapped around HTML angle brackets or tags
        "pattern": re.compile(r"return\s+.*f?[\"'].*<.*>.*[\"']|html|render_template|<div>|<h1>", re.IGNORECASE),
        "severity": "Medium",
        "description": "HTML or UI string layout constructed dynamically. Risk of untrusted script reflection injection."
    },
    "Path Traversal": {
        # Flags ANY use of open() that handles dynamic variables or string concatenation instead of a static safe string
        "pattern": re.compile(r"open\(\s*[A-Za-z0-9_]+\s*,\s*['\"][rwa]|\bopen\([^,]*(\+|f[\"']|\.format)", re.IGNORECASE),
        "severity": "Medium",
        "description": "File descriptor stream handling initiated dynamically using dynamic variables or concatenation operations."
    },
    "Server-Side Request Forgery (SSRF)": {
        # Catches any outbound requests parsing data streams via external endpoints
        "pattern": re.compile(r"requests\.(get|post|put|delete|head)\(", re.IGNORECASE),
        "severity": "Medium",
        "description": "Outbound HTTP transaction invoked. Untrusted destination parameters can lead to internal proxy pivots."
    },
    "Weak Cryptography": {
        # Detects legacy hashing references
        "pattern": re.compile(r"hashlib\.(md5|sha1)\(", re.IGNORECASE),
        "severity": "Medium",
        "description": "Use of cryptographically broken or fast legacy hashing algorithms (MD5/SHA1)."
    }
}

def run_local_rules(file_path: str) -> list:
    """
    Reads a target file line by line and benchmarks it against the regex ruleset catalog.
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("#"):
                continue
                
            for vuln_type, rule in RULES.items():
                if rule["pattern"].search(stripped_line):
                    findings.append({
                        "vulnerability_type": vuln_type,
                        "severity": rule["severity"],
                        "file_name": file_path,
                        "line_number": line_num,
                        "suspicious_code": stripped_line,
                        "explanation": rule["description"]
                    })
    except Exception as e:
        print(f"[X] Operational error attempting to extract analysis from {file_path}: {str(e)}")
        
    return findings