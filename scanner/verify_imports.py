# verify_imports.py
import sys

print("[*] Commencing environment dependency check...")

try:
    # --- Check Python Standard Library Modules ---
    import os
    import re
    import subprocess
    import html
    import hashlib
    from urllib.parse import urlparse
    print("[+] Core built-in modules: OK")

    # --- Check Third-Party Installed Dependencies ---
    from flask import Flask, request
    print("[+] Flask environment module: OK")
    
    import requests
    print("[+] Requests network module: OK")
    
    import bcrypt
    print("[+] Bcrypt cryptographic library: OK")
    
    from dotenv import load_dotenv
    print("[+] Python-Dotenv configuration module: OK")

    print("\n[✓] EXCELLENT! All dependencies are fully verified and operational.")
    print("[*] Your system is perfectly prepared to execute and process all 40 sample files.")

except ImportError as e:
    print(f"\n[X] CRITICAL CONFIGURATION ERROR: Missing dependency detected: {e}")
    print("[*] Please run the following repair command in your terminal:")
    print("    python -m pip install flask requests bcrypt python-dotenv")
    sys.exit(1)