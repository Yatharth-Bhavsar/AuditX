"""
Local Vulnerability Database for AuditX.

Detects CVEs via static inspection of dependencies.
"""
import os
import re

KNOWN_VULNS = {
    "log4j": {
        "cve": "CVE-2021-44228",
        "title": "Log4Shell - Remote Code Execution",
        "severity": "CRITICAL",
        "owasp": "A06: Vulnerable Components"
    },
    "werkzeug==2.2.2": { # Typical vulnerable Flask dependency
        "cve": "CVE-2023-25577",
        "title": "Werkzeug Denial of Service",
        "severity": "HIGH",
        "owasp": "A06: Vulnerable Components"
    },
    "django<4.0.0": {
        "cve": "CVE-2022-22818", 
        "title": "Django Template Injection",
        "severity": "HIGH",
        "owasp": "A06: Vulnerable Components"
    },
    "requests<2.31.0": {
        "cve": "CVE-2023-32681",
        "title": "Requests Proxy Leak",
        "severity": "MEDIUM",
        "owasp": "A06: Vulnerable Components"
    }
}

def scan_dependencies(target_dir):
    """Scans requirements.txt and package.json for known vulnerabilities."""
    findings = []
    
    # Check Python requirements
    req_path = os.path.join(target_dir, "requirements.txt")
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            
            # Simple substring mapping for the demo-strong CVEs
            if "werkzeug==2.2.2" in content:
                findings.append(_build_cve_finding("werkzeug==2.2.2", "requirements.txt"))
            elif "requests==" in content:
                # Naive regex for demo purposes
                findings.append(_build_cve_finding("requests<2.31.0", "requirements.txt"))
                
    # Check Node package.json
    pkg_path = os.path.join(target_dir, "package.json")
    if os.path.exists(pkg_path):
        with open(pkg_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            if "log4j" in content or "log4js" in content: # Simulating Log4j presence in js config or java dependencies mapping
                findings.append(_build_cve_finding("log4j", "package.json"))
                
    return findings

def _build_cve_finding(vuln_key, location):
    vuln = KNOWN_VULNS.get(vuln_key)
    if not vuln:
        return None
        
    return {
        "rule_id": vuln["cve"].replace("-", ""),
        "title": f"Known Vulnerable Dependency ({vuln['title']})",
        "cve": vuln["cve"],
        "severity": vuln["severity"],
        "owasp": vuln["owasp"],
        "regulation": ["OWASP A06", "CERT-In"],
        "location": location,
        "evidence_type": "DIRECT",
        "evidence_source": "Dependency Scan",
        "confidence": "HIGH",
        "behavior_observed": "",
        "legal_obligation": "",
        "remediation_action": "",
        "remediation_priority": 0,
        "remediation_effort": "LOW"
    }
