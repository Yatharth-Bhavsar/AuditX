"""
OWASP Mapping Engine for AuditX

Maps specific AuditX rules (R03, R04, etc.), Taint, and CVE findings to OWASP Top 10 categories.
"""

OWASP_MAPPING = {
    "R05": "A01: Broken Access Control",
    "R06": "A03: Injection",
    "R04": "A02: Cryptographic Failures",
    "R03": "A05: Security Misconfiguration",
    "R07": "A04: Insecure Design",
    "R10": "A05: Security Misconfiguration",
    "TAINT": "A03: Injection",
    "CVE": "A06: Vulnerable Components"
}

def enrich_with_owasp(findings):
    """Adds OWASP mappings to a list of findings."""
    for finding in findings:
        rule_prefix = finding.get('rule_id', '')[:4]
        if rule_prefix.startswith('R'):
            rule_id = finding.get('rule_id')
            if rule_id in OWASP_MAPPING:
                finding['owasp'] = OWASP_MAPPING[rule_id]
        elif rule_prefix.startswith('TAIN'):
            finding['owasp'] = OWASP_MAPPING['TAINT']
        elif rule_prefix.startswith('CVE'):
            finding['owasp'] = OWASP_MAPPING['CVE']
            
    return findings

def get_owasp_coverage(findings):
    """Returns a PASS/FAIL coverage dict for OWASP categories based on findings."""
    coverage = {
        "A01: Broken Access Control": "PASS",
        "A02: Cryptographic Failures": "PASS",
        "A03: Injection": "PASS",
        "A04: Insecure Design": "PASS",
        "A05: Security Misconfiguration": "PASS",
        "A06: Vulnerable Components": "PASS"
    }
    
    for f in findings:
        owasp = f.get('owasp')
        if owasp and owasp in coverage:
            coverage[owasp] = "FAIL"
            
    return coverage
