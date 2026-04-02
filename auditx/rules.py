"""
Static Rules Engine for AuditX

Evaluates AST metadata deterministically to uncover security gaps.
"""
def check_plaintext_card(metadata):
    """R01 - Plaintext PAN/Card Storage
    Detect: DB field named card_number, pan, cc_number, card_no with no encryption.
    """
    card_fields = ['card_number', 'pan', 'cc_number', 'card_no']
    for field in metadata.get('db_fields', []):
        if any(cf in field.lower() for cf in card_fields):
            evidence = f"Field '{field}' detected in models.py stored as a plain string type. No encryption library import (e.g. cryptography, fernet, pycryptodome) found in the same file or its write path."
            return {
                "what_was_found": evidence,
                "rule_id": "R01",
                "title": "Plaintext Card Number Storage",
                "severity": "CRITICAL",
                "regulation": ["PCI-DSS Req 3.4", "RBI Tokenization Circular 2022"],
                "location": "models.py", 
                "evidence_type": "DIRECT",
                "evidence_source": "AST",
                "confidence": "HIGH",
                "behavior_observed": "",
                "legal_obligation": "",
                "remediation_action": "",
                "remediation_priority": 0,
                "remediation_effort": "HIGH"
            }
    return None

def check_pii_logging(metadata):
    """R02 - PII Field in Logging"""
    pii_keywords = ['aadhaar', 'pan', 'password', 'dob', 'card_number']
    logged = metadata.get('pii_logged', [])
    found = [p for p in logged if any(kw in p.lower() for kw in pii_keywords)]
    if found:
        evidence = f"Logging statement detected capturing sensitive variable(s): {', '.join(found)}. No masking or redaction logic observed before the logging sink."
        return {
                "what_was_found": evidence,
            "rule_id": "R02",
            "title": "PII Field in Logging",
            "severity": "CRITICAL",
            "regulation": ["DPDP Act Section 8", "CERT-In Directions 2022"],
            "location": "app logging",
            "evidence_type": "DIRECT",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "LOW"
        }
    return None

def check_no_https(metadata):
    """R03 - No HTTPS Enforcement"""
    if not metadata.get('https_enforced', False):
        evidence = "Flask application initialized with no ssl_context parameter and no HTTPS redirect middleware detected."
        return {
                "what_was_found": evidence,
            "rule_id": "R03",
            "title": "No HTTPS Enforcement",
            "severity": "HIGH",
            "regulation": ["DPDP Act General Compliance"],
            "location": "app configuration",
            "evidence_type": "DIRECT",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "MEDIUM"
        }
    return None

def check_hardcoded_secrets(metadata):
    """R04 - Hardcoded Secrets"""
    secrets = metadata.get('hardcoded_secrets', [])
    if secrets:
        evidence = f"Hardcoded secret assignment detected: '{secrets[0]}'. Secrets should be injected via environment variables or a secrets manager, never committed to source code."
        return {
                "what_was_found": evidence,
            "rule_id": "R04",
            "title": "Hardcoded Secrets Detected",
            "severity": "CRITICAL",
            "regulation": ["OWASP A07", "CERT-In"],
            "location": f"line matching: {secrets[0]}",
            "evidence_type": "DIRECT",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "LOW"
        }
    return None

def check_unauth_route(metadata):
    """R05 - Unauthenticated Route"""
    if not metadata.get('auth_present', False) and len(metadata.get('routes', [])) > 0:
        routes = [r.get('path', '/api/*') for r in metadata.get('routes', [])]
        first_route = routes[0] if routes else '/api/*'
        evidence = f"No global authentication middleware or decorators (e.g., @login_required, JWT checks) detected on API routes (e.g., {first_route})."
        return {
                "what_was_found": evidence,
            "rule_id": "R05",
            "title": "Unauthenticated Route Detected",
            "severity": "HIGH",
            "regulation": ["DPDP Act", "RBI"],
            "location": "api routes",
            "evidence_type": "INDIRECT",
            "evidence_source": "AST",
            "confidence": "MEDIUM",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "MEDIUM"
        }
    return None

def check_sql_injection(metadata):
    """R06 - SQL String Concatenation"""
    if metadata.get('sql_injection_risk', False):
        evidence = "Direct string concatenation or formatting detected in SQL execution block. Query parameters are not using safe parameterized bindings, creating an injection risk."
        return {
                "what_was_found": evidence,
            "rule_id": "R06",
            "title": "SQL String Concatenation (Injection Risk)",
            "severity": "HIGH",
            "regulation": ["OWASP A03"],
            "location": "database execution",
            "evidence_type": "DIRECT",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "MEDIUM"
        }
    return None

def check_rate_limiting(metadata):
    """R07 - No Rate Limiting"""
    routes = metadata.get('routes', [])
    if any(r.get('method', '') in ['POST', 'PUT'] for r in routes) and not metadata.get('rate_limiting', False):
        evidence = "State-changing API routes (POST/PUT) found, but no rate limiting middleware (e.g., Flask-Limiter, express-rate-limit) or throttle decorators detected."
        return {
                "what_was_found": evidence,
            "rule_id": "R07",
            "title": "No Rate Limiting",
            "severity": "MEDIUM",
            "regulation": ["OWASP A04", "CERT-In"],
            "location": "api routes",
            "evidence_type": "MISSING",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "LOW"
        }
    return None

def check_sensitive_url(metadata):
    """R08 - Sensitive Field in URL Path"""
    sensitive_keywords = ['aadhaar', 'pan', 'card', 'otp']
    paths = [r['path'].lower() for r in metadata.get('routes', [])]
    sensitive_paths = [path for path in paths if any(kw in path for kw in sensitive_keywords)]
    if sensitive_paths:
        evidence = f"Sensitive identifier detected in URL path parameters: {sensitive_paths[0]}. This can leak PII into browser history, proxies, and web server access logs."
        return {
                "what_was_found": evidence,
            "rule_id": "R08",
            "title": "Sensitive Field in URL Path",
            "severity": "HIGH",
            "regulation": ["DPDP Act Section 8"],
            "location": "api routes",
            "evidence_type": "DIRECT",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "LOW"
        }
    return None

def check_retention_policy(metadata):
    """R09 - Missing Retention / Deletion Logic"""
    pii = metadata.get('sensitive_fields', [])
    if pii and not metadata.get('retention_logic', False):
        evidence = f"Database model contains sensitive fields: {', '.join(pii)}. No scheduled deletion job, TTL column, or delete() endpoint found anywhere in the scanned codebase."
        return {
                "what_was_found": evidence,
            "rule_id": "R09",
            "title": "Missing Retention / Deletion Logic",
            "severity": "HIGH",
            "regulation": ["DPDP Act Section 8(7)"],
            "location": "database models",
            "evidence_type": "MISSING",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "MEDIUM"
        }
    return None

def check_debug_mode(metadata):
    """R10 - Debug Mode Enabled"""
    if metadata.get('debug_mode', False):
        evidence = "Configuration initialization observed with 'debug=True' or equivalent environment variable default. Production execution in this state leaks internal stack traces."
        return {
                "what_was_found": evidence,
            "rule_id": "R10",
            "title": "Debug Mode Enabled in Production",
            "severity": "MEDIUM",
            "regulation": ["OWASP A05", "CERT-In"],
            "location": "app configuration",
            "evidence_type": "DIRECT",
            "evidence_source": "AST",
            "confidence": "HIGH",
            "behavior_observed": "",
            "legal_obligation": "",
            "remediation_action": "",
            "remediation_priority": 0,
            "remediation_effort": "LOW"
        }
    return None

def evaluate_rules(metadata):
    findings = []
    rules = [
        check_plaintext_card, check_pii_logging, check_no_https, check_hardcoded_secrets,
        check_unauth_route, check_sql_injection, check_rate_limiting, check_sensitive_url,
        check_retention_policy, check_debug_mode
    ]
    for rule in rules:
        res = rule(metadata)
        if res:
            findings.append(res)
    return findings
