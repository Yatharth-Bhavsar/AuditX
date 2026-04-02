import os
import datetime
import hashlib
from jinja2 import Environment, FileSystemLoader

CONSEQUENCE_MAP = {
    "R01": "Under PCI-DSS, storing unencrypted card data without a waiver can result in fines of $5,000–$100,000/month from your payment processor and potential card scheme termination.",
    "R02": "Under DPDP Act Section 8 and CERT-In Directions 2022, logging personal data without purpose creates evidence of non-compliance that regulators can use in enforcement proceedings.",
    "R03": "Transmitting personal data over unencrypted connections is a breach of DPDP Act general compliance obligations. In the event of interception, this constitutes a reportable data breach.",
    "R04": "Hardcoded secrets in source code often lead to mass data breaches. Under CERT-In Directions, exploitation of these secrets must be reported within 6 hours.",
    "R05": "Exposing APIs without authentication violates foundational security principles (OWASP). If sensitive data is exposed, DPDP Act non-compliance penalties up to ₹250 crore apply.",
    "R06": "SQL injection is a critical vulnerability. Successful exploitation grants attackers direct access to the database, triggering mandatory reporting and massive reputation damage.",
    "R07": "Without rate limiting, the system is vulnerable to credential stuffing and brute-force attacks. CERT-In requires incident reporting within 6 hours of detecting such an attack.",
    "R08": "Leaking sensitive data in URLs violates DPDP data minimization principles and risks exposure in external logs and proxies.",
    "R09": "DPDP Act Section 8(7) requires deletion of personal data once its purpose is fulfilled. Non-compliance can attract penalties up to ₹250 crore under the Act.",
    "R10": "Debug mode in production exposes internal stack traces and configuration. CERT-In requires organisations to report system compromise within 6 hours — a misconfigured system accelerates attacker access."
}

MISSING_CONSEQUENCE_MAP = {
    "MC01": "Without audit logs, incident response is impossible. CERT-In Directions mandate keeping logs for 180 days; failure to do so is a direct violation.",
    "MC02": "Indefinite data retention directly violates DPDP Act Section 8(7) and invites regulatory scrutiny and fines up to ₹250 crore.",
    "MC03": "Lack of input validation enables injection attacks and data corruption, leading to system compromise.",
    "MC04": "Unhandled errors can cascade into system outages or leak sensitive data, directly violating service-level agreements and OWASP principles.",
    "MC05": "Processing personal data without explicit consent violates DPDP Act Section 6, carrying severe penalties and halting operational capabilities."
}

REMEDIATION_ACTION_MAP = {
    "R01": "Replace the detected plaintext field with a token field. Store actual PANs in a Vault using AES-256 encryption, or entirely rely on your payment gateway's tokenization API (e.g., Stripe, Razorpay).",
    "R02": "Remove the sensitive variable from the logging statement. Use a hashing or masking function (e.g., mask_pii(aadhaar)) before routing the string to the logger.",
    "R03": "Enforce HTTPS redirect middleware (like Flask-Talisman or Express helmet) at the application level, and ensure SSL termination is configured at your load balancer.",
    "R04": "Delete the hardcoded secret. Replace it with an environment variable lookup (e.g., os.environ.get('SECRET')) and rotate the compromised credential immediately.",
    "R05": "Apply your authentication middleware or decorator to the exposed route to ensure only authenticated sessions can access the endpoint.",
    "R06": "Refactor the database query to use parameterized bindings through your ORM (e.g., SQLAlchemy) rather than unsafe string interpolation.",
    "R07": "Implement an API gateway rate limiting policy or add a library (e.g., Flask-Limiter) to restrict aggressive polling on state-changing endpoints.",
    "R08": "Move the sensitive identifier from the URL path into the secure, encrypted POST body payload.",
    "R09": "Implement a recurring background job (Cron/Celery) or DB TTL to explicitly delete or anonymize user records once they exceed their retention period.",
    "R10": "Set the framework's debug flag to False in your production environment variables."
}

TICKET_MAP = {
    "R01": {"title": "Fix: Remove plaintext card storage [PCI-DSS R01]", "tasks": ["Remove plain CC field from DB model", "Implement PA-DSS compliant vault or gateway tokenization", "Migrate/delete legacy records", "Add unit test to block plain PAN writes"]},
    "R02": {"title": "Fix: Sanitize PII from application logs [DPDP R02]", "tasks": ["Audit logging calls for the detected variable", "Implement a global log masking utility", "Ensure logs are not forwarded insecurely"]},
    "R03": {"title": "Fix: Enforce strict HTTPS [R03]", "tasks": ["Add HTTPS redirect middleware", "Verify HSTS headers are present", "Update documentation"]},
    "R04": {"title": "Fix: Remove hardcoded credential [R04]", "tasks": ["Rotate the exposed secret immediately", "Refactor code to use environment variables", "Add pre-commit hook (e.g. detect-secrets)"]},
    "R05": {"title": "Fix: Secure unauthenticated API route [R05]", "tasks": ["Add authentication decorator to route", "Write integration test for 401 Unauthorized", "Verify token validation logic"]},
    "R06": {"title": "Fix: Parameterize raw SQL queries [R06]", "tasks": ["Refactor raw SQL strings to ORM objects or parameterized queries", "Run SAST tool to confirm no other concatenation exists"]},
    "R07": {"title": "Fix: Add Rate Limiting to mutable endpoints [R07]", "tasks": ["Install rate limiting dependency", "Apply limit (e.g., 5 req/min) to POST/PUT endpoints", "Ensure 429 Too Many Requests response is handled by frontend"]},
    "R08": {"title": "Fix: Remove PII from URL path [R08]", "tasks": ["Change route method from GET to POST if necessary", "Read sensitive identifier from request body instead of URL params", "Update calling API clients"]},
    "R09": {"title": "Fix: Implement Data Retention job [DPDP R09]", "tasks": ["Add 'last_active' or similar tracking to user model", "Write background script to hard-delete or anonymize stale records", "Schedule cron job"]},
    "R10": {"title": "Fix: Disable Debug Mode [R10]", "tasks": ["Change 'debug=True' to 'debug=False' in config", "Ensure production environment explicitly sets this flag", "Verify error pages do not leak stack traces"]}
}

VERIFICATION_MAP = {
    "R01": "Run AuditX again after the fix and show a report where R01 no longer appears. Request a screenshot of the payment gateway's tokenization active mappings.",
    "R02": "Re-run AuditX. Provide an extract of the production log file showing the variable successfully masked (e.g., 'Aadhaar: ****1234').",
    "R03": "Attempt an HTTP request to the endpoint via cURL and verify it receives a 301/302 redirect to the HTTPS equivalent.",
    "R04": "Review the pull request to ensure the hardcoded string is removed and the rotation log matches the Jira ticket date.",
    "R05": "Attempt to curl the endpoint without a bearer token and verify it returns a 401 Unauthorized status.",
    "R06": "Review the pull request to ensure SQLAlchemy/ORM is used correctly with bound parameters.",
    "R07": "Run a simple load test script sending 100 requests to the endpoint and verify the server correctly blocks later requests with HTTP 429.",
    "R08": "Check the web server access logs in staging to confirm the PII no longer appears in request query strings.",
    "R09": "Examine the cron scheduler or Celery beat configuration on the server to prove the deletion job is active.",
    "R10": "Trigger an intentional 500 error on the staging server and verify a generic error page is returned rather than a stack trace."
}

REGULATION_CONTEXT_MAP = {
    "DPDP Act Section 8": {
        "name": "Digital Personal Data Protection Act 2023, Section 8",
        "enforcer": "Data Protection Board of India (MeitY)",
        "requirement": "Data fiduciaries must implement reasonable security safeguards to protect personal data.",
        "penalty": "₹250 crore per instance of non-compliance.",
        "url": "https://www.meity.gov.in/data-protection-framework"
    },
    "DPDP Act Section 8(7)": {
        "name": "Digital Personal Data Protection Act 2023, Section 8(7)",
        "enforcer": "Data Protection Board of India (MeitY)",
        "requirement": "Personal data must be erased once the purpose for which it was collected is no longer being served.",
        "penalty": "₹250 crore.",
        "url": "https://www.meity.gov.in/data-protection-framework"
    },
    "DPDP Act Section 6": {
        "name": "Digital Personal Data Protection Act 2023, Section 6",
        "enforcer": "Data Protection Board of India (MeitY)",
        "requirement": "Personal data can only be processed with free, specific, informed, unconditional and unambiguous consent.",
        "penalty": "₹250 crore.",
        "url": "https://www.meity.gov.in/data-protection-framework"
    },
    "PCI-DSS Req 3.4": {
        "name": "Payment Card Industry Data Security Standard v4.0, Requirement 3.4",
        "enforcer": "PCI Security Standards Council / your acquiring bank",
        "requirement": "Primary account numbers (PANs) must be rendered unreadable using strong cryptography wherever stored.",
        "penalty": "$5,000–$100,000/month + potential card scheme ban.",
        "url": "https://www.pcisecuritystandards.org/document_library/"
    },
    "RBI Tokenization Circular 2022": {
        "name": "RBI Circular on Card-on-File Tokenisation (CoFT)",
        "enforcer": "Reserve Bank of India",
        "requirement": "No entity in the payment chain (except card networks and issuers) may store actual card data.",
        "penalty": "RBI can revoke payment aggregator licence.",
        "url": "https://www.rbi.org.in/Scripts/BS_CircularIndexDisplay.aspx"
    },
    "CERT-In Directions 2022": {
        "name": "CERT-In Directions under Section 70B of IT Act 2000",
        "enforcer": "Indian Computer Emergency Response Team (CERT-In)",
        "requirement": "Organisations must report cyber incidents within 6 hours of detection, and retain logs for 180 days.",
        "penalty": "Imprisonment up to 1 year or fine under IT Act.",
        "url": "https://www.cert-in.org.in/"
    },
    "CERT-In": {
        "name": "CERT-In Directions under Section 70B of IT Act 2000",
        "enforcer": "Indian Computer Emergency Response Team (CERT-In)",
        "requirement": "Organisations must report cyber incidents within 6 hours of detection, and retain logs for 180 days.",
        "penalty": "Imprisonment up to 1 year or fine under IT Act.",
        "url": "https://www.cert-in.org.in/"
    },
    "OWASP A03": {
        "name": "OWASP Top 10 2021 — A03: Injection",
        "enforcer": "Not legally binding — industry best practice standard",
        "requirement": "User-supplied data must not be sent to an interpreter as part of a command or query.",
        "penalty": "None (Best Practice).",
        "url": "https://owasp.org/Top10/A03_2021-Injection/"
    },
    "OWASP A04": {
        "name": "OWASP Top 10 2021 — A04: Insecure Design",
        "enforcer": "Not legally binding — industry best practice standard",
        "requirement": "Systems must be designed with security controls from the outset, not patched in after deployment.",
        "penalty": "None (Best Practice).",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"
    },
    "OWASP A05": {
        "name": "OWASP Top 10 2021 — A05: Security Misconfiguration",
        "enforcer": "Not legally binding — referenced by CERT-In",
        "requirement": "All security configurations must be hardened. Debug and default settings must be disabled in production.",
        "penalty": "None (Best Practice).",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    },
    "OWASP A07": {
        "name": "OWASP Top 10 2021 — A07: Identification and Authentication Failures",
        "enforcer": "Not legally binding — referenced by CERT-In",
        "requirement": "Confirmation of the user's identity, authentication, and session management is critical.",
        "penalty": "None (Best Practice).",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    },
    "DPDP Act General Compliance": {
         "name": "Digital Personal Data Protection Act 2023, General Obligations",
         "enforcer": "Data Protection Board of India (MeitY)",
         "requirement": "Personal data must be protected using reasonable security safeguards to prevent data breach.",
         "penalty": "₹250 crore.",
         "url": "https://www.meity.gov.in/data-protection-framework"
    },
    "DPDP Act": {
         "name": "Digital Personal Data Protection Act 2023, General Obligations",
         "enforcer": "Data Protection Board of India (MeitY)",
         "requirement": "Personal data must be protected using reasonable security safeguards to prevent data breach.",
         "penalty": "₹250 crore.",
         "url": "https://www.meity.gov.in/data-protection-framework"
    },
    "RBI": {
        "name": "RBI General Master Directions",
        "enforcer": "Reserve Bank of India",
        "requirement": "Regulated entities must have a robust security framework covering APIs and data access.",
        "penalty": "Licence revocation and operational fines.",
        "url": "https://rbi.org.in/"
    }
}


class ReportBuilder:
    def __init__(self):
        templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(templates_dir))
        self.template = self.env.get_template('report.html')

    def build_report(self, findings, summary_obj, profile, duration, output_path, score_data, top_risk_sentence, missing_controls, custom_policy_results=None, custom_policy_score=None, owasp_coverage=None, cve_findings=None):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_dir = os.path.abspath(output_path.replace('auditx_report_', '').replace('.html', '')) # Approximate source
        
        # Unique Report ID
        hash_input = f"{target_dir}_{timestamp}".encode('utf-8')
        report_hash = hashlib.md5(hash_input).hexdigest()[:6].upper()
        report_id = f"AUDITX-{datetime.datetime.now().strftime('%Y%m%d')}-{report_hash}"

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        cited_regulations_keys = set()
        
        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            
            rule_id = f.get('rule_id', '')
            if rule_id in CONSEQUENCE_MAP:
                f['consequence'] = CONSEQUENCE_MAP[rule_id]
            else:
                f['consequence'] = "This finding may indicate a general security weakness. Remediation is advised according to standard security practices."
                
            if rule_id in REMEDIATION_ACTION_MAP:
                f['action'] = REMEDIATION_ACTION_MAP[rule_id]
            else:
                f['action'] = "Review the affected code block and apply necessary security constraints."
                
            if rule_id in TICKET_MAP:
                f['ticket'] = TICKET_MAP[rule_id]
            else:
                f['ticket'] = {
                    "title": f"Fix: {f.get('title', 'Security Vulnerability')}",
                    "tasks": ["Investigate the root cause in the affected file", "Implement patch and peer-review", "Add test cases covering this flaw"]
                }
                
            if rule_id in VERIFICATION_MAP:
                f['verification'] = VERIFICATION_MAP[rule_id]
            else:
                f['verification'] = "Ensure regression tests pass and re-run AuditX scanner."
                
            if 'what_was_found' not in f:
                f['what_was_found'] = "Pattern identified matching generic vulnerability threshold."
                
            # Collect regulations
            for reg in f.get('regulation', []):
                cited_regulations_keys.add(reg)

        for mc in missing_controls:
            mc_id = mc.get('control_id', '')
            if mc_id in MISSING_CONSEQUENCE_MAP:
                mc['consequence'] = MISSING_CONSEQUENCE_MAP[mc_id]
            reg = mc.get('regulation', '')
            if reg:
                # Some are composed like "OWASP A03 / DPDP"
                parts = [p.strip() for p in reg.split('/')]
                for p in parts:
                    cited_regulations_keys.add(p)
                    

        days = (severity_counts['CRITICAL'] * 2.0) + (severity_counts['HIGH'] * 1.0) + (severity_counts['MEDIUM'] * 0.5)
        import math
        days_rounded = math.ceil(days)
        
        metadata = {
            'version': "2.0.0",
            'directory': target_dir, 
            'profile': profile,
            'duration': f"{duration:.1f}",
            'timestamp': timestamp,
            'effort_days': f"{days_rounded} engineering days"
        }
        
        if cve_findings is None:
             cve_findings = []
             
        for cve in cve_findings:
             cve['consequence'] = f"A known exploitable vulnerability in a production dependency constitutes a preventable security failure. Under CERT-In Directions 2022, exploitation must be reported within 6 hours."
             cve['action'] = f"Bump version in requirements.txt or package.json."
             cve['verification'] = f"Run AuditX again post build."
        
        if owasp_coverage is None:
             owasp_coverage = {}
             
        # Resolve cited regulations dictionaries
        cited_regs_blocks = []
        for key in cited_regulations_keys:
            if key in REGULATION_CONTEXT_MAP:
                cited_regs_blocks.append(REGULATION_CONTEXT_MAP[key])
                
        # Determine passing items from summary_obj flags
        passing_items = []
        if getattr(summary_obj, 'auth_present', False):
            passing_items.append({"title": "Authentication present on scanned routes", "verification": "Re-run AuditX after any authentication changes."})
        if getattr(summary_obj, 'logging_present', False):
            passing_items.append({"title": "Application logging configured", "verification": "Ensure log storage satisfies 180 day retention."})
        if getattr(summary_obj, 'https_enforced', False):
            passing_items.append({"title": "HTTPS redirect constraints present", "verification": "Ensure load balancer also forces TLS."})
        
        html_content = self.template.render(
            findings=findings,
            summary=severity_counts,
            metadata=metadata,
            report_id=report_id,
            score_data=score_data,
            top_risk_sentence=top_risk_sentence,
            missing_controls=missing_controls,
            custom_policy_results=custom_policy_results,
            custom_policy_score=custom_policy_score,
            owasp_coverage=owasp_coverage,
            cve_findings=cve_findings,
            cited_regulations=cited_regs_blocks,
            passing_items=passing_items
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path
