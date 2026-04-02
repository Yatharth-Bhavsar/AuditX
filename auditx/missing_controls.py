"""
Missing Controls Engine for AuditX

Evaluates expected absence of controls in AST metadata.
"""
def check_missing_controls(metadata):
    controls = []
    
    # MC01 — Audit Logging
    if not metadata.get('logging_present', False):
        controls.append({
            "control_id": "MC01",
            "control": "Audit Logging",
            "regulation": "CERT-In Directions 2022",
            "why_it_matters": "System events, logins, and anomalies cannot be properly investigated without centralized logs.",
            "evidence_sought": "logger.info() or logging middleware on key routes.",
            "risk": "HIGH",
            "ask_developer": "Implement centralized logging for all critical system events, user logins, and operational anomalies. Ensure the log stream persists across application restarts to maintain an inviolable audit trail."
        })
        
    # MC02 — Data Retention Policy
    pii = metadata.get('sensitive_fields', [])
    if pii and not metadata.get('retention_logic', False):
        controls.append({
            "control_id": "MC02",
            "control": "Data Retention Policy",
            "regulation": "DPDP Act Section 8(7)",
            "why_it_matters": "Personal data must not be stored indefinitely once its business purpose is fulfilled.",
            "evidence_sought": "Scheduled deletion jobs, TTL fields, or clear data erasure endpoints.",
            "risk": "HIGH",
            "ask_developer": "Develop an automated data lifecycle job or integrate TTL (Time To Live) parameters on sensitive database records. Guarantee that user data collected during registration is purged securely when the account is deactivated or hits the inactivity threshold."
        })
        
    # MC03 — Input Validation
    if not metadata.get('input_validation_present', False):
        controls.append({
            "control_id": "MC03",
            "control": "Input Validation",
            "regulation": "OWASP A03 / DPDP",
            "why_it_matters": "Unvalidated inputs expose the system to injection attacks and degraded data integrity.",
            "evidence_sought": "Pydantic, marshmallow, or express-validator schemas on API routes.",
            "risk": "MEDIUM",
            "ask_developer": "Introduce a rigorous input validation schema (e.g., Pydantic or Marshmallow) on all API entry points. Deny malformed requests at the edge before they penetrate deeper system logic."
        })
        
    # MC04 — Error Handling
    if not metadata.get('error_handling_present', False):
        controls.append({
            "control_id": "MC04",
            "control": "Global Error Handling",
            "regulation": "CERT-In / OWASP A05",
            "why_it_matters": "Unhandled errors can crash the system or leak internal stack traces to attackers.",
            "evidence_sought": "try/except blocks surrounding core route logic or global error middleware.",
            "risk": "MEDIUM",
            "ask_developer": "Deploy a strict global error handler and overarching try/except middleware. Shield users from internal stack traces to preemptively mitigate application reconnaissance."
        })
        
    # MC05 — Consent Mechanism
    if pii and not metadata.get('consent_mechanism', False):
        controls.append({
            "control_id": "MC05",
            "control": "Consent Mechanism",
            "regulation": "DPDP Act Section 6",
            "why_it_matters": "Processing personal data (like Aadhaar or religion) requires explicit user consent.",
            "evidence_sought": "Mentions of consent, opt-in, or terms-agreement parameters in registration routes.",
            "risk": "HIGH",
            "ask_developer": "Engineer an explicit opt-in mechanism into the onboarding flow for handling personal identifiers. Record the exact cryptographic timestamp of user consent alongside the data."
        })
        
    return controls
