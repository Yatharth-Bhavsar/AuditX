"""
Matches extracted custom policy controls against AST metadata.
All matching is deterministic — no LLM involvement at this stage.
"""

def match_controls(controls: list, metadata: dict) -> list:
    results = []
    
    for control in controls:
        ctype = control.get('check_type', 'presence')
        keys = control.get('metadata_keys', [])
        status = "UNKNOWN"
        evidence_detail = ""
        evidence_type = "MISSING"
        
        # Check against metadata
        if not keys or not all(k in metadata for k in keys):
            status = "UNKNOWN"
            evidence_type = "MISSING"
            evidence_detail = "AuditX could not find relevant signals for this control in the extracted metadata."
        else:
            evidence_type = "DIRECT"
            values = [metadata[k] for k in keys]
            
            if ctype == "presence":
                if all(bool(v) for v in values):
                    status = "PASS"
                    evidence_detail = f"Found required values for {keys}"
                else:
                    status = "FAIL"
                    evidence_detail = f"Missing required true/present values for {keys}"
            elif ctype == "absence":
                if all(not bool(v) for v in values):
                    status = "PASS"
                    evidence_detail = f"Absence confirmed for {keys}"
                else:
                    status = "FAIL"
                    evidence_detail = f"Found prohibited values for {keys}"
            elif ctype == "value":
                pass_cond = control.get('pass_condition', '').lower()
                target_bool = "false" not in pass_cond  # Defaults to true unless false is mentioned
                if all(bool(v) == target_bool for v in values):
                    status = "PASS"
                    evidence_detail = f"Value matched expected state for {keys}"
                else:
                    status = "FAIL"
                    evidence_detail = f"Value did not match expected state for {keys}"
                    
        severity = "HIGH"
        if status == "FAIL" and ("log" in control.get('title', '').lower() or "debug" in control.get('title', '').lower()):
             severity = "MEDIUM"
             
        results.append({
            "control_id": control.get('control_id', 'UNKNOWN'),
            "title": control.get('title', 'Unknown Control'),
            "description": control.get('description', ''),
            "status": status,
            "evidence_type": evidence_type,
            "evidence_detail": evidence_detail,
            "severity": severity,
            "recommendation": ""
        })
        
    return results
