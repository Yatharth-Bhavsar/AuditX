"""
Shallow Taint Analysis for AuditX

Deterministic, fast heuristic evaluations running post-AST.
Checks for basic data flows from user input to dangerous sinks without sanitization.
"""

def extract_taint_findings(metadata):
    """
    Evaluates if 'request' is in source, 'execute' is in sink, and 'sanitize' is NOT in path.
    """
    findings = []
    
    # We leverage inferred SQL injection paths from the AST code summary.
    db_ops = metadata.get('db_operations', [])
    raw_lines = metadata.get('raw_code_snippets', []) # We'll need ast_extractor to pass chunks
    
    for snippet in raw_lines:
        snippet_lower = snippet.lower()
        
        # Shallow heuristic: Source = request, Sink = execute (or query)
        has_source = "request" in snippet_lower or "data.get" in snippet_lower
        has_sink = "execute" in snippet_lower or "query" in snippet_lower
        is_sanitized = "sanitize" in snippet_lower or "escape" in snippet_lower or "?" in snippet
        
        # String concat implies missing parameterization inside an execute block
        if has_source and has_sink and not is_sanitized and ("+" in snippet or "%" in snippet or "f\"" in snippet or "f'" in snippet):
            findings.append({
                "rule_id": "TAINT01",
                "title": "Unsanitized Input Flow",
                "severity": "HIGH",
                "owasp": "A03: Injection",
                "regulation": ["OWASP A03"],
                "location": "database transaction",
                "evidence_type": "INFERRED",
                "evidence_source": "Heuristic Taint",
                "confidence": "MEDIUM",
                "behavior_observed": "",
                "legal_obligation": "",
                "remediation_action": "",
                "remediation_priority": 0,
                "remediation_effort": "MEDIUM"
            })
            break # Dedupe logic will handle overlaps, one is enough for flag
            
    return findings
