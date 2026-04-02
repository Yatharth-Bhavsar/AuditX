import json
import logging
from pypdf import PdfReader

logger = logging.getLogger(__name__)

METADATA_SCHEMA = {
    "routes": "list of API route objects with method and path",
    "db_fields": "list of all database field names found in models",
    "sensitive_fields": "list of field names that contain PII or financial data",
    "auth_present": "boolean — true if authentication decorators found",
    "debug_mode": "boolean — true if DEBUG=True or equivalent found",
    "https_enforced": "boolean — true if SSL context or HTTPS redirect found",
    "sql_injection_risk": "boolean — true if string-concatenated SQL found",
    "pii_logged": "list of PII field names found in logger calls",
    "logging_present": "boolean — true if any logging configuration found",
    "external_calls": "list of external API/service calls detected",
    "hardcoded_secrets": "list of hardcoded API keys or secrets",
    "rate_limiting": "boolean — true if rate limiting found",
    "error_handling_present": "boolean — true if error handling found",
    "input_validation_present": "boolean — true if input validation found",
    "consent_mechanism": "boolean — true if consent terminology found",
    "retention_logic": "boolean — true if data retention logic found"
}

def extract_pdf_text(pdf_path: str) -> str:
    """Extracts text from a given PDF file."""
    reader = PdfReader(pdf_path)
    text = []
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text.append(page_text)
            
    full_text = "\n".join(text).strip()
    if len(full_text) < 100:
        raise ValueError("PDF appears to be empty or image-based. AuditX requires text-based PDFs.")
    return full_text

def extract_controls_from_policy(pdf_text: str, gemini_client) -> list:
    """Extracts deterministic control lists from policy text using LLM."""
    prompt = f"""
    You are a compliance analyst. Read the following policy document excerpt
    and extract between 10 and 15 specific, checkable technical controls.

    A checkable technical control is something that can be verified by examining a software system's code.

    Do NOT extract process controls or runtime tests.
    Return ONLY a JSON array. No preamble, no explanation, no markdown.

    Format:
    [
      {{
        "control_id": "CP-01",
        "title": "...",
        "description": "...",
        "check_type": "presence|absence|value",
        "metadata_keys": ["key1", "key2"],
        "pass_condition": "Brief description of what passing looks like"
      }}
    ]

    check_type must be one of: presence, absence, value.
    metadata_keys must reference keys from this schema:
    {json.dumps(METADATA_SCHEMA, indent=2)}

    Policy document:
    ---
    {pdf_text[:6000]}
    ---
    """
    
    for _ in range(2):
        response = gemini_client._call_gemini(prompt)
        try:
            controls = json.loads(response)
            if isinstance(controls, list):
                return controls[:15]
        except Exception as e:
            pass
            
    logger.warning("Failed to extract valid JSON controls from policy document.")
    return []
