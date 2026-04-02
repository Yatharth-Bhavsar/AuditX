from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class RouteExtract(BaseModel):
    path: str
    method: str
    handler_name: str
    input_params: List[str] = []
    db_operations: List[str] = []
    external_calls: List[str] = []

class DBField(BaseModel):
    name: str
    type: Optional[str] = None
    is_nullable: bool = True

class ModelExtract(BaseModel):
    model_name: str
    fields: List[DBField] = []

class AuthPatterns(BaseModel):
    jwt_verification: bool = False
    rate_limiting: bool = False
    input_sanitization: bool = False
    https_enforced: bool = False

class LoggingConfig(BaseModel):
    setup_detected: bool = False
    sensitive_fields_logged: bool = False
    siem_integration: bool = False

class CodebaseSummary(BaseModel):
    routes: List[RouteExtract] = []
    db_models: List[ModelExtract] = []
    sensitive_fields_found: Dict[str, List[str]] = {
        "PAN_FIELDS": [],
        "AADHAAR_FIELDS": [],
        "PII_FIELDS": [],
        "AUTH_FIELDS": []
    }
    auth_patterns: AuthPatterns = AuthPatterns()
    logging_config: LoggingConfig = LoggingConfig()
    file_count: int = 0
    language_breakdown: Dict[str, int] = {"python": 0, "javascript": 0}
    
    # Flat properties for deterministic rules & custom policies
    raw_code_snippets: List[str] = []
    hardcoded_secrets: List[str] = []
    debug_mode_enabled: bool = False
    sql_string_concat: bool = False
    rate_limiting_present: bool = False
    error_handling_present: bool = False
    input_validation_present: bool = False
    consent_mechanism: bool = False
    retention_logic: bool = False
    pii_logged: List[str] = []

    def to_flat_dict(self) -> dict:
        """Converts the internal summary into the flat schema expected by the static rules engine and policy matcher."""
        flat = {}
        flat['routes'] = [{"method": r.method, "path": r.path} for r in self.routes]
        flat['db_fields'] = [f.name for m in self.db_models for f in m.fields]
        flat['sensitive_fields'] = self.sensitive_fields_found["PAN_FIELDS"] + self.sensitive_fields_found["AADHAAR_FIELDS"] + self.sensitive_fields_found["PII_FIELDS"]
        
        flat['auth_present'] = self.auth_patterns.jwt_verification or any("auth" in r.path for r in self.routes if "register" not in r.path)
        flat['debug_mode'] = self.debug_mode_enabled
        flat['https_enforced'] = self.auth_patterns.https_enforced
        flat['sql_injection_risk'] = self.sql_string_concat
        flat['pii_logged'] = self.pii_logged
        flat['logging_present'] = self.logging_config.setup_detected
        flat['external_calls'] = []
        
        flat['hardcoded_secrets'] = self.hardcoded_secrets
        flat['raw_code_snippets'] = self.raw_code_snippets
        flat['rate_limiting'] = self.rate_limiting_present
        flat['error_handling_present'] = self.error_handling_present
        flat['input_validation_present'] = self.input_validation_present
        flat['consent_mechanism'] = self.consent_mechanism
        flat['retention_logic'] = self.retention_logic
        
        flat['db_operations'] = [op for r in self.routes for op in r.db_operations]
        return flat
