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

