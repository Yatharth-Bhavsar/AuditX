import os
import re
from pathlib import Path
import tree_sitter_python
from tree_sitter import Language, Parser
from .extractor_models import CodebaseSummary, RouteExtract, ModelExtract, DBField, AuthPatterns, LoggingConfig

# Patterns for Sensitive Fields
SENSITIVE_PATTERNS = {
    "PAN_FIELDS": ["pan", "card_number", "card_num", "cvv", "expiry", "card_last", "account_number", "ifsc", "bank_account"],
    "AADHAAR_FIELDS": ["aadhaar", "aadhar", "uid_number", "voter_id", "driving_licence"],
    "PII_FIELDS": ["email", "phone", "mobile", "dob", "date_of_birth", "address", "pincode", "religion", "caste", "gender", "mother_name", "maiden_name", "nationality", "passport"],
    "AUTH_FIELDS": ["password", "token", "secret", "api_key", "private_key", "otp"]
}

class ASTExtractor:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.summary = CodebaseSummary()
        self.parser_py = Parser(Language(tree_sitter_python.language()))
    
    def scan(self) -> CodebaseSummary:
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith('.py'):
                    # Skip the egg metadata and environment folders
                    if "venv" in root or ".egg" in root:
                        continue
                    self.summary.file_count += 1
                    self.summary.language_breakdown["python"] += 1
                    self._parse_python_file(os.path.join(root, file))
        return self.summary
        
    def _parse_python_file(self, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
            
        tree = self.parser_py.parse(bytes(code, 'utf8'))
        root_node = tree.root_node
        
        # We store chunks of raw code solely for Taint/Secret heuristics (discarded before LLM)
        for line in code.split("\n"):
            if "request" in line or "execute" in line or "query" in line or "logger" in line:
                self.summary.raw_code_snippets.append(line.strip()[:150]) # cap length
        
        self._extract_routes_and_fields(root_node, code)
        self._extract_db_models(root_node, code)
        self._check_auth_and_logging(code)
        self._check_security_heuristics(code)
        
    def _extract_routes_and_fields(self, node, code):
        route_pattern = re.compile(r'@\w+\.route\([\'"]([^\'"]+)[\'"].*?methods=\[.*?([A-Z]+).*?\]')
        
        for match in route_pattern.finditer(code):
            path = match.group(1)
            method = match.group(2)
            
            func_match = re.search(r'def\s+(\w+)\s*\(', code[match.end():])
            handler_name = func_match.group(1) if func_match else "unknown"
            
            db_ops = []
            if "INSERT INTO" in code or "SELECT * FROM" in code:
               db_ops.append("Raw SQL executed")
               
            inputs = re.findall(r"(?:request\.json|data)\.get\([\'\"](\w+)[\'\"]\)", code)
            
            route = RouteExtract(
                path=path,
                method=method,
                handler_name=handler_name,
                input_params=inputs,
                db_operations=db_ops
            )
            self.summary.routes.append(route)
            
            for param in inputs:
                self._categorize_sensitive_field(param)

    def _categorize_sensitive_field(self, field_name: str):
        field_lower = field_name.lower()
        for category, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if pattern in field_lower:
                    if field_name not in self.summary.sensitive_fields_found[category]:
                        self.summary.sensitive_fields_found[category].append(field_name)

    def _extract_db_models(self, node, code):
        table_pattern = re.compile(r'CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\)', re.DOTALL)
        for match in table_pattern.finditer(code):
            table_name = match.group(1)
            columns_str = match.group(2)
            
            model = ModelExtract(model_name=table_name)
            
            # Naive column extraction
            for line in columns_str.split(','):
                line = line.strip()
                if line:
                    parts = line.split()
                    if parts:
                        col_name = parts[0]
                        self._categorize_sensitive_field(col_name)
                        col_type = parts[1] if len(parts) > 1 else None
                        model.fields.append(DBField(name=col_name, type=col_type))
                        
            self.summary.db_models.append(model)
            
    def _check_auth_and_logging(self, code):
        # Auth pattern detection
        if "jwt" in code.lower() or "token" in code.lower() or "@login_required" in code:
            self.summary.auth_patterns.jwt_verification = True
            
        if "logging.basicConfig" in code or "getLogger" in code:
            self.summary.logging_config.setup_detected = True
            
        # PII Logger leak check
        log_leak_pattern = re.compile(r'log(?:ger)?\.(?:info|debug|warn|error)\(.*?(password|cvv|token|aadhaar|pan).*?\)', re.IGNORECASE)
        match = log_leak_pattern.search(code)
        if match:
             self.summary.logging_config.sensitive_fields_logged = True
             self.summary.pii_logged.append(match.group(1))
             
    def _check_security_heuristics(self, code):
        # DEBUG mode
        if "DEBUG = True" in code or "debug=True" in code:
            self.summary.debug_mode_enabled = True
            
        # SQL Injection (string concat in execution)
        if re.search(r'execute\(.*\+.*|query\(.*f[\'\"].*\{', code):
            self.summary.sql_string_concat = True
            
        # Hardcoded Secrets
        secret_match = re.search(r'(?:api_key|secret|password)\s*=\s*[\'\"]([A-Za-z0-9_-]{8,})[\'\"]', code, re.IGNORECASE)
        if secret_match:
            self.summary.hardcoded_secrets.append(secret_match.group(0))
            
        # Missing Controls flags
        if "RateLimit" in code or "limiter" in code.lower():
            self.summary.rate_limiting_present = True
            
        if "try:" in code and "except Exception" in code:
            self.summary.error_handling_present = True
            
        if "ssl_context" in code:
            self.summary.auth_patterns.https_enforced = True
