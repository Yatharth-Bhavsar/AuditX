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
        # Ignoring JS for this demo scope to focus on the Flask demo_repo, but structure is here
    
    def scan(self) -> CodebaseSummary:
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith('.py'):
                    self.summary.file_count += 1
                    self.summary.language_breakdown["python"] += 1
                    self._parse_python_file(os.path.join(root, file))
        return self.summary
        
    def _parse_python_file(self, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
            
        tree = self.parser_py.parse(bytes(code, 'utf8'))
        root_node = tree.root_node
        
        self._extract_routes_and_fields(root_node, code)
        self._extract_db_models(root_node, code)
        self._check_auth_and_logging(code)
        
    def _extract_routes_and_fields(self, node, code):
        # Very simplified AST extraction for demo purposes
        # Look for function definitions with decorators (routes)
        # Note: tree-sitter python bindings API shape changed in >= 0.22 (query.captures no longer works the same way),
        # so relying on regex fallback built for demo_repo.
        
        # Regex fallback for simpler extraction matching the hackathon requirements
        # Flask route: @app.route('/path', methods=['POST'])
        route_pattern = re.compile(r'@\w+\.route\([\'"]([^\'"]+)[\'"].*?methods=\[.*?([A-Z]+).*?\]')
        
        for match in route_pattern.finditer(code):
            path = match.group(1)
            method = match.group(2)
            
            # Find function name right after decorator
            func_match = re.search(r'def\s+(\w+)\s*\(', code[match.end():])
            handler_name = func_match.group(1) if func_match else "unknown"
            
            # Find DB ops in this file (simplified scope)
            db_ops = []
            if "INSERT INTO" in code or "SELECT * FROM" in code:
               db_ops.append("Raw SQL executed")
               
            # Input params from request (e.g. data.get('field'))
            inputs = re.findall(r"(?:request\.json|data)\.get\([\'\"](\w+)[\'\"]\)", code)
            
            route = RouteExtract(
                path=path,
                method=method,
                handler_name=handler_name,
                input_params=inputs,
                db_operations=db_ops
            )
            self.summary.routes.append(route)
            
            # Accumulate sensitive fields
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
        # Look for CREATE TABLE in strings (naive but works for demo_repo)
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
        # Regex checks for auth and logging patterns
        if "jwt" in code.lower() or "token" in code.lower():
            self.summary.auth_patterns.jwt_verification = True
            
        if "logging.basicConfig" in code:
            self.summary.logging_config.setup_detected = True
            
        # Check if sensitive fields are logged
        log_pattern = re.compile(r'log(?:ger)?\.\w+\(.*?(?:cvv|password|token).*?\)', re.IGNORECASE)
        if log_pattern.search(code):
             self.summary.logging_config.sensitive_fields_logged = True
