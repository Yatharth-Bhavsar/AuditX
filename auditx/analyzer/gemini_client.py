import os
import json
import time
import logging
import google.generativeai as genai
from .prompts import SYSTEM_PROMPT, USER_PROMPT_1, USER_PROMPT_2, USER_PROMPT_3
from auditx.scanner.extractor_models import CodebaseSummary

logger = logging.getLogger(__name__)

class GeminiClient:
    def __init__(self, api_key: str = None):
        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise ValueError("GEMINI_API_KEY is not set.")
        
        genai.configure(api_key=key)
        self.model = genai.GenerativeModel(
            model_name="gemini-2.5-flash",
            system_instruction=SYSTEM_PROMPT
        )
    
    def _call_gemini_with_retry(self, prompt: str, max_retries=1) -> list:
        for attempt in range(max_retries + 1):
            try:
                response = self.model.generate_content(prompt)
                text = response.text.strip()
                
                # Strip markdown fences if present
                if text.startswith("```json"):
                    text = text[7:]
                if text.startswith("```"):
                    text = text[3:]
                if text.endswith("```"):
                    text = text[:-3]
                
                return json.loads(text.strip())
            
            except Exception as e:
                # Naive 429 check
                if "429" in str(e) and attempt < max_retries:
                    logger.warning("Rate limit hit, waiting 60s before retry...")
                    time.sleep(60)
                else:
                    logger.error(f"Gemini API Error: {str(e)}")
                    # Degrade gracefully
                    return []
                    
        return []

    def run_analysis(self, summary: CodebaseSummary, profile: str) -> list:
        all_findings = []
        
        summary_dict = summary.model_dump()
        
        # Base JSON conversion function
        def to_json(obj):
            return json.dumps(obj, default=str)
        
        # --- CALL 1: General & DPDP ---
        prompt1 = USER_PROMPT_1.format(
            profile=profile, 
            codebase_summary_json=to_json(summary_dict)
        )
        findings1 = self._call_gemini_with_retry(prompt1)
        all_findings.extend(findings1)
        logger.info(f"API Call 1 produced {len(findings1)} findings. Sleeping 12s...")
        time.sleep(12) # Rate limit safety
        
        # --- CALL 2: Payments ---
        if summary.sensitive_fields_found["PAN_FIELDS"] or any('payment' in r.path for r in summary.routes):
            prompt2 = USER_PROMPT_2.format(
                profile=profile,
                payment_summary_json=to_json({
                    "routes": [r for r in summary_dict['routes'] if 'payment' in r['path'] or 'checkout' in r['path']],
                    "db_models": summary_dict['db_models'],
                    "sensitive_fields": summary.sensitive_fields_found["PAN_FIELDS"]
                })
            )
            findings2 = self._call_gemini_with_retry(prompt2)
            all_findings.extend(findings2)
            logger.info(f"API Call 2 produced {len(findings2)} findings. Sleeping 12s...")
            time.sleep(12)
            
        # --- CALL 3: Infra & Logging ---
        prompt3 = USER_PROMPT_3.format(
            profile=profile,
            infra_summary_json=to_json({
                "auth_patterns": summary_dict['auth_patterns'],
                "logging_config": summary_dict['logging_config']
            })
        )
        findings3 = self._call_gemini_with_retry(prompt3)
        all_findings.extend(findings3)
        logger.info(f"API Call 3 produced {len(findings3)} findings.")
        
        return all_findings
