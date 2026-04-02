import os
import json
import logging
import time
import google.generativeai as genai
from .prompts import SYSTEM_PROMPT, BEHAVIOR_OBSERVED_PROMPT, TOP_RISK_PROMPT

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
        
    def _call_gemini(self, prompt: str) -> str:
        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if text.startswith("```json"): text = text[7:]
            elif text.startswith("```"): text = text[3:]
            if text.endswith("```"): text = text[:-3]
            return text.strip()
        except Exception as e:
            logger.error(f"Gemini API Error: {str(e)}")
            return ""

    def translate_findings(self, findings: list) -> dict:
        """Call 1: Batch translation of behavior_observed."""
        result = {}
        if not findings: return result
        
        # Strip down findings to save tokens
        stripped_findings = [{"rule_id": f.get("rule_id", "Unknown"), "title": f.get("title", "")} for f in findings]
        prompt = BEHAVIOR_OBSERVED_PROMPT.format(findings_json=json.dumps(stripped_findings))
        
        response_text = self._call_gemini(prompt)
        try:
            parsed = json.loads(response_text)
            for item in parsed:
                if "rule_id" in item and "behavior_observed" in item:
                    result[item["rule_id"]] = item["behavior_observed"]
        except Exception as e:
             logger.warning("Failsafe activated: Failed to parse behavior JSON from Gemini.")
             
        # Failsafe defaults for any missing translations
        for f in findings:
            rid = f.get("rule_id", "Unknown")
            if rid not in result:
                result[rid] = f"The system indicates a significant compliance gap related to {f.get('title', 'security').lower()}."
                
        return result

    def get_top_risk(self, findings: list) -> str:
        """Call 2: Executive top risk summary."""
        if not findings: return "No critical risks detected."
        
        time.sleep(12) # Rate limit safety
        
        # Sort by severity to ensure CEO sees the absolute worst issue
        severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        worst = sorted(findings, key=lambda x: severity_map.get(x.get("severity", "LOW"), 4))[:3]
        stripped = [{"title": f.get("title", ""), "severity": f.get("severity", "LOW")} for f in worst]
        
        prompt = TOP_RISK_PROMPT.format(findings_json=json.dumps(stripped))
        response_text = self._call_gemini(prompt)
        
        if not response_text:
            return "Multiple security vulnerabilities require immediate technical and compliance review."
        return response_text
