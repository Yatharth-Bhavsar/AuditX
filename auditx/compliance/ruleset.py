import json
import os
import re

RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')

def load_rules(regulation_key):
    """Load the JSON ruleset for a specific regulation."""
    filename = f"{regulation_key.lower()}.json"
    filepath = os.path.join(RULES_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def fuzzy_match(text, triggers):
    """Check if any trigger word/phrase appears in the text."""
    text_lower = str(text).lower()
    for trigger in triggers:
        # Simple substring match, can be expanded to regex if needed
        # Replace underscores with spaces for more natural matching against LLM output
        clean_trigger = str(trigger).lower().replace('_', ' ')
        if clean_trigger in text_lower or str(trigger).lower() in text_lower:
            return True
    return False

def enrich_finding(finding):
    """
    Takes a finding dict from Gemini and adds full compliance section, title, and description
    by matching against the local ruleset.
    """
    regulation_key = finding.get('regulation_key', '')
    behavior_observed = finding.get('behavior_observed', '')
    
    if not regulation_key or not behavior_observed:
        return finding
        
    rules = load_rules(regulation_key)
    if not rules:
        return finding
        
    # Find the best matching rule based on triggers
    best_match = None
    for rule in rules:
        if fuzzy_match(behavior_observed, rule.get('triggers', [])):
            best_match = rule
            break
            
    # If a rule matched, enrich the finding
    if best_match:
        finding['regulation_reference'] = f"{regulation_key} — {best_match.get('section', '')}"
        finding['regulation_title'] = best_match.get('title', '')
        finding['legal_obligation'] = best_match.get('description', '')
    else:
        # Fallback if no specific rule matched
        finding['regulation_reference'] = regulation_key
        finding['regulation_title'] = "General Compliance Requirement"
        finding['legal_obligation'] = "Requirement inferred by AI auditor."
        
    return finding
