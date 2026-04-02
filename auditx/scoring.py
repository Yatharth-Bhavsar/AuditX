"""
AuditX Scoring Engine

Deterministic, transparent scoring pipeline.
"""
def calculate_score(findings, missing_controls, profile):
    """
    Scoring logic:
    Start at 100
    Each CRITICAL finding:   -25
    Each HIGH finding:       -15
    Each MEDIUM finding:     -8
    Each LOW finding:        -3
    Missing controls penalty is handled via findings or explicit deduction
    """
    score = 100
    penalties = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "critical_penalty": 0,
        "high_penalty": 0,
        "medium_penalty": 0,
        "low_penalty": 0,
        "missing_controls_count": 0,
        "missing_controls_penalty": 0,
        "profile_multiplier_applied": False,
        "starting_score": score
    }
    for f in findings:
        sev = str(f.get('severity', '')).upper()
        # Profile multipliers
        mult = 1.0
        regs = " ".join([r.lower() for r in f.get('regulation', [])])
        if profile == 'fintech' and ('pci' in regs or 'rbi' in regs):
            mult = 1.5
        elif profile == 'saas' and 'dpdp' in regs:
            mult = 1.5
            
        if sev == 'CRITICAL':
            penalties['critical_count'] += 1
            penalties['critical_penalty'] += int(25 * mult)
            if mult > 1.0: penalties['profile_multiplier_applied'] = True
        elif sev == 'HIGH':
            penalties['high_count'] += 1
            penalties['high_penalty'] += int(15 * mult)
            if mult > 1.0: penalties['profile_multiplier_applied'] = True
        elif sev == 'MEDIUM':
            penalties['medium_count'] += 1
            penalties['medium_penalty'] += int(8 * mult)
            if mult > 1.0: penalties['profile_multiplier_applied'] = True
        elif sev == 'LOW':
            penalties['low_count'] += 1
            penalties['low_penalty'] += int(3 * mult)
            if mult > 1.0: penalties['profile_multiplier_applied'] = True
            
    # Apply deductions
    score -= penalties['critical_penalty']
    score -= penalties['high_penalty']
    score -= penalties['medium_penalty']
    score -= penalties['low_penalty']
    
    # Missing controls: -5 each, capped at 20
    mc_penalty = min(len(missing_controls) * 5, 20)
    penalties['missing_controls_count'] = len(missing_controls)
    penalties['missing_controls_penalty'] = mc_penalty
    score -= mc_penalty
    
    score = max(0, score) # Floor at 0
    
    # Label mapping
    if score >= 80:
        label, color = "AUDIT READY", "green"
    elif score >= 60:
        label, color = "CONDITIONAL", "yellow"
    elif score >= 40:
        label, color = "HIGH RISK", "orange"
    else:
        label, color = "FAILURE", "red"
        
    return {
        "score": score,
        "label": label,
        "color": color,
        "breakdown": penalties
    }

def calculate_custom_score(control_results):
    total_controls = len(control_results)
    if total_controls == 0:
        return None
        
    passed = sum(1 for c in control_results if c.get('status') == 'PASS')
    failed = sum(1 for c in control_results if c.get('status') == 'FAIL')
    unknown = sum(1 for c in control_results if c.get('status') == 'UNKNOWN')
    
    raw_score = (passed / total_controls) * 100
    score = round(raw_score)
    
    if score >= 80:
        label, color = "AUDIT READY", "green"
    elif score >= 60:
        label, color = "CONDITIONAL", "yellow"
    elif score >= 40:
        label, color = "HIGH RISK", "orange"
    else:
        label, color = "FAILURE", "red"
        
    return {
        "score": score,
        "label": label,
        "color": color,
        "total_controls": total_controls,
        "passed": passed,
        "failed": failed,
        "unknown": unknown
    }
