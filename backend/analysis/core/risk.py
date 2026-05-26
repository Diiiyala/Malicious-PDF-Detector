from analysis.utils.models import Threat

def calculate_risk(threats: list[Threat]):

    score = 0
    used_ids = set()

    for t in threats:
        if t.id not in used_ids:
            score += t.severity
            used_ids.add(t.id)

    DYNAMIC_THRESHOLD = 75

    risk_percentage = min(int((score / DYNAMIC_THRESHOLD) * 100), 100)
    has_critical_threat = any(t.severity >= 12 for t in threats)
    
    if risk_percentage >= 70 or has_critical_threat:
        level = "HIGH RISK"
    elif risk_percentage >= 30:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, risk_percentage, level