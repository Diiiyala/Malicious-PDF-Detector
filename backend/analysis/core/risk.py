from analysis.utils.models import Threat

SEVERITY_MAX = 15
RISK_NORMALIZATION = 100
MAX_SCORED_PER_ID = 3
CRITICAL_SEVERITY = 12
HIGH_RISK_PCT = 70
MEDIUM_RISK_PCT = 30

STATUS_SAFE = "safe"
STATUS_WARNING = "warning"
STATUS_DANGER = "danger"

def calculate_risk(threats: list[Threat]):

    score = 0
    scored_per_id = {}

    for t in threats:
        seen = scored_per_id.get(t.id, 0)

        if seen < MAX_SCORED_PER_ID:
            score += t.severity
            scored_per_id[t.id] = seen + 1

    risk_percentage = min(int((score / RISK_NORMALIZATION) * 100), 100)
    has_critical_threat = any(t.severity >= CRITICAL_SEVERITY for t in threats)

    if risk_percentage >= HIGH_RISK_PCT or has_critical_threat:
        level = "HIGH RISK"
    elif risk_percentage >= MEDIUM_RISK_PCT:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    if not threats:
        status = STATUS_SAFE
    elif level == "HIGH RISK":
        status = STATUS_DANGER
    else:
        status = STATUS_WARNING

    return score, risk_percentage, level, status