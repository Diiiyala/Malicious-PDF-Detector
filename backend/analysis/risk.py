def calculate_risk(findings, reader):
    score = 0
    weights = {
        "JavaScript detected": 3,
        "Auto action detected": 3,
        "Embedded files detected": 4,
        "Suspicious keywords": 2,
        "Contains": 1,
        "Very little text": 2,
        "Names dictionary present": 1,
    }

    for finding in findings:
        for key in weights:
            if key in finding:
                score += weights[key]

    try:
        if reader.is_encrypted:
            score += 3
            findings.append("Encrypted PDF")
    except:
        pass

    max_score = 15
    risk_percentage = int((score / max_score) * 100)

    if score >= 7:
        level = "HIGH RISK"
    elif score >= 4:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, risk_percentage, level