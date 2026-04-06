def calculate_risk(findings, reader):
    score = 0

    weights = {
        "JavaScript detected": 3,
        "Auto action detected": 3,
        "Embedded files detected": 4,
        "ALERT: Suspicious keywords": 2,
        "ALERT: Hacking tool": 4,
        "ALERT: XSS injection": 3,
        "ALERT: Suspicious link": 3,
        "ALERT: Encoded": 4,
        "ALERT: Suspicious metadata source": 2,
        "ALERT: Potential obfuscation": 2,
        "ALERT: Future creation date": 3,
        "ALERT: Future modification date": 3,
        "ALERT: Timestamp anomaly": 3,
        "INFO: Link found": 1,
        "INFO: Long metadata": 1,
        "little text": 2,
        "Names dictionary present": 1,
    }

    used = set()

    for finding in findings:
        for key in weights:
            if key in finding:
                if key not in used:
                    score += weights[key]
                    used.add(key)

    try:
        if reader.is_encrypted:
            score += 3
            findings.append("Encrypted PDF")
    except:
        pass

    max_score = 20
    risk_percentage = min(int((score / max_score) * 100), 100)

    if score >= 10:
        level = "HIGH RISK"
    elif score >= 5:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, risk_percentage, level