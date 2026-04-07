def calculate_risk(findings, reader):
    score = 0

    weights = {
        "Auto action detected": 3,
        
        "ALERT: Launch action detected": 8,
        "ALERT: OpenAction": 7,
        "ALERT: JavaScript detected": 6,
        "ALERT: Hacking tools": 7,
        "ALERT: Encoded": 5,
        "ALERT: XSS injection": 5,
        
        "ALERT: Embedded files detected": 4,
        "ALERT: Suspicious link": 4,
        "ALERT: Suspicious keywords": 3,
        "ALERT: Future creation date": 3,         
        "ALERT: Future modification date": 3,
        "ALERT: Timestamp anomaly": 3,
        "ALERT: Many stream objects": 4,
        "ALERT: Large number of objects": 3,
        "ALERT: Potential obfuscation": 3,
        
        "ALERT: Suspicious metadata source": 2,
        "ALERT: Missing Root object": 2,
        "ALERT: No pages found": 2,
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
            if "Encrypted PDF" not in used:
                score += 3
                findings.append("Encrypted PDF")
                used.add("Encrypted PDF")
    except: pass

    max_score = 25
    risk_percentage = min(int((score / max_score) * 100), 100)

    if score >= 12:
        level = "HIGH RISK"
    elif score >= 6:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, risk_percentage, level