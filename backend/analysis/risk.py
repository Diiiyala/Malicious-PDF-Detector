
def calculate_risk(findings, reader):
    score = 0

    weights = {
        # Structure
        "ALERT: Malformed PDF header": 10, 
        "ALERT: Auto-executable (/OpenAction)": 10,
        "ALERT: Automatic triggers (/AA)": 9,
        "ALERT: Suspicious Scripting found": 9,      
        "ALERT: Embedded Files detected": 9,
        "Annotation (/Launch)": 9,
        "Annotation (/JS)": 9,
        "ALERT: Multiple PDF headers": 8,    
        "ALERT: Could not fully analyze actions": 8,
        "ALERT: PDF version missing or malformed": 7,
        "ALERT: PDF signature is not at the start": 7,
        "ALERT: Could not parse object": 7,
        "ALERT: Version mismatch": 6,    
        "ALERT: Form Field Action": 5,
        "Annotation (URI:": 5,
        "ALERT: Encrypted PDF": 5, 
        "Annotation (/Named)": 4,     
        "ALERT: Bookmark (": 4,      
        "ALERT: Old PDF version detected in header": 3,
        "INFO: Entry points to an empty object": 1,
        
        # Metadata
        "INFO: Link found": 1,
        "INFO: Long metadata field": 1,  
        "ALERT: Hacking tools detected": 9,      
        "ALERT: XSS injection attempt": 7,      
        "ALERT: Encoded Base64 payload": 5,      
        "ALERT: Encoded Hex payload": 5,         
        "ALERT: Encoded ROT13 payload": 5,       
        "ALERT: Encoded URL payload": 5,        
        "ALERT: Suspicious link detected": 5,    
        "ALERT: Potential obfuscation detected": 4, 
        "ALERT: Suspicious keywords detected": 4, 
        "ALERT: Future creation date": 3,         
        "ALERT: Future modification date": 3,
        "ALERT: Timestamp anomaly": 3,
        "ALERT: Suspicious metadata source": 3,
        
        # Content      
        "little text": 2,                       
    }

    used = set()

    for finding in findings:
        for key in weights:
            if key in finding:
                if key not in used:
                    score += weights[key]
                    used.add(key)

    max_score = sum(weights.values())
    risk_percentage = min(int((score / max_score) * 100), 100)

    if risk_percentage >= 50:
        level = "HIGH RISK"
    elif risk_percentage >= 25:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, risk_percentage, level