
def calculate_risk(findings, reader):
    score = 0
    DANGER_THRESHOLD = 45

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
        "ALERT: Multi-stage virus detected": 15,                    
        "ALERT: High-confidence obfuscated script detected": 12, 
        "Ransomware Indicators": 12,
        "Security Disabling": 10,
        "Registry Tampering": 10,
        "Stealer/Spyware": 10,
        "ALERT: Dangerous file download detected": 10,          
        "ALERT: Cryptocurrency address found": 9,
        "ALERT: Highly Random Data": 8,  
        "ALERT: Logic obfuscation detected": 8,                
        "ALERT: Direct IP access detected": 7,                  
        "ALERT: Malicious parameter key detected in URL": 6,      
        "ALERT: Suspicious hosts detected": 6,                 
        "ALERT: Obfuscated Content": 5,                       
        "ALERT: Minified/Compressed Text": 3,                  
        "ALERT: Hidden Layer": 4,                               
        "INFO: Scripting execution pattern detected": 2,                    
    }

    used_keys = set()
    for finding in findings:
        for key, weight in weights.items():
            if key in finding and key not in used_keys:
                score += weight
                used_keys.add(key)

    risk_percentage = min(int((score / DANGER_THRESHOLD) * 100), 100)

    if risk_percentage >= 70 or score >= 30:
        level = "HIGH RISK"
    elif risk_percentage >= 30:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, risk_percentage, level