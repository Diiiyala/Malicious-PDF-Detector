
def calculate_risk(findings):

    weights = {
        # Text
        "ALERT: Hidden text detected (Tiny Font": 10,    
        "ALERT: Hidden text detected (Off-Canvas": 8,    
        "INFO: Non-standard font encoding detected": 3,
        "INFO: Text transformation detected": 3,
        "INFO: Flipped/mirrored text detected": 4,
        "INFO: Page contains images but no extractable text": 2,
        
        # Structure
        "ALERT: Clickjacking Full-page overlay": 13, 
        "ALERT: Remote resource reference detected": 12,
        "ALERT: Dangerous silent trigger": 12,
        "ALERT: Silent page trigger": 12,
        "ALERT: Hidden URLs extracted from JavaScript": 12,
        "ALERT: Clickjacking Suspicious invisible button grid": 12,
        "ALERT: PDF 2.0 Associated Files (/AF) detected": 12,
        "ALERT: Annotation (/GoToR)": 12,
        "ALERT: Suspicious OCG-JavaScript coupling detected": 11,
        "ALERT: Suspicious Scripting found (Raw Scan)": 11,
        "ALERT: Auto-executable (/OpenAction) detected": 11,
        "ALERT: Suspicious /GoToE pointing to": 11,
        "ALERT: Form GoToE pointing to": 11,
        "ALERT: Malformed structure repaired and analyzed": 10,
        "ALERT: Automatic triggers (/AA) detected": 10,
        "ALERT: Annotation (/Launch) detected": 10,
        "ALERT: Embedded Files detected (Raw Scan)": 10,
        "ALERT: Malformed PDF header": 10, 
        "ALERT: Auto-executable (/OpenAction)": 10,
        "ALERT: Automatic triggers (/AA)": 9,
        "ALERT: Suspicious Scripting found": 9,      
        "ALERT: Embedded Files detected": 9,
        "Annotation (/Launch)": 9,
        "Annotation (/JS)": 9,
        "ALERT: Multiple PDF headers": 8,    
        "ALERT: Could not fully analyze actions": 8,
        "ALERT: Optional Content Groups (OCG) detected": 7,
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
        "ALERT: NTLM Relay attack pattern confirmed": 14,
        "ALERT: Analysis process interrupted during content scan": 12,
        "ALERT: Embedded file launch trigger (/Launch) found in raw data": 12,
        "ALERT: Hidden automatic execution trigger (/AA /O) detected in raw stream": 12,
        "ALERT: Scripting indicators found in raw binary data": 12,
        "ALERT: High-confidence obfuscated script detected": 12,
        "ALERT: Hidden JS-staged URL detected": 12,
        "ALERT: Scripting execution pattern detected": 12,
        "ALERT: Direct URI action detected in hidden object": 12,
        "ALERT: Hidden URI found in raw scan": 12,
        "WebSocket Connection (C2 Channel)": 12,
        "Ransomware Indicators": 12,
        "ALERT: Scripting indicator found in malformed object": 11,
        "ALERT: Scripting indicators found in raw binary data (JavaScript)": 11,
        "ALERT: Form submission trigger (/SubmitForm) found in raw data": 11,
        "ALERT: Remote PDF embedded link (/GoToE) found in raw data": 11,
        "ALERT: RichMedia object (Potential exploit carrier) found in raw data": 10,
        "Security Disabling": 10,
        "Registry Tampering": 10,
        "Stealer/Spyware": 10,
        "ALERT: Dangerous file download detected": 10,
        "ALERT: UNC path detected": 10,
        "ALERT: Automatic execution trigger found in raw data": 10,
        "ALERT: Event-based execution trigger found in raw data": 10,
        "ALERT: Embedded execution trigger (/GoToE)": 9,
        "ALERT: Cryptocurrency address found": 9,
        "ALERT: Custom encryption filter (/Crypt) found in raw data": 8,
        "ALERT: Suspicious compression filter (/JBIG2Decode) detected": 8,
        "ALERT: Logic obfuscation detected": 8,
        "ALERT: Direct IP access detected": 7,
        "ALERT: Malicious parameter key detected in URL": 6,
        "ALERT: Suspicious hosts detected": 6,
        "ALERT: Multiple execution triggers": 9,
        "ALERT: Automatic execution trigger": 8,
        "ALERT: Event-based execution trigger": 8,
        "ALERT: Specific threats detected": 10,
        "ALERT: Hidden Layer": 4,
        "ALERT: Highly Random Data (Encrypted/Compressed)": 8,
        "ALERT: Minified/Compressed Text": 3,
        "ALERT: Obfuscated Content": 5,
        "ALERT: Hex-encoded content": 2,                      
        "ALERT: URL-encoded content": 2
    }                   
    
    top_5_weights = sorted(weights.values(), reverse=True)[:5]
    DYNAMIC_THRESHOLD = sum(top_5_weights)

    score = 0
    used_keys = set()
    for finding in findings:
        for key, weight in weights.items():
            if key in finding and key not in used_keys:
                score += weight
                used_keys.add(key)
                break

    risk_percentage = min(int((score / DYNAMIC_THRESHOLD) * 100), 100)

    has_critical_threat = any(weights[k] >= 12 for k in used_keys if k in weights)
    
    if risk_percentage >= 70 or has_critical_threat:
        level = "HIGH RISK"
    elif risk_percentage >= 30:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, risk_percentage, level