import re, math, logging

URL_PATTERN = re.compile(r'https?://\S+')
SUSPICIOUS_URL_EXT = re.compile(r'\.(exe|zip|sh|py|msi|bat|scr)$', re.IGNORECASE)

def analyze_content(text):
    findings = []
    text_clean = text.strip()
    sanitized_text = re.sub(r'\s{2,}', ' ', text)
    
    # -------------------------------------------------------------------------
    # 1. Contextual Keyword Analysis
    # -------------------------------------------------------------------------
    try:
        high_risk_checks = {
            "ALERT: Confirmed Malicious Logic": [r"\beval\(", r"\bexec\(", r"String\.fromCharCode"],
            "ALERT: Automatic Trigger": [r"/OpenAction", r"/AA"]
        }
        obfuscation_patterns = {
            "ALERT: Obfuscated Scripting (Spaced-out)": [r"e\s*v\s*a\s*l", r"e\s*x\s*e\s*c", r"j\s*s\s*v\s*c\s*r\s*i\s*p\s*t"]
        }

        low_risk_indicators = [r"typeof", r"/JS", r"/JavaScript", r"base64"]
        
        # 1.1 Scan for High-Risk Logic
        for message, patterns in high_risk_checks.items():
            for pattern in patterns:
                if re.search(pattern, sanitized_text, re.IGNORECASE):
                    findings.append(message)
                    break

        # 1.2 Scan for Spaced-out Obfuscation
        for message, patterns in obfuscation_patterns.items():
            for pattern in patterns:
                if re.search(pattern, sanitized_text, re.IGNORECASE):
                    findings.append(message)
                    break

        # 1.3 Perform Low-Risk Clustering Analysis
        matched_indicators = []
        for pattern in low_risk_indicators:
            if re.search(pattern, sanitized_text, re.IGNORECASE):
                matched_indicators.append(pattern)
        
        if len(matched_indicators) >= 2:
            findings.append(f"INFO: Multiple suspicious indicators found ({', '.join(matched_indicators)})")
            
    except Exception as e:
        logging.error(f"Keyword Analysis failed: {e}")

    # -------------------------------------------------------------------------
    # 2. URL and Link Analysis
    # -------------------------------------------------------------------------
    try:
        urls = URL_PATTERN.findall(text)
        if urls:
            findings.append(f"INFO: Contains {len(urls)} link(s)")
            
            for url in urls:
                clean_url = url.strip('()<>[]"\'')
                
                if SUSPICIOUS_URL_EXT.search(clean_url):
                    findings.append(f"ALERT: Link points to executable file ({clean_url.split('/')[-1]})")
                
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', clean_url):
                    findings.append(f"ALERT: Link uses direct IP address (Potential C2 server)")
                    
    except Exception as e:
        logging.error(f"URL Analysis failed: {e}")

    # -------------------------------------------------------------------------
    # 3. Heuristic & Density Analysis
    # -------------------------------------------------------------------------
    try:
        if 0 < len(text_clean) < 50:
            findings.append("ALERT: Extremely low text density (Suspicious PDF)")
        
        if len(text_clean) > 100:
            entropy_score = calculate_entropy(text_clean)
            if entropy_score > 5.0:
                findings.append(f"ALERT: High text entropy ({entropy_score:.2f}) - Possible encoded payload")
                
    except Exception as e:
        logging.error(f"Heuristic Analysis failed: {e}")

    return findings

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy