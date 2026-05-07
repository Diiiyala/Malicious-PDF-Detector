import re, math, base64, string
from collections import Counter
from analysis.detectors.links import analyze_links

B64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
BTC_ADDRESS = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')

SYSTEM_THREATS = {
    "Ransomware Indicators": [r"decrypt", r"encrypt", r"private_key", r"recover_files", r"\.locked"],
    "Registry Tampering": [r"reg add", r"HKEY_LOCAL_MACHINE", r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "Security Disabling": [r"netsh advfirewall", r"Set-MpPreference", r"DisableRealtimeMonitoring", r"taskkill /f /im"],
    "Stealer/Spyware": [r"cookie", r"password", r"wallet\.dat", r"Login Data", r"autofill"],
    "Environment Leak": [r"\$\{HOME\}", r"\.env", r"AWS_CREDENTIALS", r"vnd\.sun\.star\.expand"], 
    "XFA/SOAP Attack": [r"method=\"soap\"", r"soapAction", r"xdp:xdp", r"XSLT"]
}

def analyze_content(text, depth=0):
    if depth > 2: return []
    
    findings = []
    text_clean = re.sub(r'\s+', ' ', text).strip()
    indicators = { "execution": False, "obfuscation": False, "network": False, "payload": False }
    
    # -------------------------------------------------------------------------
    # 1. External Links & Network Analysis
    # -------------------------------------------------------------------------
    
    link_findings, link_indicators, unc_paths, _ = analyze_links(text)
    findings.extend(link_findings)
    if link_indicators["network"]:
        indicators["network"] = True
        
    # -------------------------------------------------------------------------
    # 2. Evidence Gathering
    # -------------------------------------------------------------------------
    
    # 2.1 Scripting/Execution Logic
    exec_patterns = {
        r"\beval\s*\(": "eval() function",
        r"\bexec\s*\(": "exec() function",
        r"String\.fromCharCode": "Charcode obfuscation",
        r"app\.openDoc": "Remote document opening",
        r"launchURL": "URL launching",
        r"<\s*script": "Embedded HTML Script tag",
        r"new\s+Image\s*\(": "JS-based Beacon (new Image)",
        r"new\s+WebSocket\s*\(": "WebSocket Connection (C2 Channel)"
    }
               
    for p, label in exec_patterns.items():
        if re.search(p, text, re.IGNORECASE):
            indicators["execution"] = True
            findings.append(f"ALERT: Scripting execution pattern detected ({label})")

    # 2.2 Obfuscation Detection
    compact = re.sub(r'\s+', '', text).lower()
    if check_obfuscation(text, compact):
        for key in ["eval", "exec", "unescape"]:
            if key in compact and not re.search(rf"\b{key}\b", text):
                indicators["obfuscation"] = True
                findings.append(f"ALERT: Logic obfuscation detected ({key})")
                
    # 2.3 Auto-Triggers 
    has_open_action = bool(re.search(r"/OpenAction", text, re.IGNORECASE))
    has_aa = bool(re.search(r"/AA", text, re.IGNORECASE))
    has_gotoe = bool(re.search(r"/GoToE", text, re.IGNORECASE))

    if has_open_action and has_aa:
        findings.append("ALERT: Multiple execution triggers (/OpenAction & /AA)")
        indicators["execution"] = True
    elif has_open_action:
        findings.append("ALERT: Automatic execution trigger (/OpenAction)")
        indicators["execution"] = True
    elif has_aa:
        findings.append("ALERT: Event-based execution trigger (/AA)")
        indicators["execution"] = True
    elif has_gotoe:
        findings.append("ALERT: Embedded execution trigger (/GoToE)")
        indicators["execution"] = True
        
    # 2.4 Behavioral Pattern Mapping 
    detected_threats = []
    for threat_name, patterns in SYSTEM_THREATS.items():
        if any(re.search(p, text, re.IGNORECASE) for p in patterns):
            detected_threats.append(threat_name)
            if "Security" in threat_name or "Registry" in threat_name: indicators["execution"] = True
            if "Stealer" in threat_name: indicators["payload"] = True
    
    if detected_threats:
        findings.append(f"ALERT: Specific threats detected: {', '.join(detected_threats)}")

    # 2.5 Financial Indicator Check
    if BTC_ADDRESS.search(text):
        findings.append(f"ALERT: Cryptocurrency address found (Potential Ransomware)")

    # -------------------------------------------------------------------------
    # 3. Layered Analysis
    # -------------------------------------------------------------------------
    
    candidates = B64_PATTERN.findall(text)
    for cand in candidates:
        try:
            decoded = base64.b64decode(cand, validate=True).decode('utf-8', errors='ignore')
            
            if sum(1 for c in decoded if c in string.printable) / len(decoded) > 0.85:
                sub_res = analyze_content(decoded, depth + 1)
                for f in sub_res:
                    if "ALERT" in f:
                        findings.append(f"ALERT: Hidden Layer {depth+1}: {f.replace('ALERT: ', '')}")
        except: continue


    # -------------------------------------------------------------------------
    # 4. Correlation Engine
    # -------------------------------------------------------------------------
    
    has_gotoe = bool(re.search(r"/GoToE", text, re.IGNORECASE))
    
    if has_gotoe and unc_paths:
        findings.append("ALERT: NTLM Relay attack pattern confirmed (GoToE + UNC)")
        
    if (indicators["execution"] or re.search(r"<\s*script", text, re.IGNORECASE)) and indicators["obfuscation"]:
        findings.append("ALERT: High-confidence obfuscated script detected")
        
    if indicators["payload"] and (indicators["execution"] or indicators["network"]):
        findings.append("ALERT: Multi-stage virus detected")

    ent_score = calculate_entropy(text_clean)
    if len(text_clean) > 200 and ent_score > 5.5:
        diag = diagnose_content(text_clean, ent_score)
        findings.append(f"ALERT: {diag} (Entropy: {ent_score:.2f})")

    if any("ALERT" in f for f in findings):
        findings = [f for f in findings if "INFO" not in f]

    return sorted(list(set(findings)))

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def calculate_entropy(data):
    if not data: return 0
    counts = Counter(data)
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in counts.values())

def check_obfuscation(text, compact_text):
    if not text: return False
    original_entropy = calculate_entropy(text)
    compact_entropy = calculate_entropy(compact_text)
    entropy_jump = compact_entropy - original_entropy
    symbols = sum(1 for c in text if c in "{}[]();,.$")
    symbol_density = symbols / len(text) if len(text) > 0 else 0
    return entropy_jump > 0.5 and symbol_density > 0.15 and original_entropy > 4.5

def diagnose_content(text, score):
    if not text: return "Empty"
    sample = text[:200]
    hex_ratio = sum(1 for c in sample if c in string.hexdigits) / len(sample) if len(sample) > 0 else 0
    
    if hex_ratio > 0.8: return "Possible Shellcode Stream"
    if score > 6.5: return "Highly Random Data (Encrypted/Compressed)"
    
    printable_ratio = sum(1 for c in text if c in string.printable) / len(text)
    return "Minified/Compressed Text" if printable_ratio > 0.9 else "Obfuscated Content"