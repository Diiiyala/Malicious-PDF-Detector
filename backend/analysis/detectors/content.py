import re, math, base64, string
from collections import Counter
from analysis.utils.links import analyze_links
from analysis.utils.normalizer import is_valid_decoded

B64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
BTC_ADDRESS = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')

EXEC_PATTERNS = {
    r"\beval\s*\(": "eval() function",
    r"\bexec\s*\(": "exec() function",
    r"String\.fromCharCode": "Charcode obfuscation",
    r"app\.openDoc": "Remote document opening",
    r"launchURL": "URL launching",
    r"<\s*script": "Embedded HTML Script tag",
    r"new\s+Image\s*\(": "JS Beacon",
    r"new\s+WebSocket\s*\(": "WebSocket C2 Channel"
}

SYSTEM_THREATS = {
    "Ransomware Indicators": [r"decrypt", r"encrypt", r"private_key", r"recover_files", r"\.locked"],
    "Registry Tampering": [r"reg add", r"HKEY_LOCAL_MACHINE", r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "Security Disabling": [r"netsh advfirewall", r"Set-MpPreference", r"DisableRealtimeMonitoring", r"taskkill /f /im"],
    "Stealer/Spyware": [r"cookie", r"password", r"wallet\.dat", r"Login Data", r"autofill"],
    "Environment Leak": [r"\$\{HOME\}", r"\.env", r"AWS_CREDENTIALS", r"vnd\.sun\.star\.expand"], 
    "XFA/SOAP Attack": [r"method=\"soap\"", r"soapAction", r"xdp:xdp", r"XSLT", r"<?xml-stylesheet"],
    "XXE Injection Attempt": [r"<!ENTITY", r"SYSTEM\s+['\"]http", r"<!DOCTYPE"],
    "EICAR Standard Anti-Virus Test File": [r"EICAR-STANDARD-ANTIVIRUS", r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR"]
}

def analyze_content(text, depth=0, aggregator=None):
    if depth > 2: return []
    
    findings = []
    text_clean = re.sub(r'\s+', ' ', text).strip()
    indicators = { "execution": False, "obfuscation": False, "network": False, "payload": False }
    
    # ---------------------------------------------------------------------
    # 1. Links Analysis
    # ---------------------------------------------------------------------
    
    link_findings, link_indicators, unc_paths, _ = analyze_links(text)
    findings.extend(link_findings)
    indicators["network"] = link_indicators.get("network", False)
        
    # ---------------------------------------------------------------------
    # 2. Execution Patterns
    # ---------------------------------------------------------------------

    for pattern, label in EXEC_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            indicators["execution"] = True
            findings.append(f"ALERT: Scripting execution pattern detected ({label})")

    # ---------------------------------------------------------------------
    # 3. Obfuscation Detection
    # ---------------------------------------------------------------------

    compact = re.sub(r'\s+', '', text).lower()
    if check_obfuscation(text, compact):
        for key in ["eval", "exec", "unescape"]:
            if key in compact and not re.search(rf"\b{key}\b", text):
                indicators["obfuscation"] = True
                findings.append(f"ALERT: Logic obfuscation detected ({key})")
                
    # ---------------------------------------------------------------------
    # 4. Auto Execution Triggers
    # ---------------------------------------------------------------------

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
     
    # ---------------------------------------------------------------------
    # 5. Threat Mapping
    # ---------------------------------------------------------------------

    detected_threats = []
    
    for threat_name, patterns in SYSTEM_THREATS.items():
        if any(re.search(p, text, re.IGNORECASE) for p in patterns):
            detected_threats.append(threat_name)
    
            if "Security" in threat_name or "Registry" in threat_name:
                indicators["execution"] = True

            if "Stealer" in threat_name:
                indicators["payload"] = True

    if detected_threats:
        findings.append(f"ALERT: Specific threats detected: {', '.join(detected_threats)}")
        
    # ---------------------------------------------------------------------
    # 6. XML / XXE / XFA SOAP Payload Capture
    # ---------------------------------------------------------------------

    if aggregator:
        text_lower = text.lower()

        if any(k in text_lower for k in ["<?xml", "<!doctype", "<xdp:xdp", "method=\"soap\"", "soapaction"]):
            
            if any(re.search(p, text, re.IGNORECASE) for p in SYSTEM_THREATS["XXE Injection Attempt"]):
                aggregator.add_script(
                    text,
                    f"XML/XXE Layer {depth}",
                    script_type="XML/XXE Payload"
                )
            elif "method=\"soap\"" in text_lower or "soapaction" in text_lower:
                aggregator.add_script(
                    text,
                    f"XFA/SOAP Layer {depth}",
                    script_type="XFA/SOAP Payload"
                )
        
    # ---------------------------------------------------------------------
    # 7. Crypto Check
    # ---------------------------------------------------------------------

    if BTC_ADDRESS.search(text):
        findings.append(f"ALERT: Cryptocurrency address found (Potential Ransomware)")

    # ---------------------------------------------------------------------
    # 8. Base64 Layer Analysis
    # ---------------------------------------------------------------------
    
    for cand in B64_PATTERN.findall(text):
        try:
            decoded = base64.b64decode(cand, validate=True).decode('utf-8', errors='ignore')
            
            if is_valid_decoded(decoded) and aggregator:
                aggregator.add_script(decoded, f"Base64 Layer {depth+1}", script_type="Decoded Payload")
            
            if len(decoded) > 0 and (
                sum(c in string.printable for c in decoded) / len(decoded)
                > 0.85
            ):
                sub = analyze_content(decoded, depth + 1, aggregator)
                for f in sub:
                    if "ALERT" in f:
                        findings.append(f"ALERT: Hidden Layer {depth+1}: "f"{f.replace('ALERT: ', '')}")
        except Exception: continue

    # ---------------------------------------------------------------------
    # 9. Correlation Engine
    # ---------------------------------------------------------------------
    
    if has_gotoe and unc_paths:
        findings.append("ALERT: NTLM Relay attack pattern confirmed (GoToE + UNC)")
        
    if (indicators["execution"] or re.search(r"<\s*script", text, re.IGNORECASE)) and indicators["obfuscation"]:
        findings.append("ALERT: High-confidence obfuscated script detected")
        
    if indicators["payload"] and (indicators["execution"] or indicators["network"]):
        findings.append("ALERT: Multi-stage virus detected")

    # ---------------------------------------------------------------------
    # 10. Entropy Analysis
    # ---------------------------------------------------------------------

    ent = calculate_entropy(text_clean)
    if len(text_clean) > 200 and ent > 5.5:
        findings.append(f"ALERT: {diagnose_content(text_clean, ent)} "f"(Entropy: {ent:.2f})")

    # ---------------------------------------------------------------------
    # Final cleanup
    # ---------------------------------------------------------------------
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
    
    printable_ratio = sum(1 for c in text if c in string.printable) / len(text) if text else 0
    
    return "Minified/Compressed Text" if printable_ratio > 0.9 else "Obfuscated Content"