import re, math, logging, base64, string
from collections import Counter

IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_PATTERN = re.compile(r'https?://[^\s]+', re.IGNORECASE)
SUSPICIOUS_URL_EXT = re.compile(r'\.(exe|zip|sh|py|msi|bat|scr)$', re.IGNORECASE)

def analyze_content(text, depth=0):
    findings = []
    text_clean = text.strip()
    
    # -------------------------------------------------------------------------
    # 1. Evidence Gathering
    # -------------------------------------------------------------------------
    indicators = {
        "execution": False,
        "obfuscation": False,
        "network": False,
        "payload": False
    }

    # 1.1 Scripting/Execution Logic
    exec_patterns = [r"\beval\(", r"\bexec\(", r"String\.fromCharCode"]
    for p in exec_patterns:
        if re.search(p, text, re.IGNORECASE):
            indicators["execution"] = True
            findings.append(f"INFO: Scripting execution pattern detected ({p.strip(r'|')})")

    # 1.2 Obfuscation Detection (Correlation-based)
    compact_version = re.sub(r'[\s\W_]+', '', text).lower()
    obf_keys = ["unescape", "base64", "eval", "exec"] # javascript removed as it's too noisy
    for key in obf_keys:
        if key in compact_version and not re.search(rf"\b{key}\b", text, re.IGNORECASE):
            indicators["obfuscation"] = True
            findings.append(f"ALERT: Obfuscated logic detected ({key})")

    # 1.3 Auto-Triggers 
    if re.search(r"/OpenAction", text, re.IGNORECASE):
        findings.append("ALERT: Automatic execution on file open detected (/OpenAction)")
        indicators["execution"] = True 

    if re.search(r"/AA", text, re.IGNORECASE):
        findings.append("ALERT: Event-based execution trigger detected (/AA - Additional Actions)")
        indicators["execution"] = True

    # -------------------------------------------------------------------------
    # 2. Smart Layering 
    # -------------------------------------------------------------------------
    if depth < 2:
        b64_candidates = re.findall(r'[A-Za-z0-9+/]{40,}[=]{0,2}', text)
        for candidate in b64_candidates:
            if calculate_entropy(candidate) > 4.5:
                try:
                    decoded = base64.b64decode(candidate, validate=True).decode('utf-8', errors='ignore')
                    if len(decoded.strip()) > 15:
                        sub_findings = analyze_content(decoded, depth + 1)
                        if any("ALERT" in f or "INFO" in f for f in sub_findings):
                            indicators["payload"] = True
                            findings.extend([f"SUB-LAYER-{depth+1}: {f}" for f in sub_findings])
                except: continue

    # -------------------------------------------------------------------------
    # 3. Network Indicators
    # -------------------------------------------------------------------------
    urls = URL_PATTERN.findall(text)
    for url in urls:
        clean_url = url.strip('()<>[]"\'')
        if SUSPICIOUS_URL_EXT.search(clean_url) or IP_PATTERN.search(clean_url):
            indicators["network"] = True
            findings.append(f"INFO: Suspicious network indicator: {clean_url}")

    # -------------------------------------------------------------------------
    # 4. The Correlation Engine
    # -------------------------------------------------------------------------
    if indicators["execution"] and indicators["obfuscation"]:
        findings.append("ALERT: High-confidence obfuscated malware script detected")
        
    if indicators["payload"] and (indicators["execution"] or indicators["network"]):
        findings.append("ALERT: Multi-stage delivery payload detected in decoded layer")

    if len(text_clean) > 200:
        ent_score = calculate_entropy(text_clean)
        if ent_score > 5.5:
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

def diagnose_content(text, score):
    hex_chars = set(string.hexdigits)
    if sum(1 for c in text[:100] if c in hex_chars) > 80:
        return "Possible Shellcode Stream"
    if score > 6.8:
        return "Highly Random Data (Encrypted/Compressed)"
    
    printable_ratio = sum(1 for c in text if c in string.printable) / len(text)
    if printable_ratio > 0.9:
        return "Minified/Compressed Text"
        
    return "Obfuscated Content"