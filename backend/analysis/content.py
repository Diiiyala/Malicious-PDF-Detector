import re, math, logging, base64
from collections import Counter

IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_PATTERN = re.compile(r'https?://[^\s]+', re.IGNORECASE)
SUSPICIOUS_URL_EXT = re.compile(r'\.(exe|zip|sh|py|msi|bat|scr)$', re.IGNORECASE)

def analyze_content(text, depth=0):
    findings = []
    text_clean = text.strip()
    
    # -------------------------------------------------------------------------
    # 1. Enhanced Keyword Analysis
    # -------------------------------------------------------------------------
    try:
        high_risk_checks = {
            "ALERT: Confirmed Malicious Logic": [r"\beval\(", r"\bexec\(", r"String\.fromCharCode"],
            "ALERT: Automatic Trigger": [r"/OpenAction", r"/AA"]
        }

        obf_targets = ["eval", "unescape", "javascript"]
        compact_version = re.sub(r'[\s\W_]+', '', text)

        for message, patterns in high_risk_checks.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(message)
                    break

        for target in obf_targets:
            if re.search(rf"\b{target}\b", text, re.IGNORECASE):
                findings.append(f"ALERT: Suspicious Keyword ({target})")
            elif target in compact_version.lower():
                findings.append(f"ALERT: Obfuscated Scripting Detected ({target})")
            
    except Exception as e:
        logging.error(f"Keyword Analysis failed: {e}")

    # -------------------------------------------------------------------------
    # 2. Smart Layering (Validated Base64 Decoding)
    # -------------------------------------------------------------------------
    if depth < 2:
        b64_candidates = re.findall(r'[A-Za-z0-9+/]{40,}[=]{0,2}', text)
        for candidate in b64_candidates:
            if calculate_entropy(candidate) > 4.5:
                try:
                    decoded_bytes = base64.b64decode(candidate, validate=True)
                    decoded = decoded_bytes.decode('utf-8', errors='ignore')
                    
                    if len(decoded.strip()) > 15 and decoded.strip() != candidate:
                        sub_findings = analyze_content(decoded, depth + 1)
                        
                        if any("ALERT" in f for f in sub_findings):
                            findings.append(f"ALERT: Malicious content hidden in Layer {depth+1}")
                            findings.extend([f"NESTED: {f}" for f in sub_findings])
                except:
                    continue

    # -------------------------------------------------------------------------
    # 3. URL and Verified IP Analysis
    # -------------------------------------------------------------------------
    try:
        urls = URL_PATTERN.findall(text)
        for url in urls:
            clean_url = url.strip('()<>[]"\'')
            if SUSPICIOUS_URL_EXT.search(clean_url):
                findings.append(f"ALERT: Link points to executable file ({clean_url.split('/')[-1]})")
            if IP_PATTERN.search(clean_url):
                findings.append(f"ALERT: Link uses direct IP address (Potential C2 server)")
    except Exception as e:
        logging.error(f"URL Analysis failed: {e}")

    # -------------------------------------------------------------------------
    # 4. Optimized Heuristics (Entropy & Density)
    # -------------------------------------------------------------------------
    try:
        if len(text_clean) > 100:
            ent_score = calculate_entropy(text_clean)
            if ent_score > 5.2:
                findings.append(f"ALERT: High text entropy ({ent_score:.2f})")

        if 0 < len(text_clean) < 40:
            findings.append("ALERT: Extremely low text density")
            
    except Exception as e:
        logging.error(f"Heuristic Analysis failed: {e}")

    return sorted(list(set(findings)))

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def calculate_entropy(data):
    if not data: return 0
    counts = Counter(data)
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in counts.values())