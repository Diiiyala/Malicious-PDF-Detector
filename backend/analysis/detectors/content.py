import re, base64, string
from itertools import islice
from analysis.utils.models import ExtractedContent, Threat
from analysis.utils.links import analyze_links
from analysis.utils.normalizer import is_valid_decoded
from analysis.utils.text_metrics import calculate_entropy
from analysis.signatures import EXEC_PATTERNS, SYSTEM_THREATS

B64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
BTC_ADDRESS = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')

MAX_MATCHES_PER_PATTERN = 25

def scan_text(text: str, aggregator=None) -> list[Threat]:
    if not text:
        return []
    return _analyze_text_recursive(text, depth=0, aggregator=aggregator)


def analyze_content(content: ExtractedContent, aggregator=None) -> list[Threat]:
    return scan_text(content.extracted_text, aggregator=aggregator)

def _analyze_text_recursive(text: str, depth=0, aggregator=None) -> list[Threat]:
    if depth > 2: return []
    
    threats = []
    text_clean = re.sub(r'\s+', ' ', text).strip()
    indicators = { "execution": False, "obfuscation": False, "network": False, "payload": False }
    
    # ---------------------------------------------------------------------
    # 1. Links Analysis
    # ---------------------------------------------------------------------
    
    link_findings, link_indicators, unc_paths, _ = analyze_links(text)
    
    for lf in link_findings:
        severity = 10 if "UNC" in lf else 6
        threats.append(Threat(
            id="CONT-LINK-DETECTED", 
            category="Content", 
            severity=severity, 
            description=lf.replace("ALERT: ", ""), 
            location=f"Layer {depth}"
        ))
    indicators["network"] = link_indicators.get("network", False)
        
    # ---------------------------------------------------------------------
    # 2. Execution Patterns
    # ---------------------------------------------------------------------

    for pattern, (label, severity) in EXEC_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            indicators["execution"] = True
            threats.append(Threat(
                id="CONT-EXEC-PATTERN", 
                category="Content", 
                severity=severity, 
                description=f"Scripting execution pattern detected ({label})", 
                location=f"Layer {depth}"
            ))

    # ---------------------------------------------------------------------
    # 3. Obfuscation Detection
    # ---------------------------------------------------------------------

    compact = re.sub(r'\s+', '', text).lower()
    if check_obfuscation(text, compact):
        for key in ["eval", "exec", "unescape"]:
            if key in compact and not re.search(rf"\b{key}\b", text):
                indicators["obfuscation"] = True
                threats.append(Threat(
                    id="CONT-LOGIC-OBFUSCATION", 
                    category="Content", 
                    severity=8, 
                    description=f"Logic obfuscation detected ({key})", 
                    location=f"Layer {depth}"
                ))
                
    # ---------------------------------------------------------------------
    # 4. Auto Execution Triggers
    # ---------------------------------------------------------------------

    has_open_action = bool(re.search(r"/OpenAction", text, re.IGNORECASE))
    has_aa = bool(re.search(r"/AA", text, re.IGNORECASE))
    has_gotoe = bool(re.search(r"/GoToE", text, re.IGNORECASE))

    if has_open_action and has_aa:
        threats.append(Threat(id="CONT-TRIG-MULTI", category="Content", severity=10, description="Multiple execution triggers (/OpenAction & /AA)", location=f"Layer {depth}"))
        indicators["execution"] = True
    elif has_open_action:
        threats.append(Threat(id="CONT-TRIG-OPENACTION", category="Content", severity=10, description="Automatic execution trigger (/OpenAction)", location=f"Layer {depth}"))
        indicators["execution"] = True
    elif has_aa:
        threats.append(Threat(id="CONT-TRIG-AA", category="Content", severity=9, description="Event-based execution trigger (/AA)", location=f"Layer {depth}"))
        indicators["execution"] = True
    elif has_gotoe:
        threats.append(Threat(id="CONT-TRIG-GOTOE", category="Content", severity=9, description="Embedded execution trigger (/GoToE)", location=f"Layer {depth}"))
        indicators["execution"] = True
     
    # ---------------------------------------------------------------------
    # 5. Threat Mapping
    # ---------------------------------------------------------------------

    for threat_name, (patterns, severity) in SYSTEM_THREATS.items():
        for p in patterns:
            for match in islice(re.finditer(p, text, re.IGNORECASE), MAX_MATCHES_PER_PATTERN):
                matched_str = match.group(0).strip()
                threats.append(Threat(
                    id=f"CONT-SYS-{threat_name[:4].upper()}", 
                    category="Content", 
                    severity=severity,
                    description=f"{threat_name} (Found: '{matched_str}')",
                    location=f"Offset: {match.start()} (Layer {depth})"
                ))
    
                if "Security" in threat_name or "Registry" in threat_name:
                    indicators["execution"] = True
                if "Stealer" in threat_name:
                    indicators["payload"] = True
        
    # ---------------------------------------------------------------------
    # 6. XML / XXE / XFA SOAP Payload Capture
    # ---------------------------------------------------------------------

    if aggregator:
        text_lower = text.lower()
        if any(k in text_lower for k in ["<?xml", "<!doctype", "<xdp:xdp", "method=\"soap\"", "soapaction"]):
            if any(re.search(p, text, re.IGNORECASE) for p in SYSTEM_THREATS["XXE Injection Attempt"][0]):
                aggregator.add_script(text, f"XML/XXE Layer {depth}", script_type="XML/XXE Payload")
            elif "method=\"soap\"" in text_lower or "soapaction" in text_lower:
                aggregator.add_script(text, f"XFA/SOAP Layer {depth}", script_type="XFA/SOAP Payload")
        
    # ---------------------------------------------------------------------
    # 7. Crypto Check
    # ---------------------------------------------------------------------

    if BTC_ADDRESS.search(text):
        threats.append(Threat(
            id="CONT-CRYPTO-ADDRESS", 
            category="Content", 
            severity=9, 
            description="Cryptocurrency address found (Potential Ransomware)", 
            location=f"Layer {depth}"
        ))

    # ---------------------------------------------------------------------
    # 8. Base64 Layer Analysis
    # ---------------------------------------------------------------------
    
    for cand in B64_PATTERN.findall(text):
        try:
            decoded = base64.b64decode(cand, validate=True).decode('utf-8', errors='ignore')
            
            if is_valid_decoded(decoded) and aggregator:
                aggregator.add_script(decoded, f"Base64 Layer {depth+1}", script_type="Decoded Payload")
            
            if len(decoded) > 0 and (sum(c in string.printable for c in decoded) / len(decoded) > 0.85):
                sub_threats = _analyze_text_recursive(decoded, depth + 1, aggregator)
                threats.extend(sub_threats)
        except Exception: 
            continue

    # ---------------------------------------------------------------------
    # 9. Correlation Engine
    # ---------------------------------------------------------------------
    
    if has_gotoe and unc_paths:
        threats.append(Threat(id="CONT-CORR-NTLM", category="Content", severity=14, description="NTLM Relay attack pattern confirmed (GoToE + UNC)", location=f"Layer {depth}"))
        
    if (indicators["execution"] or re.search(r"<\s*script", text, re.IGNORECASE)) and indicators["obfuscation"]:
        threats.append(Threat(id="CONT-CORR-OBFUSCATED", category="Content", severity=12, description="High-confidence obfuscated script detected", location=f"Layer {depth}"))
        
    if indicators["payload"] and (indicators["execution"] or indicators["network"]):
        threats.append(Threat(id="CONT-CORR-MULTISTAGE", category="Content", severity=15, description="Multi-stage virus detected", location=f"Layer {depth}"))

    # ---------------------------------------------------------------------
    # 10. Entropy Analysis
    # ---------------------------------------------------------------------

    ent = calculate_entropy(text_clean)
    if len(text_clean) > 200 and ent > 6.5:
        diag = diagnose_content(text_clean, ent)
        severity = 8 if "Encrypted" in diag else (5 if "Obfuscated" in diag else 3)
        threats.append(Threat(
            id="CONT-ENTROPY-ANOMALY", 
            category="Content", 
            severity=severity, 
            description=f"{diag} (Entropy: {ent:.2f})", 
            location=f"Layer {depth}"
        ))

    return threats

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

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