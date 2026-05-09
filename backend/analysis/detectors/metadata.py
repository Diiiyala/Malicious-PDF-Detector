import re
from datetime import datetime
from analysis.utils.links import analyze_links

SUSPICIOUS_WORDS = [
    "exploit", "payload", "shell", "malware", "hack", "xss", "script", "eval", 
    "dropper", "backdoor", "reverse_shell", "bind_shell", "stager", "obfuscated", 
    "bypass", "noprofile", "hidden", "executionpolicy", "encodedcommand", 
    "downloadstring", "cmd.exe", "/bin/sh", "/bin/bash", "socket", "pickle", 
    "subprocess", "mimikatz", "pwdump", "keystroke", "keylogger", "credential", "token"
]

HACKING_TOOLS = [
    "metasploit", "cobalt strike", "empire", "veil", "mimikatz", "powersploit",  
    "nishang", "bloodhound", "beacon", "sherlock", "brute ratel", "sliper", 
    "sqlmap", "nmap", "burp suite", "wireshark", "hydra", "aircrack", "responder", 
    "kali linux", "parrot os", "backbox", "pentoo", "blackarch"
]

SUSPICIOUS_SOURCE_INDICATORS = [
    "attacker", "malicious", "script", "exploit", "payload", "shell",
    "dropper", "backdoor", "stager", "bypass", "encoded", "obfuscated",

    "metasploit", "cobalt strike", "mimikatz", "powersploit", "empire",
    "burp", "collaborator", "interact.sh", "jonaslejon", "deepzec",

    "cve-2018-4993", "cve-2019-7089", "cve-2014-8453", "cve-2017-10951",
    "cve-2024-4367", "cve-2020-29075", "cve-2022-28244", "cve-2018-5158",
    "cve-2025-66516", "cve-2025-70401", "cve-2024-12426", "cve-2025-59803",

    "callback", "phone-home", "exfiltration", "tunneling", "beacon",
    "injection", "unauthorized", "suspicious", "leak", "harvesting"
]

TARGET_SOURCE_FIELDS = ["/Author", "/Creator", "/Producer"]

def analyze_metadata(reader):
    findings = []
    suspicious_keywords = set()

    try:
        metadata = reader.metadata
        if not metadata:
            return ["INFO: No metadata found"]
        
        full_metadata_text = " ".join(str(v) for v in metadata.values() if v).lower()
        
        # ---------------------------------------------------------------------
        # 1. Link Analysis
        # ---------------------------------------------------------------------

        link_findings, _, _, _ = analyze_links(full_metadata_text)
        findings.extend(link_findings)
        
        # ---------------------------------------------------------------------
        # 2. Timestamp Analysis
        # ---------------------------------------------------------------------

        analyze_timestamps(metadata, findings)
        
        # -------------------------------------------------------------------------
        # 3. Metadata Field Analysis
        # -------------------------------------------------------------------------
          
        for value in metadata.values():
            if not value:
                continue
            value_str = str(value).strip()
            value_lower = value_str.lower()

            # 3.1 Suspicious keywords
            for word in SUSPICIOUS_WORDS:
                if word in value_lower:
                    suspicious_keywords.add(word)
                                  
            # 3.2 XSS Detection         
            if re.search(r"<\s*script", value_lower) or "javascript:" in value_lower:
                findings.append(f"ALERT: XSS injection attempt detected ({value_str})")
                suspicious_keywords.add("xss")
                
            # 3.3 Oversized Metadata Fields
            if len(value_str) > 200:
                findings.append("INFO: Long metadata field detected")

        if suspicious_keywords:
            findings.append(f"ALERT: Suspicious keywords detected "f"({', '.join(sorted(suspicious_keywords))})")
            
        # -------------------------------------------------------------------------
        # 4. Hacking Tool Detection
        # -------------------------------------------------------------------------
        
        found_tools = [
            tool.capitalize()
            for tool in HACKING_TOOLS
            if tool.lower() in full_metadata_text
        ]
        
        if found_tools:
            findings.append(f"ALERT: Hacking tools detected ({'/'.join(found_tools)})")

        # -------------------------------------------------------------------------
        # 5. Suspicious Source Analysis
        # -------------------------------------------------------------------------
        
        analyze_suspicious_sources(metadata, findings)

    except Exception as e:
        findings.append(f"Metadata error: {str(e)}")

    return findings

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def analyze_timestamps(metadata, findings):

    try:
        creation_date = metadata.get("/CreationDate")
        modification_date = metadata.get("/ModDate")
           
        today_int = int(datetime.now().strftime("%Y%m%d"))

        if not creation_date:
            return
        
        creation_raw = re.sub(r"[^0-9]", "", str(creation_date))[:8]
        
        if len(creation_raw) != 8:
            return 
            
        creation_pretty = (
            f"{creation_raw[:4]}-"
            f"{creation_raw[4:6]}-"
            f"{creation_raw[6:]}"
        )
        
        if int(creation_raw) > today_int:
            findings.append(f"ALERT: Future creation date detected ({creation_pretty})")

        if not modification_date:
            return
        
        modification_raw = re.sub(r"[^0-9]", "", str(modification_date))[:8]

        if len(modification_raw) != 8:
            return

        modification_pretty = (
            f"{modification_raw[:4]}-"
            f"{modification_raw[4:6]}-"
            f"{modification_raw[6:]}"
        )
        if int(modification_raw) < int(creation_raw):
            findings.append("ALERT: Timestamp anomaly detected "f"(Created: {creation_pretty}, "f"Modified: {modification_pretty})")

        if int(modification_raw) > today_int:
            findings.append(f"ALERT: Future modification date detected "f"({modification_pretty})")
            
    except Exception: pass

    
def analyze_suspicious_sources(metadata, findings):

    found_details = set()

    for field in TARGET_SOURCE_FIELDS:
        if field not in metadata:
            continue

        value_lower = str(metadata[field]).lower()
        field_name = field.replace("/", "")

        for indicator in SUSPICIOUS_SOURCE_INDICATORS:
            if indicator in value_lower:
                found_details.add(f"{field_name}/{indicator.capitalize()}")

    if found_details:
        findings.append("ALERT: Suspicious metadata source detected "f"({', '.join(sorted(found_details))})")