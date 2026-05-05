import re
from datetime import datetime

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

MALICIOUS_PARAMS = ["php", "exe", "sh", "py", "cmd", "cookie", "steal", "script"]

def analyze_metadata(reader):
    findings = []
    all_keywords = set()

    try:
        metadata = reader.metadata
        if not metadata:
            findings.append("INFO: No metadata found")
            return findings
        
        full_metadata_text = " ".join([str(v) for v in metadata.values() if v]).lower()
        
        analyze_timestamps(metadata, findings)
        
        # -------------------------------------------------------------------------
        # 1. Individual Metadata Field Analysis
        # -------------------------------------------------------------------------
          
        for key, value in metadata.items():
            if not value:
                continue
            val = str(value).strip()
            val_lower = val.lower()

            # -------------------------------------------------------------------------
            # 1.1 Suspicious keywords
            # -------------------------------------------------------------------------
            
            for word in SUSPICIOUS_WORDS:
                if word in val_lower:
                    all_keywords.add(word)
                    
            # -------------------------------------------------------------------------
            #  1.2 URLs
            # -------------------------------------------------------------------------     
                           
            urls = re.findall(r'https?://\S+', val)
            for url in urls:
                clean_url = url.strip('()<>[]"\'')

                if any(x in clean_url.lower() for x in MALICIOUS_PARAMS):
                    findings.append(f"ALERT: Suspicious link detected ({clean_url})")
                    
            # -------------------------------------------------------------------------
            # 1.3 XSS
            # -------------------------------------------------------------------------
            
            if re.search(r'<\s*script', val_lower) or "javascript:" in val_lower:
                findings.append(f"ALERT: XSS injection attempt detected ({val})")
                all_keywords.add("xss")
            
            # -------------------------------------------------------------------------
            # 1.4 Length
            # -------------------------------------------------------------------------
            
            if len(val) > 200:
                findings.append("INFO: Long metadata field detected")

        if all_keywords:
            findings.append(f"ALERT: Suspicious keywords detected ({', '.join(all_keywords)})")
            
        # -------------------------------------------------------------------------
        # 2. Hacking tools
        # -------------------------------------------------------------------------
        
        found_tools = [tool.capitalize() for tool in HACKING_TOOLS if tool.lower() in full_metadata_text]
        
        if found_tools:
            tools_str = "/".join(found_tools)
            findings.append(f"ALERT: Hacking tools detected ({tools_str})")

        # -------------------------------------------------------------------------
        # 3. Suspicious sources
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
        mod_date = metadata.get("/ModDate")   
        today_str = datetime.now().strftime('%Y%m%d')
        today_int = int(today_str)

        if creation_date:
            c_raw = re.sub(r'[^0-9]', '', str(creation_date))[:8]
            if len(c_raw) == 8:
                c_pretty = f"{c_raw[:4]}-{c_raw[4:6]}-{c_raw[6:]}"                    
                if int(c_raw) > today_int:
                    findings.append(f"ALERT: Future creation date detected ({c_pretty})")
                if mod_date:
                    m_raw = re.sub(r'[^0-9]', '', str(mod_date))[:8]
                    if len(m_raw) == 8:
                        m_pretty = f"{m_raw[:4]}-{m_raw[4:6]}-{m_raw[6:]}"
                        if int(m_raw) < int(c_raw):
                            findings.append(f"ALERT: Timestamp anomaly detected (Created: {c_pretty}, Modified: {m_pretty})")                             
                        if int(m_raw) > today_int:
                            findings.append(f"ALERT: Future modification date detected ({m_pretty})")
    except Exception: pass

    
def analyze_suspicious_sources(metadata, findings):

    sources_found = set()
        
    target_fields = ["/Author", "/Creator", "/Producer"]
    suspicious_indicators = [
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
    found_details = []
        
    for field in target_fields:
        if field in metadata:
            val_lower = str(metadata[field]).lower()
            for indicator in suspicious_indicators:
                if indicator in val_lower:
                    field_name = field.replace("/", "")
                    found_details.append(f"{field_name}/{indicator.capitalize()}")

    if found_details:
        unique_details = ", ".join(sorted(list(set(found_details))))
        findings.append(f"ALERT: Suspicious metadata source detected ({unique_details})")