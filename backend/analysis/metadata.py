import re, base64, codecs, urllib.parse
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
    decoded_values = []
    all_keywords = set()

    try:
        metadata = reader.metadata
        if not metadata:
            findings.append("No metadata found")
            return findings
        
        full_metadata_text = " ".join([str(v) for v in metadata.values() if v]).lower()
        
        # -----------------------
        #  Timestamp Anomaly & Future Date
        # -----------------------
            
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
        
        # -----------------------
        #   Individual Metadata Field Analysis
        # -----------------------  
          
        for key, value in metadata.items():
            if not value:
                continue
            val = str(value).strip()
            val_lower = val.lower()

            # -----------------------
            # Suspicious keywords
            # -----------------------
            
            for word in SUSPICIOUS_WORDS:
                if word in val_lower:
                    all_keywords.add(word)
                    
            # -----------------------
            #  URLs
            # -----------------------     
                           
            urls = re.findall(r'https?://\S+', val)
            for url in urls:
                clean_url = url.strip('()<>[]"\'')

                if any(x in clean_url.lower() for x in MALICIOUS_PARAMS):
                    findings.append(f"ALERT: Suspicious link detected ({clean_url})")
                else:
                    findings.append(f"INFO: Link found ({clean_url})")
                    
            # -----------------------
            #  XSS
            # -----------------------
            
            if re.search(r'<\s*script', val_lower) or "javascript:" in val_lower:
                findings.append(f"ALERT: XSS injection attempt detected ({val})")
                all_keywords.add("xss")

            # -----------------------
            #  Base64
            # -----------------------
            
            if len(val) > 50 and is_base64(val):
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                    if readable_text(decoded):
                        findings.append(f"ALERT: Encoded Base64 payload detected ({decoded})")
                except: pass

            # -----------------------
            # Hex decoding
            # -----------------------
            
            try:
                hex_clean = re.sub(r'[^0-9a-fA-F]', '', val)
                
                if len(hex_clean) >= 8 and len(hex_clean) % 2 == 0: 
                    try:
                        hex_bytes = bytes.fromhex(hex_clean)
                        hex_decoded = hex_bytes.decode("utf-8", errors="ignore")
                        
                        if readable_text(hex_decoded, threshold=0.8):
                            if any(x in hex_decoded.lower() for x in ["http", "cmd", "script", "powershell"]):
                                findings.append(f"ALERT: Encoded Hex payload detected ({hex_decoded})")
                    except: pass
            except: pass

            # -----------------------
            # ROT13 decoding
            # -----------------------
            
            try:
                val_stripped = val.strip()
                if re.fullmatch(r'[A-Za-z0-9_:/.-]+', val_stripped):
                    if not val_stripped.lower().startswith(('http', 'www', '<script')):                      
                        rot13_decoded = codecs.decode(val_stripped, 'rot_13')                    
                        if readable_text(rot13_decoded) and rot13_decoded.lower() != val_stripped.lower():
                            if any(x in rot13_decoded.lower() for x in ["http", "cmd", "script", "admin"]):
                                findings.append(f"ALERT: Encoded ROT13 payload detected ({rot13_decoded})")
            except Exception: pass

            # -----------------------
            # URL decoding
            # -----------------------
            
            try:
                url_decoded = urllib.parse.unquote(val)
                if url_decoded != val and readable_text(url_decoded):
                    decoded_values.append(f"URL decoded: {url_decoded}")
                    if any(x in url_decoded.lower() for x in ["cmd", "powershell", "script"]):
                        findings.append(f"ALERT: Encoded URL payload detected ({url_decoded})")
            except: pass
            
            # -----------------------
            #  Length and Obfuscation
            # -----------------------
            
            if len(val) > 200:
                findings.append("INFO: Long metadata field detected")

            non_ascii_ratio = sum(1 for c in val if ord(c) > 127) / len(val)
            if non_ascii_ratio > 0.3:
                percentage = int(non_ascii_ratio * 100)
                findings.append(f"ALERT: Potential obfuscation detected ({percentage}% non-ASCII characters)")


        if all_keywords:
            findings.append(f"ALERT: Suspicious keywords detected ({', '.join(all_keywords)})")
            
        # -----------------------
        #  Hacking tools
        # ----------------------- 
        
        found_tools = [tool.capitalize() for tool in HACKING_TOOLS if tool.lower() in full_metadata_text]
        
        if found_tools:
            tools_str = "/".join(found_tools)
            findings.append(f"ALERT: Hacking tools detected ({tools_str})")

        # -----------------------
        #  Suspicious sources
        # ----------------------- 
        
        sources_found = set()
        
        target_fields = ["/Author", "/Creator", "/Producer"]
        suspicious_indicators = ["attacker", "malicious", "script"]

        for field in target_fields:
            if field in metadata:
                val_lower = str(metadata[field]).lower()
                for indicator in suspicious_indicators:
                    if indicator in val_lower:
                        sources_found.add(indicator.capitalize())

        if sources_found:
            indicators_str = "/".join(sources_found)
            findings.append(f"ALERT: Suspicious metadata source detected ({indicators_str})")
         
         
        findings.extend(decoded_values)
                            
    except Exception as e:
        findings.append(f"Metadata error: {str(e)}")

    return findings

# -----------------------
#  Helpers
# -----------------------

def is_base64(s):
    try:
        if not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
            return False
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except:
        return False


def readable_text(s, threshold=0.6):
    """Return True if at least `threshold` fraction of chars are printable ASCII"""
    if not s:
        return False
    ratio = sum(1 for c in s if 32 <= ord(c) <= 126) / len(s)
    return ratio >= threshold