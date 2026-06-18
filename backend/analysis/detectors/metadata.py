import re
from datetime import datetime
from analysis.utils.models import ExtractedContent, Threat
from analysis.utils.links import analyze_links
from analysis.signatures import (
    SUSPICIOUS_WORDS,
    HACKING_TOOLS,
    SUSPICIOUS_SOURCE_INDICATORS,
)

TARGET_SOURCE_FIELDS = ["/Author", "/Creator", "/Producer"]

def analyze_metadata(content: ExtractedContent) -> list[Threat]:
    threats = []
    suspicious_keywords = set()

    metadata = content.metadata_dict
    if not metadata:
        return threats
    
    full_metadata_text = " ".join(str(v) for v in metadata.values() if v).lower()
    
    # ---------------------------------------------------------------------
    # 1. Link Analysis
    # ---------------------------------------------------------------------
    
    link_findings, _, _, _ = analyze_links(full_metadata_text)
    for lf in link_findings:
        threats.append(Threat(
            id="META-LINK-DETECTED",
            category="Metadata",
            severity=5,
            description=lf.replace("ALERT: ", ""),
            location="Metadata Text"
        ))
        
    # ---------------------------------------------------------------------
    # 2. Timestamp Analysis
    # ---------------------------------------------------------------------

    threats.extend(analyze_timestamps(metadata))
        
    # -------------------------------------------------------------------------
    # 3. Metadata Field Analysis
    # -------------------------------------------------------------------------
          
    for key, value in metadata.items():
        if not value:
            continue
        value_str = str(value).strip()
        value_lower = value_str.lower()
        field_name = key.replace("/", "")

        # 3.1 Suspicious keywords
        for word in SUSPICIOUS_WORDS:
            if word in value_lower:
                suspicious_keywords.add(word)
                                  
        # 3.2 XSS Detection         
        if re.search(r"<\s*script", value_lower) or "javascript:" in value_lower:
            threats.append(Threat(
                id="META-XSS-ATTEMPT",
                category="Metadata",
                severity=7,
                description=f"XSS injection attempt detected ({value_str[:100]})",
                location=f"Field: {field_name}"
            ))
            suspicious_keywords.add("xss")
                
        # 3.3 Oversized Metadata Fields
        if len(value_str) > 200:
            threats.append(Threat(
                id="META-LONG-FIELD",
                category="Metadata",
                severity=1,
                description=f"Long metadata field detected ({field_name}: {len(value_str)} chars)",
                location=f"Field: {field_name}"
            ))

    if suspicious_keywords:
        threats.append(Threat(
            id="META-SUSPICIOUS-KEYWORD",
            category="Metadata",
            severity=4,
            description=f"Suspicious keywords detected ({', '.join(sorted(suspicious_keywords))})",
            location="Metadata Fields"
        ))   
        
    # -------------------------------------------------------------------------
    # 4. Hacking Tool Detection
    # -------------------------------------------------------------------------
        
    found_tools = [
        tool.capitalize()
        for tool in HACKING_TOOLS
        if tool.lower() in full_metadata_text
    ]
    
    if found_tools:
        threats.append(Threat(
            id="META-HACKING-TOOL",
            category="Metadata",
            severity=9,
            description=f"Hacking tools detected ({'/'.join(found_tools)})",
            location="Metadata Fields"
        ))

    # -------------------------------------------------------------------------
    # 5. Suspicious Source Analysis
    # -------------------------------------------------------------------------
        
    threats.extend(analyze_suspicious_sources(metadata))

    return threats

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def analyze_timestamps(metadata) -> list[Threat]:
    threats = []
    try:
        creation_date = metadata.get("/CreationDate")
        modification_date = metadata.get("/ModDate")
           
        today_int = int(datetime.now().strftime("%Y%m%d"))

        if not creation_date:
            return threats
        
        creation_raw = re.sub(r"[^0-9]", "", str(creation_date))[:8]
        
        if len(creation_raw) != 8:
            return threats
            
        creation_pretty = f"{creation_raw[:4]}-{creation_raw[4:6]}-{creation_raw[6:]}"
        
        if int(creation_raw) > today_int:
            threats.append(Threat(
                id="META-FUTURE-CREATION",
                category="Metadata",
                severity=3,
                description=f"Future creation date detected ({creation_pretty})",
                location="CreationDate"
            ))

        if not modification_date:
            return threats
        
        modification_raw = re.sub(r"[^0-9]", "", str(modification_date))[:8]

        if len(modification_raw) != 8:
            return threats

        modification_pretty = f"{modification_raw[:4]}-{modification_raw[4:6]}-{modification_raw[6:]}"
        
        if int(modification_raw) < int(creation_raw):
            threats.append(Threat(
                id="META-TIMESTAMP-ANOMALY",
                category="Metadata",
                severity=3,
                description=f"Timestamp anomaly detected (Created: {creation_pretty}, Modified: {modification_pretty})",
                location="Timestamps"
            ))

        if int(modification_raw) > today_int:
            threats.append(Threat(
                id="META-FUTURE-MODIFICATION",
                category="Metadata",
                severity=3,
                description=f"Future modification date detected ({modification_pretty})",
                location="ModDate"
                ))
            
    except Exception: 
        pass
    return threats

    
def analyze_suspicious_sources(metadata) -> list[Threat]:
    threats = []
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
        threats.append(Threat(
            id="META-SUSPICIOUS-SOURCE",
            category="Metadata",
            severity=3,
            description=f"Suspicious metadata source detected ({', '.join(sorted(found_details))})",
            location="Source Fields"
        ))
    return threats