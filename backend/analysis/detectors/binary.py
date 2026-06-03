import re
from analysis.utils.models import ExtractedContent, Threat
from analysis.utils.normalizer import normalize_all, decode_pdf_octal, decode_pdf_hex_names

# -----------------------------------------------------------------------
# Threat Signatures
# -----------------------------------------------------------------------

STRUCTURE_PATTERNS = {
    rb"/AA\s*<<\s*/O": ("Silent page trigger (/O or /C)", 12, "BIN-STR-SILENT"),
    rb"/OpenAction": ("Automatic execution trigger (/OpenAction)", 10, "BIN-STR-OPEN"),
    rb"/AA": ("Automatic triggers (/AA)", 9, "BIN-STR-AA"),
    rb"/Launch": ("Annotation (/Launch)", 10, "BIN-STR-LAUNCH")
}
    
CONTENT_PATTERNS = {
    rb"/S\s*/URI": ("Direct URI action detected in hidden object", 12, "BIN-URI-ACTION"),
    rb"/JS\s*\(": ("Suspicious Scripting found in malformed object", 11, "BIN-JS-MALFORMED"),
    rb"/JavaScript": ("Suspicious Scripting found", 9, "BIN-JS"),
    rb"/JS\b": ("Suspicious Scripting found", 9, "BIN-JS"),
    rb"/SubmitForm": ("Form submission trigger (/SubmitForm) found in raw data", 11, "BIN-SUBMIT"),
    rb"application/x-formcalc": ("Scripting indicators found in raw binary data (FormCalc)", 13, "BIN-FORMCALC"),
    rb"<?xml-stylesheet": ("Scripting indicators found in raw binary data (XSLT/XML)", 13, "BIN-XSLT"),
    rb"/RichMedia": ("RichMedia object (Potential exploit carrier) found in raw data", 10, "BIN-RICHMEDIA"),
    rb"/Crypt": ("Custom encryption filter (/Crypt) found in raw data", 8, "BIN-CRYPT"),
    rb"/JBIG2Decode": ("Suspicious compression filter (/JBIG2Decode) detected", 8, "BIN-JBIG2"),
    rb"<template": ("Specific threats detected: XFA/SOAP Attack", 13, "BIN-XFA-SOAP"),
    rb"<subform": ("Specific threats detected: XFA/SOAP Attack", 13, "BIN-XFA-SOAP"),
    rb"<img\s+src=": ("XSS injection attempt detected via HTML tag", 12, "BIN-XSS"),
    rb"onerror\s*=": ("XSS injection attempt detected via HTML tag", 12, "BIN-XSS"),
    rb'method="soap"': ("Specific threats detected: XFA/SOAP Attack", 13, "BIN-XFA-SOAP"),
    rb'soapAction': ("Specific threats detected: XFA/SOAP Attack", 13, "BIN-XFA-SOAP"),
    rb"vnd\.sun\.star\.expand": ("Specific threats detected: Environment Leak Pattern (LibreOffice)", 12, "BIN-ENV-LEAK"),
    rb"<!DOCTYPE": ("XXE Injection Attempt", 13, "BIN-XXE"),
    rb"<!ENTITY": ("XXE Injection Attempt", 13, "BIN-XXE"),
    rb"SYSTEM\s+[\"']": ("XXE Injection Attempt", 13, "BIN-XXE"),
    rb"PUBLIC\s+[\"']": ("XXE Injection Attempt", 13, "BIN-XXE"),
    rb"file://": ("XXE Injection Attempt", 13, "BIN-XXE"),
    rb"expect://": ("XXE Injection Attempt", 13, "BIN-XXE"),
}
 
# -----------------------------------------------------------------------
# Aggregator Maps
# -----------------------------------------------------------------------
   
SCRIPT_TYPE_MAP = {
    rb"/JavaScript": "JavaScript",
    rb"/JS": "JavaScript",
    rb"/JS\b": "JavaScript",
    rb"/JS\s*\(": "JavaScript",
    rb"application/x-formcalc": "XFA/FormCalc",
    rb"<?xml-stylesheet": "XSLT/XML",
    rb"<template": "XFA/XML-Form",
    rb"<subform": "XFA/XML-Form",
    rb'method="soap"': "XFA/SOAP Payload",
    rb'soapAction': "XFA/SOAP Payload",
    rb"<img\s+src=": "Stored XSS Payload",
    rb"onerror\s*=": "Stored XSS Payload",
    rb"vnd\.sun\.star\.expand": "Environment Leak Exploit",
    rb"<!DOCTYPE": "XML/XXE Payload",
    rb"<?xml": "XML/XXE Payload"
}

AGGREGATOR_PATTERNS = set(SCRIPT_TYPE_MAP.keys())

def analyze_binary(content: ExtractedContent, aggregator=None) -> list[Threat]:
    threats = []
    file_content = content.raw_binary
    
    if not file_content:
        return threats
    
    # ------------------------------------------------------------------
    # 1. Extract standard paths & URIs
    # ------------------------------------------------------------------

    threats.extend(extract_embedded_paths(file_content))  
    threats.extend(extract_hidden_uris(file_content))
    
    # ------------------------------------------------------------------
    # 2. Structure-based detection
    # ------------------------------------------------------------------

    for pattern, (desc, severity, t_id) in STRUCTURE_PATTERNS.items():
        if re.search(pattern, file_content, re.IGNORECASE):
            threats.append(Threat(
                id=t_id, category="Binary Structure", severity=severity, 
                description=desc, location="Raw Binary"
            ))
                          
    # ------------------------------------------------------------------
    # 3. Content-based detection & Script Aggregation
    # ------------------------------------------------------------------
    processed_offsets = set() 
    processed_snippets = set()
    
    for pattern, (desc, severity, t_id) in CONTENT_PATTERNS.items():
        matches = list(re.finditer(pattern, file_content, re.IGNORECASE))

        if not matches: continue
        for match in matches: 
            start = match.start()
            
            # ----------------------------------------------------------
            # Contextual Detection
            # ----------------------------------------------------------

            context = detect_pdf_context(file_content, start)
            context_str = ", ".join(context)
            keyword_found = pattern.decode('utf-8', errors='ignore')
            
            threats.append(Threat(
                id=t_id,
                category="Binary Content",
                severity=severity,
                description=f"{desc} (Found: '{keyword_found}')",
                location=f"Offset: {start} [Context: {context_str}]"
            ))
                
            # ----------------------------------------------------------
            # Aggregator Extraction
            # ----------------------------------------------------------

            if aggregator and pattern in AGGREGATOR_PATTERNS:
                detected_type = SCRIPT_TYPE_MAP.get(pattern, "Binary Discovery")
                
                if any(abs(start - old_offset) < 1500 for old_offset in processed_offsets):
                    continue
                
                if detected_type in ["XFA/SOAP Payload", "XML/XXE Payload", "Environment Leak Exploit", "XFA/XML-Form", "XSLT/XML"]:
                    raw_chunk = file_content[start:start + 1500]
                    snippet = raw_chunk.decode('utf-8', errors='ignore')

                    if "xml-stylesheet" in snippet and "?>" in snippet:
                        snippet = snippet.split("?>")[0] + "?>"
                    elif "endstream" in snippet:
                        snippet = snippet.split("endstream")[0] + "endstream"
                    elif "</xdp:xdp>" in snippet:
                        snippet = snippet.split("</xdp:xdp>")[0] + "</xdp:xdp>"
                    elif "</template>" in snippet:
                        snippet = snippet.split("</template>")[0] + "</template>"
        
                    clean_snippet = snippet.strip()
                else:
                    raw_chunk = file_content[start:start + 1000]
                    paren_start = raw_chunk.find(b'(')
                    
                    if paren_start != -1:
                        depth = 0
                        chunk_content = bytearray()
                        
                        for i in range(paren_start, len(raw_chunk)):
                            char = raw_chunk[i]
                            if char == ord(b'('):
                                depth += 1
                                chunk_content.append(char)
                            elif char == ord(b')'):
                                depth -= 1
                                chunk_content.append(char)
                                if depth == 0:
                                    break
                                continue
                            else:
                                chunk_content.append(char)
                            
                        snippet = chunk_content.decode('utf-8', errors='ignore')
                    else:
                        snippet = raw_chunk.decode('utf-8', errors='ignore')
                    
                    clean_snippet = snippet.strip()
                    while True:
                        prev_len = len(clean_snippet)
                        clean_snippet = re.sub(r'^(?:/JavaScript|/JS)\b', '', clean_snippet, flags=re.IGNORECASE).strip()
                        clean_snippet = re.sub(r'^\(\s*', '', clean_snippet).strip()
                        
                        if len(clean_snippet) == prev_len:
                            break
                
                    if clean_snippet.endswith(')'):
                        clean_snippet = clean_snippet[:-1].strip()
                    
                normalized_snippet = normalize_all(clean_snippet)     
                
                if normalized_snippet not in processed_snippets and normalized_snippet.strip():
                    processed_offsets.add(start)
                    processed_snippets.add(normalized_snippet)                          
                    aggregator.add_script(normalized_snippet, f"Raw Binary Scan (Pos: {start})", script_type=detected_type)
                    
    return threats

# -----------------------------------------------------------------------
#  Helpers
# -----------------------------------------------------------------------     
        
def detect_pdf_context(file_content, position):
    search_window = file_content[max(0, position - 3000):position]

    context_checks = [
        (rb"/AcroForm", "/AcroForm"),
        (rb"/XFA", "/XFA stream"),
        (rb"/Metadata", "/Metadata"),
        (rb"/Subtype\s*/XML", "XML stream"),
        (rb"/EmbeddedFile", "/EmbeddedFile stream"),
        (rb"/ObjStm", "/ObjStm"),
        (rb"/Names", "/Names object"),
        (rb"/EmbeddedFiles", "/EmbeddedFiles object"),
    ]

    detected = []
    for pattern, label in context_checks:
        if re.search(pattern, search_window, re.IGNORECASE):
            detected.append(label)

    return detected or ["/Unknown"]


def extract_embedded_paths(file_content) -> list[Threat]:
    threats = []
    raw_f_matches = re.finditer(rb'/F\s*\(', file_content)

    for match in raw_f_matches:
        start_pos = match.end()
        depth = 1
        content = bytearray()

        for i in range(start_pos, len(file_content)):
            char = file_content[i]
            if char == ord(b'('):
                depth += 1
            elif char == ord(b')'):
                depth -= 1
                if depth == 0:
                    break
            content.append(char)

        path_str = content.decode('utf-8', errors='ignore')
        path_str = decode_pdf_octal(path_str)
        path_str = decode_pdf_hex_names(path_str)
        
        threats.append(Threat(
            id="BIN-REMOTE-PATH", category="Binary Discovery", severity=11,
            description=f"Remote path detected (/F) (Found: '{path_str}')", location="Raw Binary"
        ))

    return threats


def extract_hidden_uris(file_content) -> list[Threat]:
    threats = []
    raw_uris = re.findall(rb'/URI\s*\((.*?)\)', file_content)

    for uri in raw_uris:
        uri_str = uri.decode('utf-8', errors='ignore')
        uri_str = decode_pdf_octal(uri_str)
        uri_str = decode_pdf_hex_names(uri_str)
        
        threats.append(Threat(
            id="BIN-HIDDEN-URI", category="Binary Discovery", severity=12,
            description=f"Hidden URI found in raw scan (Found: '{uri_str}')", location="Raw Binary"
        ))

    return threats
