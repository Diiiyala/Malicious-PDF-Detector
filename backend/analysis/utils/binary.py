import re
from collections import defaultdict
from analysis.utils.normalizer import normalize_all

# -----------------------------------------------------------------------
# Threat Signatures
# -----------------------------------------------------------------------

STRUCTURE_PATTERNS = {
    rb"/AA\s*<<\s*/O": "ALERT: Silent page trigger (/O or /C)",
    rb"/OpenAction": "ALERT: Automatic execution trigger (/OpenAction)",
    rb"/AA": "ALERT: Automatic triggers (/AA)",
    rb"/Launch": "ALERT: Annotation (/Launch)"
}
    
CONTENT_PATTERNS = {
    rb"/S\s*/URI": "ALERT: Direct URI action detected in hidden object",
    rb"/JS\s*\(": "ALERT: Suspicious Scripting found in malformed object",
    rb"/JavaScript": "ALERT: Suspicious Scripting found",
    rb"/JS\b": "ALERT: Suspicious Scripting found",
    rb"/SubmitForm": "ALERT: Form submission trigger (/SubmitForm) found in raw data",
    rb"application/x-formcalc": "ALERT: Scripting indicators found in raw binary data (FormCalc)",
    rb"<?xml-stylesheet": "ALERT: Scripting indicators found in raw binary data (XSLT/XML)",
    rb"/RichMedia": "ALERT: RichMedia object (Potential exploit carrier) found in raw data",
    rb"/Crypt": "ALERT: Custom encryption filter (/Crypt) found in raw data",
    rb"/JBIG2Decode": "ALERT: Suspicious compression filter (/JBIG2Decode) detected",
    rb"<template": "ALERT: Specific threats detected: XFA/SOAP Attack",
    rb"<subform": "ALERT: Specific threats detected: XFA/SOAP Attack",
    rb"<img\s+src=": "ALERT: XSS injection attempt detected via HTML tag",
    rb"onerror\s*=": "ALERT: XSS injection attempt detected via HTML tag",
    rb'method="soap"': "ALERT: Specific threats detected: XFA/SOAP Attack",
    rb'soapAction': "ALERT: Specific threats detected: XFA/SOAP Attack",
    rb"vnd\.sun\.star\.expand": "ALERT: Specific threats detected: Environment Leak Pattern (LibreOffice)",
    rb"<!ENTITY": "XXE Injection Attempt",
    rb"SYSTEM\s+[\"']": "XXE Injection Attempt",
    rb"PUBLIC\s+[\"']": "XXE Injection Attempt",
    rb"file://": "XXE Injection Attempt",
    rb"expect://": "XXE Injection Attempt",
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

def binary_scan(file_content, aggregator=None):
    content_findings = defaultdict(set)
    structure_findings = []
    
    # ------------------------------------------------------------------
    # 1. Extract standard paths & URIs
    # ------------------------------------------------------------------

    structure_findings.extend(extract_embedded_paths(file_content))  
    structure_findings.extend(extract_hidden_uris(file_content))
    
    # ------------------------------------------------------------------
    # 2. Structure-based detection
    # ------------------------------------------------------------------

    for pattern, message in STRUCTURE_PATTERNS.items():
        if re.search(pattern, file_content, re.IGNORECASE):

            if message not in structure_findings:
                structure_findings.append(message)
                          
    # ------------------------------------------------------------------
    # 3. Content-based detection & Script Aggregation
    # ------------------------------------------------------------------
    processed_offsets = set() 
    processed_snippets = set()
    
    for pattern, message in CONTENT_PATTERNS.items():
        matches = list(re.finditer(pattern, file_content, re.IGNORECASE))

        if not matches: continue
        for match in matches: 
            start = match.start()
            
            # ----------------------------------------------------------
            # XXE Contextual Detection
            # ----------------------------------------------------------

            context = detect_pdf_context(file_content, start)
            
            if message == "XXE Injection Attempt":
                final_msg = "ALERT: Specific threats detected: XXE Injection Attempt"
                content_findings[final_msg].update(context)
            else:
                content_findings[message].add(f"(Offset: {start})")
                
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
                        content = bytearray()
                        
                        for i in range(paren_start, len(raw_chunk)):
                            char = raw_chunk[i]
                            if char == ord(b'('):
                                depth += 1
                                content.append(char)
                            elif char == ord(b')'):
                                depth -= 1
                                content.append(char)
                                if depth == 0:
                                    break
                                continue
                            else:
                                content.append(char)
                            
                        snippet = content.decode('utf-8', errors='ignore')
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
                    
    # ------------------------------------------------------------------
    # 4. Final Formatting
    # ------------------------------------------------------------------

    final_content_findings = []
    for msg, items in content_findings.items():
        if not items:
            final_content_findings.append(msg)
            continue
        unique_items = sorted(list(items), key=lambda x: int(re.search(r'\d+', x).group()) if re.search(r'\d+', x) else 0)
        joined = ", ".join(unique_items)
        
        if "Specific threats detected" in msg:
            keyword_found = "Detected in Binary"
            for b_pat, b_msg in CONTENT_PATTERNS.items():
                if b_msg == "XXE Injection Attempt" and "XXE" in msg:
                    keyword_found = b_pat.decode('utf-8', errors='ignore')
                    break
                elif b_msg == msg.split(" in (")[0]:
                    keyword_found = b_pat.decode('utf-8', errors='ignore')
                    break
            final_content_findings.append(f"{msg} (Found: '{keyword_found}') in ( {joined} )")
        else:
            final_content_findings.append(f"{msg} in ( {joined} )")

    return final_content_findings, structure_findings

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


def extract_embedded_paths(file_content):

    findings = []
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
        findings.append(f"ALERT: Remote path detected (/F): ({path_str})")

    return findings


def extract_hidden_uris(file_content):

    findings = []
    raw_uris = re.findall(rb'/URI\s*\((.*?)\)', file_content)

    for uri in raw_uris:
        uri_str = uri.decode('utf-8', errors='ignore')
        findings.append(f"ALERT: Hidden URI found in raw scan: {uri_str}")

    return findings
