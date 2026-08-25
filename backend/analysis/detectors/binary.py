import re, ipaddress
from analysis.utils.models import ExtractedContent, Threat
from analysis.utils.normalizer import normalize_all, decode_pdf_octal, decode_pdf_hex_names
from analysis.signatures import (
    SUSPICIOUS_URI_KEYWORDS,
    STRUCTURE_PATTERNS,
    CONTENT_PATTERNS,
    SCRIPT_TYPE_MAP,
    AGGREGATOR_PATTERNS,
)

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
        if any(is_structural_match(file_content, m.start())
               for m in re.finditer(pattern, file_content, re.IGNORECASE)):
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

            if not is_structural_match(file_content, start):
                continue

            # ----------------------------------------------------------
            # Contextual Detection
            # ----------------------------------------------------------

            context = detect_pdf_context(file_content, start)
            context_str = ", ".join(context)
            keyword_found = match.group(0).decode('utf-8', errors='ignore').strip()
            
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
        
def is_structural_match(file_content: bytes, position: int, radius: int = 80) -> bool:

    lo = max(0, position - radius)
    hi = min(len(file_content), position + radius)
    window = file_content[lo:hi]
    if not window:
        return False
    printable = sum(1 for b in window if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(window) >= 0.80


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

def extract_pdf_literal_string(data: bytes, start_pos: int) -> str | None:

    depth = 1
    escaped = False
    result = bytearray()

    for i in range(start_pos, len(data)):
        c = data[i]

        if escaped:
            result.append(c)
            escaped = False
            continue

        if c == ord('\\'):
            escaped = True
            result.append(c)
            continue

        if c == ord('('):
            depth += 1
            result.append(c)
            continue

        if c == ord(')'):
            depth -= 1
            if depth == 0:
                break
            result.append(c)
            continue

        result.append(c)

    try:
        value = result.decode("utf-8", errors="ignore").strip()
        value = decode_pdf_octal(value)
        value = decode_pdf_hex_names(value)
        return value
    
    except Exception:
        return None

def is_valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except Exception:
        return False

def contains_ip(text: str) -> bool:
    candidates = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)
    for candidate in candidates:
        if is_valid_ip(candidate):
            return True
    return False

def extract_hidden_uris(file_content: bytes) -> list[Threat]:
    threats = []

    for match in re.finditer(rb'/URI\s*\(', file_content):
        if not is_structural_match(file_content, match.start()):
            continue

        uri = extract_pdf_literal_string(file_content, match.end())

        if not uri:
            continue

        uri_lower = uri.lower()
        suspicious = (any(k in uri_lower for k in SUSPICIOUS_URI_KEYWORDS) or contains_ip(uri))

        if suspicious:
            threats.append(Threat(
                id="URI-DETECTED", category="Network / Links", severity=8,
                description=f"Suspicious URI detected ('{uri}')", location="Raw Binary"
            ))

    for match in re.finditer(rb'/URI\s*<([0-9A-Fa-f]+)>', file_content):
        if not is_structural_match(file_content, match.start()):
            continue
        try:
            uri = bytes.fromhex(match.group(1).decode()).decode("utf-8", errors="ignore").strip()
            uri_lower = uri.lower()
            
            suspicious = (any(k in uri_lower for k in SUSPICIOUS_URI_KEYWORDS) or contains_ip(uri))

            if suspicious:
                threats.append(Threat(
                    id="URI-DETECTED-HEX", category="Network / Links", severity=8,
                    description=f"Suspicious Hex URI detected ('{uri}')", location="Raw Binary"
                ))
        except Exception:
            pass

    return threats

def extract_embedded_paths(file_content) -> list[Threat]:
    threats = []

    for match in re.finditer(rb'/F\s*\(', file_content):
        if not is_structural_match(file_content, match.start()):
            continue

        path = extract_pdf_literal_string(file_content, match.end())

        if not path: continue
        if "endstream" in path.lower() or "endobj" in path.lower(): continue

        path_lower = path.lower()

        suspicious = (
            any(k in path_lower for k in SUSPICIOUS_URI_KEYWORDS)
            or contains_ip(path)
        )

        very_long = len(path) > 500

        if suspicious or very_long:
            severity = 11

            if re.search(r'(powershell|cmd\.exe|wscript|cscript)', path_lower):
                severity = 12

            threats.append(Threat(
                id="BIN-REMOTE-PATH", category="Binary Discovery", severity=severity,
                description=f"Remote path detected (/F) ('{path}')", location="Raw Binary"
            ))

    return threats