import re

def binary_scan(file_content, aggregator=None):
    content_findings = []
    structure_findings = []
    
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
        structure_findings.append(f"ALERT: Remote PDF embedded link (/GoToE) pointing to: ({path_str})")
    
    structure_patterns = {
        rb"/AA\s*<<\s*/O": "ALERT: Silent page trigger (/O or /C)",
        rb"/OpenAction": "ALERT: Auto-executable (/OpenAction)",
        rb"/AA": "ALERT: Automatic triggers (/AA)",
        rb"/Launch": "ALERT: Annotation (/Launch)"
    }
    
    content_patterns = {
        rb"/S\s*/URI": "ALERT: Direct URI action detected in hidden object",
        rb"/JS\s*\(": "ALERT: Scripting indicator found in malformed object",
        rb"/SubmitForm": "ALERT: Form submission trigger (/SubmitForm) found in raw data",
        rb"/JavaScript": "ALERT: Suspicious Scripting found",
        rb"/JS": "ALERT: Suspicious Scripting found",
        rb"application/x-formcalc": "ALERT: Scripting indicators found in raw binary data (FormCalc)",
        rb"<?xml-stylesheet": "ALERT: Scripting indicators found in raw binary data (XSLT/XML)",
        rb"/RichMedia": "ALERT: RichMedia object (Potential exploit carrier) found in raw data",
        rb"/Crypt": "ALERT: Custom encryption filter (/Crypt) found in raw data",
        rb"/JBIG2Decode": "ALERT: Suspicious compression filter (/JBIG2Decode) detected"
    }
    
    for pattern, message in structure_patterns.items():
        if re.search(pattern, file_content, re.IGNORECASE):
            structure_findings.append(message)
            
    for pattern, message in content_patterns.items():       
        if re.search(pattern, file_content, re.IGNORECASE):
            content_findings.append(message)
            
        if aggregator and pattern in [rb"/JavaScript", rb"/JS", rb"application/x-formcalc", rb"<?xml-stylesheet"]:
            for match in re.finditer(pattern, file_content, re.IGNORECASE):
                start = match.start()
                snippet = file_content[start : start + 500].decode('utf-8', errors='ignore')
                aggregator.add_script(snippet, f"Raw Binary Scan (Pos: {start})", script_type="Binary Discovery")
            
    raw_uris = re.findall(rb'/URI\s*\((.*?)\)', file_content)
    for uri in raw_uris:
        uri_str = uri.decode('utf-8', errors='ignore')
        content_findings.append(f"ALERT: Hidden URI found in raw scan: {uri_str}")
        
    return content_findings, structure_findings