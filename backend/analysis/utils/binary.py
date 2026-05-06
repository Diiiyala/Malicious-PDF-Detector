import re

def binary_scan(file_content):
    content_findings = []
    structure_findings = []
    
    structure_patterns = {
        rb"/AA\s*<<\s*/O": "ALERT: Silent page trigger (/O or /C)",
        rb"/OpenAction": "ALERT: Auto-executable (/OpenAction)",
        rb"/AA": "ALERT: Automatic triggers (/AA)",
        rb"/Launch": "ALERT: Annotation (/Launch)",
        rb"/GoToE": "ALERT: Remote PDF embedded link (/GoToE)",
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
            
    raw_uris = re.findall(rb'/URI\s*\((.*?)\)', file_content)
    for uri in raw_uris:
        uri_str = uri.decode('utf-8', errors='ignore')
        content_findings.append(f"ALERT: Hidden URI found in raw scan: {uri_str}")
        
    return content_findings, structure_findings