import re

def binary_scan(file_content):
    extra_findings = []
    patterns = {
        rb"/AA\s*<<\s*/O": "ALERT: Hidden automatic execution trigger (/AA /O) detected in raw stream",
        rb"/S\s*/URI": "ALERT: Direct URI action detected in hidden object",
        rb"/JS\s*\(": "ALERT: Scripting indicator found in malformed object",
        rb"/OpenAction": "ALERT: Automatic execution trigger found in raw data",
        rb"/AA": "ALERT: Event-based execution trigger found in raw data",
        rb"/Launch": "ALERT: Embedded file launch trigger (/Launch) found in raw data",
        rb"/SubmitForm": "ALERT: Form submission trigger (/SubmitForm) found in raw data",
        rb"/GoToE": "ALERT: Remote PDF embedded link (/GoToE) found in raw data",
        rb"/JavaScript": "ALERT: Scripting indicators found in raw binary data (JavaScript)",
        rb"/JS": "ALERT: Scripting indicators found in raw binary data (JavaScript)",
        rb"application/x-formcalc": "ALERT: Scripting indicators found in raw binary data (FormCalc)",
        rb"<?xml-stylesheet": "ALERT: Scripting indicators found in raw binary data (XSLT/XML)",
        rb"/RichMedia": "ALERT: RichMedia object (Potential exploit carrier) found in raw data",
        rb"/Crypt": "ALERT: Custom encryption filter (/Crypt) found in raw data",
        rb"/JBIG2Decode": "ALERT: Suspicious compression filter (/JBIG2Decode) detected"
    }
    
    for pattern, message in patterns.items():
        if re.search(pattern, file_content, re.IGNORECASE):
            extra_findings.append(message)
            
    raw_uris = re.findall(rb'/URI\s*\((.*?)\)', file_content)
    for uri in raw_uris:
        uri_str = uri.decode('utf-8', errors='ignore')
        extra_findings.append(f"ALERT: Hidden URI found in raw scan: {uri_str}")
        
    return extra_findings

