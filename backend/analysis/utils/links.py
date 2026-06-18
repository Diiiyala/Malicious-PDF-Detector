import re
from analysis.signatures import SHORTENERS, SUSPICIOUS_KEYWORDS, MALICIOUS_PARAMS

IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_PATTERN = re.compile(r'\b(?:https?|ftp|ftps|file|smb|ssh|telnet|gopher|ldap|mailto|news|nntp|irc|data|javascript|ws|wss|vnd\.sun\.star\.expand)://[^\s"\'\)\(\}\{><,]+', re.IGNORECASE)
UNC_PATTERN = re.compile(r'(?:\\\\|\\\\\\\\)(?:https?://)?[a-zA-Z0-9.-]+\\[^\s\)\>]+', re.IGNORECASE)

JS_URL_PATTERN = re.compile(
    r'(?:(?:cPath|url|uri|location|src|cURL|action|target|soapAction)\s*[:=]\s*(?:encodeURI\s*\(\s*)?["\']?|'
    r'(?:app\.launchURL|this\.getURL|getURL|launchURL)\s*\(\s*(?:encodeURI\s*\(\s*)?["\'])'
    r'([^"\'\s\)\+]+)', 
    re.IGNORECASE
)

def analyze_links(text):
    findings = []
    indicators = {"network": False}
    current_found_urls = []
    
    js_links = JS_URL_PATTERN.findall(text)
    staged_urls = set()
    
    # -------------------------------------------------------------------------
    # 1. Detect JS-staged URLs
    # -------------------------------------------------------------------------
    
    for link in js_links:
        current_found_urls.append(link)
        if URL_PATTERN.match(link) or IP_PATTERN.search(link):
            staged_urls.add(link)
            indicators["network"] = True
    
    if staged_urls:
        sorted_urls_str = ", ".join(sorted(list(staged_urls)))
        findings.append(f"ALERT: Hidden JS-staged URLs detected: [ {sorted_urls_str} ]")
            
    # -------------------------------------------------------------------------
    # 2. Detect suspicious paths & URLs
    # -------------------------------------------------------------------------
    
    unc_paths = UNC_PATTERN.findall(text)
    for unc in unc_paths:
        findings.append(f"ALERT: UNC path detected (Potential NTLM Hash Theft): {unc}")
        indicators["network"] = True
        
    urls = URL_PATTERN.findall(text)
    suspicious_hosts = []
    
    for url in urls:
        c_url = url.strip('()<>[]"\'').lower()
        
        if any(x in c_url for x in MALICIOUS_PARAMS):
            findings.append(f"ALERT: Suspicious link detected ({url})")
            indicators["network"] = True
            
        domain_match = re.search(r'https?://([^/]+)', c_url)
        domain = domain_match.group(1) if domain_match else ""

        if IP_PATTERN.search(domain):
            findings.append(f"ALERT: Direct IP access detected: {domain}")
            indicators["network"] = True

        if any(s in domain for s in SHORTENERS) or any(k in domain for k in SUSPICIOUS_KEYWORDS):
            suspicious_hosts.append(domain)
            indicators["network"] = True
        
        query_params = re.findall(r'[?&]([^=&]+)', c_url)
        if any(p in MALICIOUS_PARAMS for p in query_params):
            findings.append(f"ALERT: Malicious parameter key detected in URL")
            indicators["network"] = True

    if suspicious_hosts:
        unique_hosts = sorted(list(set(suspicious_hosts)))
        findings.append(f"ALERT: Suspicious hosts detected: {', '.join(unique_hosts)}")
            
    return findings, indicators, unc_paths, current_found_urls