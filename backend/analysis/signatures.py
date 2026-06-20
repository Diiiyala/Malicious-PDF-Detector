
# ==========================================================================================
# 1. INDICATORS (HEURISTICS / VOCABULARY SIGNALS)
# ==========================================================================================

# 1.1 URL / link-based indicators

SHORTENERS = ["bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "buff.ly", "adf.ly"]

SUSPICIOUS_KEYWORDS = [
    "pastebin", "discordapp", "githubusercontent", "ngrok", "000webhost",
    "script", "image", "jonaslejon", "malicious-pdf", "deepzec", "modzero",
]

MALICIOUS_PARAMS = [
    "download", "payload", "sh", "py", "cmd", "php", "exe", "exec", "bin",
    "cSubmitAs", "cFS", "CHTTP", "xdpContent", "textEncoding", "cookie",
    "steal", "script",
]

# 1.2 general text / threat vocabulary

SUSPICIOUS_WORDS = [
    "exploit", "payload", "shell", "malware", "hack", "xss", "script", "eval",
    "dropper", "backdoor", "reverse_shell", "bind_shell", "stager", "obfuscated",
    "bypass", "noprofile", "hidden", "executionpolicy", "encodedcommand",
    "downloadstring", "cmd.exe", "/bin/sh", "/bin/bash", "socket", "pickle",
    "subprocess", "mimikatz", "pwdump", "keystroke", "keylogger", "credential", "token",
]

HACKING_TOOLS = [
    "metasploit", "cobalt strike", "empire", "veil", "mimikatz", "powersploit",
    "nishang", "bloodhound", "beacon", "sherlock", "brute ratel", "sliver",
    "sqlmap", "nmap", "burp suite", "wireshark", "hydra", "aircrack", "responder",
    "kali linux", "parrot os", "backbox", "pentoo", "blackarch",
]

SUSPICIOUS_SOURCE_INDICATORS = [
    "attacker", "malicious", "script", "exploit", "payload", "shell",
    "dropper", "backdoor", "stager", "bypass", "encoded", "obfuscated",
    "metasploit", "cobalt strike", "mimikatz", "powersploit", "empire",
    "burp", "collaborator", "interact.sh", "jonaslejon", "deepzec",
    "callback", "phone-home", "exfiltration", "tunneling", "beacon",
    "injection", "unauthorized", "suspicious", "leak", "harvesting",
]

# 1.3 URI-level risky schemes / extensions

SUSPICIOUS_URI_KEYWORDS = [
    "javascript:", "vbscript:", "data:", "file://", "expect://",
    "smb://", "ftp://", "ldap://", "gopher://", "ms-msdt:", "search-ms:",
    ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".wsc", ".scr",
    ".ps1", ".sh", ".py", ".jar", ".msi", ".dll", ".sys", ".elf",
    ".docm", ".xlsm", ".pptm",
    "cmd.exe", "powershell", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic",
]

# ==========================================================================================
# 2. DETECTION RULES (REGEX-BASED CONTENT ANALYSIS)
# ==========================================================================================

# 2.1 TEXT REGEX RULES (EXEC_PATTERNS + SYSTEM_THREATS)

EXEC_PATTERNS = {
    r"\beval\s*\(": ("eval() function", 12),
    r"\bexec\s*\(": ("exec() function", 12),
    r"String\.fromCharCode": ("Charcode obfuscation", 8),
    r"app\s*(?:\.\s*openDoc|\[\s*['\"]openDoc['\"]\s*\])": ("Remote document opening", 11),
    r"launchURL": ("URL launching", 11),
    r"<\s*script": ("Embedded HTML Script tag", 12),
    r"new\s+Image\s*\(": ("JS Beacon", 10),
    r"new\s+WebSocket\s*\(": ("WebSocket C2 Channel", 12),
    r"\bPost\s*\(\s*[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"']\s*,\s*[\"']": ("FormCalc Post() Arbitrary Header Injection", 12)
}

SYSTEM_THREATS = {
    "Parameter/Header Injection Attempt": ([r"textEncoding\s*=\s*.*?&#x(?:0D|0A|D|A);?", r"textEncoding\s*=\s*.*?\\r\\n", r"X-Injected"], 12),
    "Ransomware Indicators": ([r"decrypt", r"encrypt", r"private_key", r"recover_files", r"\.locked\b"], 12),
    "Registry Tampering": ([r"reg add", r"HKEY_LOCAL_MACHINE", r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"], 10),
    "Security Disabling": ([r"netsh advfirewall", r"Set-MpPreference", r"DisableRealtimeMonitoring", r"taskkill /f /im"], 10),
    "Stealer/Spyware": ([
        r"document\.cookie", r"chrome\.cookies", r"(?:local|session)Storage\s*\.\s*(?:get|set)Item", r"navigator\.credentials",
        r"getField\s*\(\s*[\"'][^\"']*(?:pass(?:word|wd)?|pwd|cookie|secret|token|otp|pin|cvv|ssn|card)[^\"']*[\"']",
        r"getPageNthWord(?:Quads)?\s*\(", r"getPageNumWords\s*\(", r"wallet\.dat", r"[\\/]Login Data\b", r"[\\/]Local State\b",
        r"key[34]\.db", r"logins\.json", r"signons\.sqlite", r"cookies\.sqlite", r"\.kdbx\b", r"\.keystore\b", ], 10),
    "Environment Leak": ([r"\$\{HOME\}", r"\.env\b", r"AWS_CREDENTIALS", r"vnd\.sun\.star\.expand"], 12),
    "XFA/SOAP Attack": ([r"method=\"soap\"", r"soapAction", r"xdp:xdp", r"XSLT", r"<?xml-stylesheet"], 13),
    "XXE Injection Attempt": ([r"<!ENTITY", r"SYSTEM\s+['\"]http", r"<!DOCTYPE"], 13),
    "EICAR Standard Anti-Virus Test File": ([r"EICAR-STANDARD-ANTIVIRUS", r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR"], 15)
}

# 2.2 BINARY PATTERNS (STRUCTURE + CONTENT)

STRUCTURE_PATTERNS = {
    rb"/AA\s*<<\s*/O": ("Silent page trigger (/O or /C)", 12, "BIN-STR-SILENT"),
    rb"/OpenAction": ("Automatic execution trigger (/OpenAction)", 10, "BIN-STR-OPEN"),
    rb"/Launch": ("Annotation (/Launch)", 10, "BIN-STR-LAUNCH")
}

CONTENT_PATTERNS = {
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

# 2.3 CLASSIFICATION MAPS (SCRIPT_TYPE_MAP)

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

# ==========================================================================================
# INTEGRITY CHECK
# ==========================================================================================

_ALL_VOCAB = {
    "SHORTENERS": SHORTENERS,
    "SUSPICIOUS_KEYWORDS": SUSPICIOUS_KEYWORDS,
    "MALICIOUS_PARAMS": MALICIOUS_PARAMS,
    "SUSPICIOUS_WORDS": SUSPICIOUS_WORDS,
    "HACKING_TOOLS": HACKING_TOOLS,
    "SUSPICIOUS_SOURCE_INDICATORS": SUSPICIOUS_SOURCE_INDICATORS,
    "SUSPICIOUS_URI_KEYWORDS": SUSPICIOUS_URI_KEYWORDS,
}

for _name, _lst in _ALL_VOCAB.items():
    _dupes = sorted({x for x in _lst if _lst.count(x) > 1})
    if _dupes:
        raise ValueError(f"Duplicate entries in signature list {_name}: {_dupes}")