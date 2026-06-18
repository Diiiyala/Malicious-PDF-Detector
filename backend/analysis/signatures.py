
# ---------------------------------------------------------------------------
#  URLs / links
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
#  Metadata
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
#  Raw-binary URI keywords
# ---------------------------------------------------------------------------
SUSPICIOUS_URI_KEYWORDS = [
    "javascript:", "vbscript:", "data:", "file://", "expect://",
    "smb://", "ftp://", "ldap://", "gopher://", "ms-msdt:", "search-ms:",
    ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".wsc", ".scr",
    ".ps1", ".sh", ".py", ".jar", ".msi", ".dll", ".sys", ".elf",
    ".docm", ".xlsm", ".pptm",
    "cmd.exe", "powershell", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic",
]

# ---------------------------------------------------------------------------
# Integrity check: ensure no duplicate entries exist within each signature list
# ---------------------------------------------------------------------------
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
