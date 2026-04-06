import re

def analyze_content(text):
    findings = []
    checks = {
        "JavaScript detected": ["/JavaScript", "/JS"],
        "Auto action detected": ["/OpenAction"],
        "Suspicious keywords": ["eval(", "exec(", "base64"]
    }

    for message, patterns in checks.items():
        for pattern in patterns:
            if pattern in text:
                findings.append(message)
                break

    urls = re.findall(r'https?://\S+', text)
    if urls:
        findings.append(f"Contains {len(urls)} link(s)")

    if len(text.strip()) > 0 and len(text.strip()) < 50:
        findings.append("Very little text (suspicious PDF)")

    return findings