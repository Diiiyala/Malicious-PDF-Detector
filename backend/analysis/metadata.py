def analyze_metadata(reader):
    findings = []
    try:
        metadata = reader.metadata
        if metadata:
            for key, value in metadata.items():
                if value:
                    val = str(value).lower()
                    if any(x in val for x in ["hack", "exploit", "payload", "malware"]):
                        findings.append(f"Suspicious metadata: {key}")
    except Exception as e:
        findings.append(f"Metadata error: {str(e)}")
    return findings