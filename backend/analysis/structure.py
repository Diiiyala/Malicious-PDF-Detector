def analyze_structure(reader):
    findings = []
    try:
        root = reader.trailer.get("/Root")
        if root:
            findings.append("INFO: Valid PDF structure")
            try:
                if hasattr(root, 'get') and "/Names" in root:
                    findings.append("Names dictionary present")
            except Exception:
                pass
        try:
            if "/EmbeddedFiles" in str(reader.trailer):
                findings.append("Embedded files detected")
        except Exception:
            pass
    except Exception as e:
        findings.append(f"Structure error: {str(e)}")
    return findings