def analyze_structure(reader):
    findings = []

    try:
        trailer = reader.trailer
        root = trailer.get("/Root")

        # -----------------------
        # Basic structure check
        # -----------------------
        if root:
            findings.append("INFO: Valid PDF structure")
        else:
            findings.append("ALERT: Missing Root object")

        # -----------------------
        # Pages check
        # -----------------------
        try:
            pages = reader.pages
            if len(pages) == 0:
                findings.append("ALERT: No pages found")
        except:
            findings.append("ALERT: Pages could not be read")

        # -----------------------
        # Names dictionary
        # -----------------------
        try:
            if root and hasattr(root, 'get') and root.get("/Names"):
                findings.append("INFO: Names dictionary present")
        except:
            pass

        # -----------------------
        # Embedded files
        # -----------------------
        try:
            if "/EmbeddedFiles" in str(trailer):
                findings.append("ALERT: Embedded files detected")
        except:
            pass

        # -----------------------
        # JavaScript detection
        # -----------------------
        try:
            if "/JavaScript" in str(trailer) or "/JS" in str(trailer):
                findings.append("ALERT: JavaScript detected")
        except:
            pass

        # -----------------------
        # OpenAction 
        # -----------------------
        try:
            if root and "/OpenAction" in root:
                findings.append("ALERT: OpenAction (auto execution on open)")
        except:
            pass

        # -----------------------
        # AcroForm 
        # -----------------------
        try:
            if root and "/AcroForm" in root:
                findings.append("INFO: AcroForm (interactive form) present")
        except:
            pass

        # -----------------------
        # Suspicious actions
        # -----------------------
        try:
            if "/AA" in str(trailer):
                findings.append("ALERT: Additional Actions (AA) detected")
        except:
            pass

        # -----------------------
        # Launch action 
        # -----------------------
        try:
            if "/Launch" in str(trailer):
                findings.append("ALERT: Launch action detected (can execute files)")
        except:
            pass

        # -----------------------
        # Object count
        # -----------------------
        try:
            obj_count = len(reader.xref)
            if obj_count > 1000:
                findings.append("ALERT: Large number of objects (possible obfuscation)")
        except:
            pass

        # -----------------------
        # Stream objects
        # -----------------------
        try:
            stream_count = 0
            for obj in reader.xref:
                try:
                    o = reader.get_object(obj)
                    if hasattr(o, "get_data"):
                        stream_count += 1
                except:
                    continue

            if stream_count > 50:
                findings.append("ALERT: Many stream objects detected (possible hidden payload)")
        except:
            pass

    except Exception as e:
        findings.append(f"Structure error: {str(e)}")

    return findings