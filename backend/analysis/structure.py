
def analyze_structure(reader):
    findings = []
    
    # -----------------------
    # 1. Header Analysis
    # -----------------------
    try:
        stream = reader.stream
        stream.seek(0)
        raw_start = stream.read(100)
        
        header_index = raw_start.find(b"%PDF-")
        
        if header_index == -1:
            header_display = "".join([chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in raw_start[:10]])
            findings.append(f"ALERT: Malformed PDF header (Found: '{header_display}' instead of %PDF- signature)")
        elif header_index > 0:
            findings.append(f"ALERT: PDF signature is not at the start (Offset: {header_index} bytes - potential hiding)")
        
        header_version = None
        if header_index != -1:
            header_version = raw_start[header_index+5 : header_index+8].decode('utf-8', errors='ignore')
            if header_version < "1.4":
                findings.append(f"ALERT: Old PDF version detected in header ({header_version})")
            else:
                findings.append(f"INFO: PDF Header detected (Version: {header_version})")

        header_count = raw_start.count(b"%PDF-")
        if header_count > 1:
            findings.append(f"ALERT: Multiple PDF headers detected ({header_count} found - potential spoofing)")

    except Exception as e:
        findings.append(f"Header Analysis Error: {str(e)}")

    return findings