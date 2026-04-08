
WHITELIST = ["/Dests", "/AP", "/Pages", "/Templates", "/IDS", "/URLS"]

def analyze_structure(reader):
    findings = []
    root = None
       
    # -------------------------------------------------------------------------
    # 1. Header Analysis
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # 2. Root Analysis
    # -------------------------------------------------------------------------
    try:
        root_obj = reader.trailer.get("/Root")
        if root_obj:
            root = root_obj.get_object()
            findings.append("INFO: Valid PDF structure")
            
            catalog_version = root.get("/Version")
            if catalog_version and header_version:
                cat_v_str = str(catalog_version).replace("/", "")
                if cat_v_str != header_version:
                    findings.append(f"ALERT: Version mismatch (Header: {header_version}, Catalog: {cat_v_str})")
            
            if "/OpenAction" in root:
                findings.append("ALERT: Auto-executable action detected (/OpenAction)")
            
            if "/AA" in root:
                findings.append("ALERT: Automatic triggers detected in Catalog (/AA)")
                
    except Exception as e:
        findings.append(f"Root Analysis Error: {str(e)}")
        
    # -------------------------------------------------------------------------
    # 3. Names Analysis
    # -------------------------------------------------------------------------
    try:
        if root and "/Names" in root:
            names = root["/Names"].get_object()
            found_keys = names.keys()
            
            for key in found_keys:
                if key not in WHITELIST:

                    if key in ["/JavaScript", "/JS"]:
                            try:
                                js_node = names[key].get_object()
                                if "/Names" in js_node:
                                    js_list = js_node["/Names"]
                                    script_names = [str(js_list[i]) for i in range(0, len(js_list), 2)]
                                    if script_names:
                                        findings.append(f"ALERT: Suspicious Scripting section found in Names ({key}) with scripts: [{', '.join(script_names)}]")
                                    else:
                                        findings.append(f"ALERT: Suspicious Scripting section found in Names ({key}) but no script names identified")
                                else:
                                    findings.append(f"ALERT: Suspicious Scripting section found in Names ({key}) but structure is unusual")
                            except:
                                findings.append(f"ALERT: Suspicious Scripting section found in Names ({key}) with obfuscated/unreadable script names")
                    
                    elif key == "/EmbeddedFiles":
                        try:
                            emb_files = names["/EmbeddedFiles"].get_object()
                            if "/Names" in emb_files:
                                file_list = emb_files["/Names"]
                                embedded_names = [str(file_list[i]) for i in range(0, len(file_list), 2)]
                                
                                if embedded_names:
                                    findings.append(f"ALERT: Embedded Files section detected ({key}) with files: [{', '.join(embedded_names)}]")
                                else:
                                    findings.append(f"ALERT: Embedded Files section detected ({key}) but no files identified")
                            else:
                                findings.append(f"ALERT: Embedded Files section detected ({key}) but structure is unusual")
                        except:
                            findings.append(f"ALERT: Embedded Files section detected ({key}) with obfuscated/unreadable content")
                            
                    else:
                        findings.append(f"ALERT: Unexpected/Hidden section found in NameTree: {key}")
                            
    except Exception as e:
        findings.append(f"NameTree Analysis Error: {str(e)}")

    # -------------------------------------------------------------------------
    # 4. Encryption Analysis
    # -------------------------------------------------------------------------            
    try:
        if reader.is_encrypted:
            findings.append("ALERT: Encrypted PDF (Restricted access)")
    except Exception: pass

    return findings