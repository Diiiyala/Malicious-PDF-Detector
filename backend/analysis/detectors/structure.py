import re
from collections import Counter
from analysis.utils.links import analyze_links

WHITELIST = ["/Dests", "/AP", "/Pages", "/Templates", "/IDS", "/URLS"]
SUSPICIOUS_KEYS = ["/Launch", "/SubmitForm", "/GoToE", "/RichMedia", "/XFA"]

def analyze_structure(reader, file_stream):
    findings = []
    js_scripts = set()
    embedded_files = set()
    unknown_items = set()
    root = None
          
    # -------------------------------------------------------------------------
    # 1. Header Analysis
    # -------------------------------------------------------------------------
    try:
        file_stream.seek(0)
        raw_data = file_stream.read()     
        
        # Check for PDF Signature
        header_index = raw_data.find(b"%PDF-")
        
        if header_index == -1:
            header_display = "".join([chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in raw_data[:10]])
            findings.append(f"ALERT: Malformed PDF header (Found: '{header_display}' instead of %PDF- signature)")
            
        # Check for Signature Offset
        elif header_index > 0:
            findings.append(f"ALERT: PDF signature is not at the start (Offset: {header_index} bytes - potential hiding)")
        
        header_version = None
        
       # Extract and Validate PDF Version
        if header_index != -1:
            
            # Extract version
            version_area = raw_data[header_index+5 : header_index+15]
            version_match = re.search(b"^[0-9.]+", version_area)
            
            if version_match:
                header_version = version_match.group(0).decode('utf-8', errors='ignore').strip()
                
                # Validate version
                if is_version_older(header_version, "1.4"):
                    findings.append(f"INFO: Old PDF version detected in header ({header_version})")
            else:
                findings.append("ALERT: PDF version missing or malformed in header")
                
        # Check for Multiple Headers
        header_count = raw_data.count(b"%PDF-")
        if header_count > 1:
            findings.append(f"ALERT: Multiple PDF headers detected ({header_count} found - potential spoofing)")

    except Exception as e:
        findings.append(f"INFO: Header Analysis failed: {type(e).__name__}")
        
    if reader is None:
        return sorted(list(set(findings)))

    # -------------------------------------------------------------------------
    # 2. Root Analysis
    # -------------------------------------------------------------------------
    try:
        # Verify Catalog Object
        root_obj = reader.trailer.get("/Root")
        if root_obj:
            root = root_obj.get_object()
            
            if "/OCProperties" in root:
                ocp = root["/OCProperties"].get_object()
                findings.append("ALERT: Optional Content Groups (OCG) detected - potential hidden layer exploit")
                
                ocp_str = str(ocp)
                if "/JS" in ocp_str or "/JavaScript" in ocp_str:
                    found_js_names = []
                    js_name_match = re.findall(r'/([^/\s()<>\[\]{}]+)\s+<<\s*/S\s*/JavaScript', ocp_str)
                    
                    if js_name_match:
                        found_js_names = list(set(js_name_match))
                        names_str = ", ".join(found_js_names)
                        findings.append(f"ALERT: Suspicious OCG-JavaScript coupling detected (Scripts: {names_str})")
                    else:
                        findings.append("ALERT: Suspicious OCG-JavaScript coupling detected")
                
                elif "/AA" in root:
                     findings.append("ALERT: Suspicious OCG-Automatic Trigger coupling detected")

            # Verify PDF 2.0 Associated Files
            if "/AF" in root:
                af_list = root["/AF"]
                af_details = []
                
                try:
                    for af_ref in af_list:
                        af_obj = af_ref.get_object()
                        if af_obj:
                            f_name = af_obj.get("/F", "Unknown")                        
                            f_type = "Unknown"
                            scan_status = ""
                            
                            if "/EF" in af_obj:
                                ef_dict = af_obj["/EF"].get_object()
                                if "/F" in ef_dict:
                                    emb_obj = ef_dict["/F"].get_object()
                                    f_type = emb_obj.get("/Subtype", "Unknown").replace("/", "")
                                    
                                    try:
                                        embedded_data = emb_obj.get_data()
                                        if embedded_data:
                                            decoded_text = embedded_data.decode('utf-8', errors='ignore')
                                            
                                            from analysis.detectors.content import analyze_content
                                            content_findings = analyze_content(decoded_text)
                                            
                                            for cf in content_findings:
                                                findings.append(f"{cf} (Found inside embedded file: {f_name})")
                                                
                                    except Exception as e:
                                        scan_status = " [Scan Failed]"
                            
                            af_details.append(f"{f_name} [Type: {f_type}{scan_status}]")
                    
                    if af_details:
                        details_str = ", ".join(af_details)
                        findings.append(f"ALERT: PDF 2.0 Associated Files (/AF) detected: ({details_str})")
                except:
                    findings.append("ALERT: PDF 2.0 Associated Files (/AF) detected (Failed to parse details)")
                
            # Check for Version Mismatch
            catalog_version = root.get("/Version")
            if catalog_version and header_version:
                cat_v_str = str(catalog_version).replace("/", "")
                if cat_v_str != header_version:
                    findings.append(f"ALERT: Version mismatch (Header: {header_version}, Catalog: {cat_v_str})")
                    
    except Exception as e:
        findings.append(f"Root Analysis failed: {type(e).__name__}")
        
    # -------------------------------------------------------------------------
    # 3. Names Analysis
    # -------------------------------------------------------------------------
    try:
        # Verify Names Dictionary
        if root and "/Names" in root:
            names = root["/Names"].get_object()
            
            # Iterate through all categories in the NameTree
            for category_key in names.keys():
                walk_names_tree(names[category_key], findings, WHITELIST, unknown_items, js_scripts, embedded_files, category=category_key)               
                
            if js_scripts: findings.append(f"ALERT: Suspicious Scripting found in Names: {sorted(list(js_scripts))}")      
            if embedded_files: findings.append(f"ALERT: Embedded Files detected in Names: {sorted(list(embedded_files))}")              
            if unknown_items: findings.append(f"INFO: Unknown NameTree entries found: {sorted(unknown_items)}")
                
    except Exception as e:
        findings.append(f"NameTree Analysis incomplete: {type(e).__name__}")
        
    
    # -------------------------------------------------------------------------
    # 4. Action Analysis
    # -------------------------------------------------------------------------   
    
    try:
        action_findings = perform_action_analysis(reader, root)
        findings.extend(action_findings)
        
    except Exception as e:
        findings.append(f"Action Analysis collapsed: {type(e).__name__}")

    # -------------------------------------------------------------------------
    # 5. Stream & Object Analysis
    # -------------------------------------------------------------------------  
    
    try:
        stream_findings = analyze_streams_and_objects(reader)
        findings.extend(stream_findings)
    except Exception as e:
        findings.append(f"Stream Analysis collapsed: {type(e).__name__}")
   
    # -------------------------------------------------------------------------
    # 6. Encryption Analysis
    # -------------------------------------------------------------------------            
    try:
        # Check for File Encryption
        if reader.is_encrypted:
            findings.append("ALERT: Encrypted PDF (Restricted access)")
            
    except Exception as e: 
        findings.append(f"INFO: Encryption check failed: {type(e).__name__}")

    return sorted(list(set(findings)))

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def is_version_older(current, target):
        try:
            return tuple(map(int, current.split('.'))) < tuple(map(int, target.split('.')))
        except:
            return False
        
        
def perform_action_analysis(reader, root):
    action_findings = []
    action_locations = {}

    def add_location(action_type, location):
        if action_type not in action_locations:
            action_locations[action_type] = []
        action_locations[action_type].append(location)

    # Analyze Root Actions
    if root:
        if "/OpenAction" in root:
            add_location("Auto-executable (/OpenAction)", "Catalog")
        
        if "/AA" in root:
            aa_dict = root["/AA"].get_object()
            found_silent_triggers = []
            
            for silent_trigger in ["/WP", "/DP", "/WC", "/WS", "/DS"]:
                if silent_trigger in aa_dict:
                    found_silent_triggers.append(silent_trigger)
            
            if found_silent_triggers:
                triggers_str = ", ".join(found_silent_triggers)
                add_location(f"ALERT: Dangerous silent trigger ({triggers_str}) detected", "Catalog")
            
            add_location("Automatic triggers (/AA)", "Catalog")

    # Analyze Page-Level Actions and Annotations  
    try:
        for i, page in enumerate(reader.pages):
            page_obj = page.get_object()
            loc_str = f"Page {i+1}"
            
            mediabox = page_obj.get("/MediaBox")
            page_area = 0
            if mediabox:
                page_area = abs(float(mediabox[2]) - float(mediabox[0])) * abs(float(mediabox[3]) - float(mediabox[1]))
            
            if "/AA" in page_obj:
                aa_page = page_obj["/AA"].get_object()
                if "/O" in aa_page or "/C" in aa_page:
                     add_location("ALERT: Silent page trigger (/O or /C)", loc_str)
                add_location("ALERT: Automatic triggers (/AA)", loc_str)

            if "/Annots" in page_obj:
                visible_widgets_on_page = 0
                for annot in page_obj["/Annots"]:
                    obj = annot.get_object()
                    if not obj: continue
                                          
                    rect = obj.get("/Rect")
                    subtype = obj.get("/Subtype")
                    is_widget = (subtype == "/Widget")
                    
                    is_transparent = (obj.get("/F") == 2 or not obj.get("/AP"))
                    has_js = False
                    
                    if "/A" in obj:
                        action_dict = obj["/A"].get_object()
                        if action_dict.get("/S") == "/JavaScript":
                            has_js = True

                    if rect and page_area > 0:
                        width = abs(float(rect[2]) - float(rect[0]))
                        height = abs(float(rect[3]) - float(rect[1]))
                        annot_area = width * height
                        coverage = annot_area / page_area
                                                   
                        if coverage > 0.9:
                            if has_js or is_widget:
                                impact_desc = "ALERT: Clickjacking Full-page overlay (Invisible overlay detected; any click on the page may trigger malicious scripts)"
                                add_location(impact_desc, loc_str)

                        if is_widget and is_transparent and coverage < 0.05:
                            visible_widgets_on_page += 1

                    if "/A" in obj:
                        action_dict = obj["/A"].get_object()
                        a_type = action_dict.get("/S")
                                              
                        if a_type == "/URI":
                            uri_link = action_dict.get("/URI", "Unknown Link")
                            add_location(f"ALERT: Annotation (URI: {uri_link})", loc_str)
                        
                        elif a_type == "/GoToR":
                            f_spec = action_dict.get("/F")
                            f_path = "Unknown"
                            if f_spec:
                                f_obj = f_spec.get_object() if hasattr(f_spec, "get_object") else f_spec
                                if isinstance(f_obj, dict):
                                    f_path = f_obj.get("/F") or f_obj.get("/Unix") or str(f_obj)
                                else:
                                    f_path = str(f_obj)
                            add_location(f"ALERT: Annotation (/GoToR) pointing to: ({f_path})", loc_str)
                                
                        elif a_type == "/GoToE":
                            f_path = action_dict.get("/F")
                            add_location(f"ALERT: Suspicious /GoToE pointing to: {f_path if f_path else 'Internal'}", loc_str)
                        else:
                            a_type_clean = str(a_type).replace("/", "")
                            add_location(f"ALERT: Annotation (/{a_type_clean})", loc_str)
                
                if visible_widgets_on_page > 3:
                    add_location("ALERT: Clickjacking Suspicious invisible button grid detected", loc_str)
                            
    except Exception as e:
        action_findings.append(f"ALERT: Could not fully analyze actions on page {i+1} (Potential obfuscation)")

    # Analyze AcroForm
    try:
        if root and "/AcroForm" in root:
            fields = root["/AcroForm"].get_object().get("/Fields", [])
            for field in fields:
                f_obj = field.get_object()
                field_name = f_obj.get("/T", "Unnamed")
                
                if "/AA" in f_obj:
                    add_location("ALERT: Automatic triggers (/AA)", f"Field: {field_name}")
                    
                elif "/A" in f_obj:
                    action_dict = f_obj["/A"].get_object()
                    a_type = action_dict.get("/S")
                    
                    if a_type == "/GoToE":
                        f_spec = action_dict.get("/F")
                        f_path = "Unknown"
                        if f_spec:
                            f_spec_obj = f_spec.get_object() if hasattr(f_spec, "get_object") else f_spec
                            if isinstance(f_spec_obj, dict):
                                f_path = f_spec_obj.get("/F", "Unknown")
                            else:
                                f_path = str(f_spec_obj)
                        
                        add_location(f"ALERT: Form GoToE pointing to: ({f_path})", f"Field: {field_name}")
                    else:
                        a_type_clean = str(a_type).replace("/", "")
                        add_location(f"ALERT: Form Field Action (/{a_type_clean})", f"Field: {field_name}")
                        
    except: pass
    
    # Analyze Outlines
    try:
        if root and "/Outlines" in root:
            check_outlines_recursive(root["/Outlines"].get_object(), add_location)
    except: pass

    # Aggregate results
    for action, locations in action_locations.items():
        loc_counts = Counter(locations)
        loc_summary = ", ".join([f"{loc}" + (f" (x{count})" if count > 1 else "") for loc, count in loc_counts.items()])
        action_findings.append(f"{action} found in: [{loc_summary}]")

    return action_findings


def check_outlines_recursive(node, add_loc_func):
    if not node: return
    
    # Check for Action in current Bookmark node
    if "/A" in node:
        title = node.get("/Title", "Untitled Bookmark")
        add_loc_func(f"ALERT: Bookmark ({node['/A'].get('/S')})", f"Bookmark: {title}")
    
    # Traverse children and siblings
    if "/First" in node:
        check_outlines_recursive(node["/First"].get_object(), add_loc_func)
    if "/Next" in node:
        check_outlines_recursive(node["/Next"].get_object(), add_loc_func)
        

def walk_names_tree(node, findings, whitelist, untrusted_items, js_scripts, embedded_files, category=None):

    if not node: return
    node = node.get_object()

    # Check for Child Nodes
    if "/Kids" in node:
        for kid in node["/Kids"]:
            walk_names_tree(kid, findings, whitelist, untrusted_items, js_scripts, embedded_files, category)
            
    # Check for Leaf Nodes with Data
    if "/Names" in node:
        names_list = node["/Names"]
        for i in range(0, len(names_list), 2):
            key = str(names_list[i])
            value_obj = names_list[i+1]   
            process_name_node(key, value_obj, findings, whitelist, untrusted_items, js_scripts, embedded_files, category)
    
    # Check for Direct Hidden Sections
    if category and category not in whitelist:
        if category not in ["/JavaScript", "/JS", "/EmbeddedFiles"]:
             untrusted_items.add(category)
            
            
def process_name_node(key, value_obj, findings, whitelist, untrusted_items, js_scripts, embedded_files, category):

    # Verify Object Integrity and Access
    try:
        if value_obj.get_object() is None:
            findings.append(f"INFO: Entry [{key}] points to an empty object")
    except:
        findings.append(f"ALERT: Could not parse object for [{key}] - potential corruption")
        
    # Analyze JavaScript Payloads
    if category in ["/JavaScript", "/JS"]:
        js_scripts.add(key)
    
    # Analyze Embedded File Payloads
    elif category == "/EmbeddedFiles":
        embedded_files.add(key)
        
    # Analyze suspicious NameTree keys
    if key in SUSPICIOUS_KEYS:
        findings.append(f"ALERT: Suspicious key detected in NameTree: {key}")
     
    # Collect Unexpected entries
    elif key not in whitelist:
        untrusted_items.add(key)
        
        
def analyze_streams_and_objects(reader):
    stream_findings = []
    extracted_urls = []
    suspicious_filters = ["/JBIG2Decode", "/Crypt"]
    font_threats = {} 
    remote_refs = {}
    filter_objs = {}
    

    # Retrieve all object numbers from cross-reference table
    try:
        all_obj_nums = reader.xref.get_object_numbers()
    except AttributeError:
        try:
            size_obj = reader.trailer.get("/Size", 100)
            all_obj_nums = range(1, int(size_obj))
        except:
            all_obj_nums = range(1, len(reader.pages) * 50)

    # Scan individual objects
    def process_obj(obj, location_label):
        try:
            if hasattr(obj, "get_object"):
                obj = obj.get_object()
                if obj is None: return

            if isinstance(obj, dict):
                
                # Check for FontMatrix injection (CVE-2024-4367)
                if "/FontMatrix" in obj:
                    matrix_str = str(obj["/FontMatrix"])
                    if re.search(r'[a-zA-Z]{4,}', matrix_str):
                        keywords = ["fetch", "eval", "function", "xmlhttp", "axios", "xml", "script"]
                        if any(k in matrix_str.lower() for k in keywords):
                            msg = "ALERT: Scripting indicator found in font object"
                            if msg not in font_threats: font_threats[msg] = []
                            font_threats[msg].append(location_label)
                            
                # 2. Check for the existence of the /F key
                if "/F" in obj:
                    if obj.get("/Subtype") == "/Image" or "/FS" in obj:
                        f_path = str(obj.get("/F"))
                        msg = f"ALERT: Remote resource reference detected (Path: {f_path})"
                        if msg not in remote_refs: remote_refs[msg] = []
                        remote_refs[msg].append(location_label)
            
                # 3. Check for direct Script injection        
                if "/JS" in obj or "/JavaScript" in obj:
                    js_content = obj.get("/JS") or obj.get("/JavaScript")
                    try:
                        js_str = js_content.get_object() if hasattr(js_content, "get_object") else js_content
                        content_to_scan = js_str.decode('utf-8', errors='ignore') if isinstance(js_str, bytes) else str(js_str)
                        l_findings, _, _, l_urls = analyze_links(content_to_scan)
                        stream_findings.extend(l_findings)
                        for url in l_urls: extracted_urls.append(f"{location_label}: {url}")
                    except: pass

                # 4. Check for suspicious compression filters
                filt = obj.get("/Filter")
                if filt:
                    filt_list = filt if isinstance(filt, list) else [filt]
                    for f in filt_list:
                        f_name = str(f)
                        for s_filt in suspicious_filters:
                            if s_filt in f_name:
                                if f_name not in filter_objs: filter_objs[f_name] = []
                                filter_objs[f_name].append(location_label)

            elif isinstance(obj, list):
                for item in obj:
                    process_obj(item, obj_num)

        except: pass
        
    # Iterate through all objects in the PDF
    for obj_num in all_obj_nums:
        try:
            obj = reader.get_object(obj_num)
            if obj is not None:
                process_obj(obj, f"Obj {obj_num}")
        except: continue

    # Deep Scan Fonts found in Pages
    try:
        for i, page in enumerate(reader.pages):
            if "/Resources" in page and "/Font" in page["/Resources"]:
                fonts = page["/Resources"]["/Font"].get_object()
                for f_name in fonts:
                    process_obj(fonts[f_name], f"Page {i+1} Font:{f_name}")
    except: pass
    
    for msg, locations in font_threats.items():
        unique_locs = sorted(list(set(locations)))
        stream_findings.append(f"{msg} found in: [{', '.join(unique_locs)}]")

    for msg, locations in remote_refs.items():
        unique_locs = sorted(list(set(locations)))
        stream_findings.append(f"{msg} found in: [{', '.join(unique_locs)}]")

    for filt, locations in filter_objs.items():
        unique_locs = sorted(list(set(locations)))
        stream_findings.append(f"ALERT: Suspicious stream filter ({filt}) detected in: [{', '.join(unique_locs)}]")
         
    if extracted_urls:
        stream_findings.append(f"ALERT: Hidden URLs extracted from JavaScript: [{', '.join(sorted(list(set(extracted_urls))))}]")

    return stream_findings