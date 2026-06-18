import re, logging
from collections import Counter
from analysis.utils.models import ExtractedContent, Threat
from analysis.utils.links import analyze_links
from analysis.detectors.content import analyze_content
from analysis.signatures import SUSPICIOUS_URI_KEYWORDS

logger = logging.getLogger(__name__)

WHITELIST = ["/Dests", "/AP", "/Pages", "/Templates", "/IDS", "/URLS"]
SUSPICIOUS_KEYS = ["/Launch", "/SubmitForm", "/GoToE", "/RichMedia", "/XFA"]

def analyze_structure(content: ExtractedContent, reader, aggregator=None) -> list[Threat]:
    threats = []
    js_scripts = set()
    embedded_files = set()
    unknown_items = set()
    root = None
    
    raw_data = content.raw_binary
          
    # -------------------------------------------------------------------------
    # 1. Header Analysis
    # -------------------------------------------------------------------------
    try:      
        # Check for PDF Signature
        header_index = raw_data.find(b"%PDF-")
        
        if header_index == -1:
            header_display = "".join([chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in raw_data[:10]])
            threats.append(Threat(
                id="STR-HDR-MALFORMED", category="Structure", severity=10,
                description=f"Malformed PDF header (Found: '{header_display}' instead of %PDF- signature)", location="Header"
            ))
            
        # Check for Signature Offset
        elif header_index > 0:
            threats.append(Threat(
                id="STR-HDR-OFFSET", category="Structure", severity=7,
                description=f"PDF signature is not at the start (Offset: {header_index} bytes - potential hiding)", location="Header"
            ))
        
        # Validate PDF Version presence
        if header_index != -1:
            version_area = raw_data[header_index+5 : header_index+15]
            version_match = re.search(b"^[0-9.]+", version_area)

            if not version_match:
                threats.append(Threat(
                    id="STR-HDR-NOVER", category="Structure", severity=7,
                    description="PDF version missing or malformed in header", location="Header"
                ))
                
        # Check for Multiple Headers
        header_count = raw_data.count(b"%PDF-")
        if header_count > 1:
            threats.append(Threat(
                id="STR-HDR-MULTI", category="Structure", severity=8,
                description=f"Multiple PDF headers detected ({header_count} found - potential spoofing)", location="Header"
            ))

    except Exception as e: pass
        
    if reader is None:
        return threats

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
                ocp_str = str(ocp)
                
                if "/JS" in ocp_str or "/JavaScript" in ocp_str:
                    js_name_match = re.findall(r'/([^/\s()<>\[\]{}]+)\s+<<\s*/S\s*/JavaScript', ocp_str)
                    names_str = f" (Scripts: {', '.join(list(set(js_name_match)))})" if js_name_match else ""
                    threats.append(Threat(
                        id="STR-ROOT-OCG-JS", category="Structure", severity=11,
                        description=f"Optional Content Groups (OCG) detected - Suspicious JavaScript coupling{names_str}", location="Root Catalog"
                    ))
                        
                elif "/AA" in root:
                    threats.append(Threat(
                        id="STR-ROOT-OCG-AA", category="Structure", severity=11,
                        description="Optional Content Groups (OCG) detected - Suspicious Automatic Trigger coupling (Potential Hidden Layer Exploit)", location="Root Catalog"
                    ))               

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

                                            dummy_content = ExtractedContent(extracted_text=decoded_text)
                                            content_threats = analyze_content(dummy_content, aggregator=aggregator)
                                            
                                            for ct in content_threats:
                                                ct.location = f"Inside embedded file: {f_name}"
                                                threats.append(ct)
                                                
                                    except Exception as e:
                                        scan_status = " [Scan Failed]"
                            
                            af_details.append(f"{f_name} [Type: {f_type}{scan_status}]")
                    
                    if af_details:
                        details_str = ", ".join(af_details)
                        threats.append(Threat(
                            id="STR-ROOT-AF", category="Structure", severity=12,
                            description=f"PDF 2.0 Associated Files (/AF) detected: ({details_str})", location="Root Catalog"
                        ))
                except Exception as e:
                    logger.debug("/AF (Associated Files) parsing failed: %s", e)
                    threats.append(Threat(
                        id="STR-ROOT-AF-FAIL", category="Structure", severity=12,
                        description="PDF 2.0 Associated Files (/AF) detected (Failed to parse details)", location="Root Catalog"
                    ))
                                       
    except Exception as e: pass
        
    # -------------------------------------------------------------------------
    # 3. Names Analysis
    # -------------------------------------------------------------------------
    try:
        # Verify Names Dictionary
        if root and "/Names" in root:
            names = root["/Names"].get_object()
            
            # Iterate through all categories in the NameTree
            for category_key in names.keys():
                walk_names_tree(names[category_key], threats, WHITELIST, unknown_items, js_scripts, embedded_files, category=category_key)               
                
            if js_scripts: 
                threats.append(Threat(
                    id="STR-NAMES-JS", category="Structure", severity=12,
                    description=f"Suspicious Scripting found in Names: {sorted(list(js_scripts))}", location="NameTree"
                ))      
            if embedded_files: 
                threats.append(Threat(
                    id="STR-NAMES-EMBEDDED", category="Structure", severity=9,
                    description=f"Embedded Files detected in Names: {sorted(list(embedded_files))}", location="NameTree"
                ))              
            if unknown_items: 
                threats.append(Threat(
                    id="STR-NAMES-UNKNOWN", category="Structure", severity=2,
                    description=f"Unknown NameTree entries found: {sorted(unknown_items)}", location="NameTree"
                ))
                
    except Exception as e: pass
         
    # -------------------------------------------------------------------------
    # 4. Action Analysis
    # -------------------------------------------------------------------------   
    
    try:
        action_threats = perform_action_analysis(reader, root, aggregator)
        threats.extend(action_threats)
    except Exception as e:
        pass

    # -------------------------------------------------------------------------
    # 5. Stream & Object Analysis
    # -------------------------------------------------------------------------  
    
    try:
        stream_threats = analyze_streams_and_objects(reader, aggregator)
        threats.extend(stream_threats)
    except Exception as e:
        pass
   
    # -------------------------------------------------------------------------
    # 6. Encryption Analysis
    # -------------------------------------------------------------------------            
    if content.has_encryption:
        threats.append(Threat(
            id="STR-ENCRYPTED", category="Structure", severity=5,
            description="Encrypted PDF (Restricted access)", location="Document Settings"
        ))

    return threats

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def perform_action_analysis(reader, root, aggregator=None) -> list[Threat]:
    threats = []
    threat_map = {}

    def add_threat(t_id, severity, description, location):
        key = (t_id, "Action/Trigger", severity, description)
        if key not in threat_map:
            threat_map[key] = []
        threat_map[key].append(location)
        
    def extract_action_path(action_dict):
        f_spec = action_dict.get("/F")
        if not f_spec: return None
        f_obj = f_spec.get_object() if hasattr(f_spec, "get_object") else f_spec
        
        if isinstance(f_obj, dict):
            f_path = f_obj.get("/F") or f_obj.get("/Unix") or str(f_obj)
            return str(f_path)
        return str(f_obj)

    # Analyze Root Actions
    if root:
        if "/OpenAction" in root:
            action_traced = False
            try:
                oa_obj = root["/OpenAction"].get_object()

                if isinstance(oa_obj, dict) and "/S" in oa_obj:
                    action_type = str(oa_obj.get("/S")).replace("/", "")
                    
                    add_threat("STR-ACT-OPEN-EXEC", 12, f"Automatic execution trigger (/OpenAction) executing Action (/{action_type})", "Catalog")
                    action_traced = True
                    
                    if action_type == "SubmitForm":
                        if "/Flags" in oa_obj:
                            flags = int(oa_obj.get("/Flags", 0))
                            if flags & 4:
                                add_threat("STR-ACT-SUBMIT-HTML", 12, "SubmitForm configured to leak data as HTML (Flags 4)", "Catalog")
                            elif flags & 256:
                                add_threat("STR-ACT-SUBMIT-PDF", 13, "SubmitForm configured to leak entire PDF (Flags 256)", "Catalog")
                            else:
                                add_threat("STR-ACT-SUBMIT-FLAGS", 4, f"SubmitForm triggered with Flags: {flags}", "Catalog")
                    
                    elif action_type == "URI":
                        uri_val = str(oa_obj.get("/URI", "Unknown"))
                        add_threat("STR-ACT-OPEN-URI", 12, f"OpenAction triggers URI: {uri_val}", "Catalog")
                        
            except Exception as e: pass

            if not action_traced:
                add_threat("STR-ACT-OPENACTION", 11, "Automatic execution trigger (/OpenAction) detected", "Catalog")
        
        if "/AA" in root:
            aa_dict = root["/AA"].get_object()
            found_silent_triggers = []
            
            for silent_trigger in ["/WP", "/DP", "/WC", "/WS", "/DS"]:
                if silent_trigger in aa_dict:
                    found_silent_triggers.append(silent_trigger)
            
            if found_silent_triggers:
                triggers_str = ", ".join(found_silent_triggers)
                add_threat("STR-ACT-SILENT-ROOT", 12, f"Silent background trigger detected (Found: '{triggers_str}')", "Catalog")
                
            add_threat("STR-ACT-AA-ROOT", 10, "Automatic triggers (/AA) detected", "Catalog")

    # Analyze Page-Level Actions and Annotations  
    try:
        for i, page in enumerate(reader.pages):
            loc_str = f"Page {i+1}"
            
            try:
                page_obj = page.get_object()
                    
                mediabox = page_obj.get("/MediaBox")
                page_area = 0
                if mediabox:
                    page_area = abs(float(mediabox[2]) - float(mediabox[0])) * abs(float(mediabox[3]) - float(mediabox[1]))
                
                if "/AA" in page_obj:
                    aa_page = page_obj["/AA"].get_object()
                    if "/O" in aa_page or "/C" in aa_page:
                        add_threat("STR-ACT-PAGE-SILENT", 12, "Silent page trigger (/O or /C)", loc_str)
                    add_threat("STR-ACT-PAGE-AA", 10, "Automatic triggers (/AA)", loc_str)

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
                        trigger_type = "Unknown trigger"
                        extracted_path = None
                        
                        if "/A" in obj:
                            action_dict = obj["/A"].get_object()
                            a_type = action_dict.get("/S")
                            extracted_path = extract_action_path(action_dict)
                            
                            if a_type == "/JavaScript":
                                has_js = True
                                trigger_type = "JavaScript trigger"
                                
                            elif a_type == "/URI":
                                uri_link = str(action_dict.get("/URI", "Unknown Link"))
                                trigger_type = f"DNS/HTTP trigger: {uri_link}"
                                extracted_path = uri_link
                                
                            elif a_type == "/SubmitForm":
                                trigger_type = f"Data exfiltration trigger: {extracted_path}" if extracted_path else "Data exfiltration trigger"
                                
                            elif a_type in ["/Launch", "/GoToR", "/ImportData", "/Thread", "/GoToE"]:
                                a_clean = str(a_type).replace("/", "")
                                trigger_type = f"{a_clean} trigger: {extracted_path}" if extracted_path else f"{a_clean} trigger (Internal)"
                                
                            elif a_type:
                                trigger_type = f"{str(a_type).replace('/', '')} trigger"
                                
                        is_link_trigger = (subtype == "/Link" and "/A" in obj)
                        is_clickjacking = False

                        if rect and page_area > 0:
                            width = abs(float(rect[2]) - float(rect[0]))
                            height = abs(float(rect[3]) - float(rect[1]))
                            annot_area = width * height
                            coverage = annot_area / page_area
                                                    
                            if coverage > 0.9:
                                if has_js or is_widget or is_link_trigger:
                                    add_threat("STR-ACT-CLICKJACK", 13, f"Clickjacking overlay ({trigger_type})", loc_str)
                                    is_clickjacking = True

                        if is_widget and is_transparent and coverage < 0.05:
                            visible_widgets_on_page += 1
                                
                        if "/T" in obj:
                            t_val = str(obj["/T"])
                            if any(k in t_val.lower() for k in ["<script", "javascript:", "<img", "onerror="]):
                                add_threat("STR-ACT-STORED-XSS", 12, f"Stored XSS injection attempt detected in Annotation field (/T): {t_val[:50]}", loc_str)
                                if aggregator:
                                    aggregator.add_script(t_val, f"{loc_str} Annotation /T Field", script_type="Stored XSS Payload")
                                    
                        if "/A" in obj and not is_clickjacking:
                            action_dict = obj["/A"].get_object()
                            a_type = action_dict.get("/S")
                            
                            if a_type == "/URI":
                                uri_lower = extracted_path.lower() if extracted_path else ""                               
                                is_suspicious = any(k in uri_lower for k in SUSPICIOUS_URI_KEYWORDS) or \
                                                re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', uri_lower)
                                if is_suspicious:
                                    add_threat("URI-DETECTED", 8, f"Suspicious URI detected ('{extracted_path}')", loc_str)
                                    
                            elif a_type == "/ImportData":
                                add_threat("STR-ACT-IMPORTDATA", 12, f"External data import trigger (/ImportData) pointing to: ({extracted_path})", loc_str)
                            elif a_type == "/GoToR":
                                add_threat("STR-ACT-GOTOR", 12, f"Annotation (/GoToR) pointing to: ({extracted_path})", loc_str)
                            elif a_type == "/GoToE":
                                add_threat("STR-ACT-GOTOE", 11, f"Suspicious /GoToE pointing to: {extracted_path if extracted_path else 'Internal'}", loc_str)
                            elif a_type in ["/Launch", "/SubmitForm", "/Thread"]:
                                a_clean = str(a_type).replace("/", "")
                                desc = f"Annotation (/{a_clean}) pointing to: ({extracted_path})" if extracted_path else f"Annotation (/{a_clean})"
                                add_threat(f"STR-ACT-{a_clean.upper()}", 10, desc, loc_str)
                            else:
                                a_type_clean = str(a_type).replace("/", "")
                                add_threat(f"STR-ACT-ANNOT-{a_type_clean}", 4, f"Annotation (/{a_type_clean})", loc_str)
                    
                if visible_widgets_on_page > 3:
                    add_threat("STR-ACT-CLICKJACK-GRID", 12, "Clickjacking Suspicious invisible button grid detected", loc_str)
            
            except Exception as page_error:
                continue
                               
    except Exception as e:
        add_threat("STR-ACT-ERROR", 2, "Could not access document pages array", "Document Body")
        
    # Analyze AcroForm
    try:
        if root and "/AcroForm" in root:
            fields = root["/AcroForm"].get_object().get("/Fields", [])
            for field in fields:
                f_obj = field.get_object()
                field_name = f_obj.get("/T", "Unnamed")
                
                if "/AA" in f_obj:
                    add_threat("STR-ACT-FORM-AA", 10, "Automatic triggers (/AA)", f"Field: {field_name}")
                    
                elif "/A" in f_obj:
                    action_dict = f_obj["/A"].get_object()
                    a_type = action_dict.get("/S")
                    extracted_path = extract_action_path(action_dict)
                    
                    if a_type == "/GoToE":
                        add_threat("STR-ACT-FORM-GOTOE", 11, f"Form GoToE pointing to: ({extracted_path if extracted_path else 'Internal'})", f"Field: {field_name}")
                    elif a_type == "/ImportData":
                        add_threat("STR-ACT-FORM-IMPORT", 12, f"External data import trigger (/ImportData) pointing to: ({extracted_path})", f"Field: {field_name}")
                    else:
                        a_type_clean = str(a_type).replace("/", "")
                        desc = f"Form Field Action (/{a_type_clean}) pointing to: ({extracted_path})" if extracted_path else f"Form Field Action (/{a_type_clean})"
                        add_threat("STR-ACT-FORM-ACTION", 5, desc, f"Field: {field_name}")
    except Exception as e:
        logger.debug("Form field action analysis failed: %s", e)
    
    # Analyze Outlines
    try:
        if root and "/Outlines" in root:
            check_outlines_recursive(root["/Outlines"].get_object(), add_threat)
    except Exception as e:
        logger.debug("Outlines analysis failed: %s", e)
    
    # Aggregate results
    for (t_id, category, severity, desc), locations in threat_map.items():
        loc_counts = Counter(locations)

        loc_summary = ", ".join([f"{loc}" + (f" (x{count})" if count > 1 else "") for loc, count in loc_counts.items()])
        
        threats.append(Threat(
            id=t_id,
            category=category,
            severity=severity,
            description=desc,
            location=loc_summary
        ))

    return threats


def check_outlines_recursive(node, add_threat_func):
    if not node: return
    
    # Check for Action in current Bookmark node
    if "/A" in node:
        title = node.get("/Title", "Untitled Bookmark")
        action_type = node['/A'].get('/S')
        add_threat_func("STR-ACT-BOOKMARK", 4, f"Bookmark ({action_type})", f"Bookmark: {title}")
    
    # Traverse children and siblings
    if "/First" in node:
        check_outlines_recursive(node["/First"].get_object(), add_threat_func)
    if "/Next" in node:
        check_outlines_recursive(node["/Next"].get_object(), add_threat_func)
        

def walk_names_tree(node, threats, whitelist, untrusted_items, js_scripts, embedded_files, category=None):

    if not node: return
    node = node.get_object()

    # Check for Child Nodes
    if "/Kids" in node:
        for kid in node["/Kids"]:
            walk_names_tree(kid, threats, whitelist, untrusted_items, js_scripts, embedded_files, category)
            
    # Check for Leaf Nodes with Data
    if "/Names" in node:
        names_list = node["/Names"]
        for i in range(0, len(names_list), 2):
            key = str(names_list[i])
            value_obj = names_list[i+1]   
            process_name_node(key, value_obj, threats, whitelist, untrusted_items, js_scripts, embedded_files, category)
            
    # Check for Direct Hidden Sections
    if category and category not in whitelist:
        if category not in ["/JavaScript", "/JS", "/EmbeddedFiles"]:
             untrusted_items.add(category)
            
def process_name_node(key, value_obj, threats, whitelist, untrusted_items, js_scripts, embedded_files, category):
    
    # Verify Object Integrity and Access
    try:
        if value_obj.get_object() is None:
            threats.append(Threat(
                id="STR-NAMES-EMPTY", category="Structure", severity=1, 
                description=f"Entry [{key}] points to an empty object", location=f"NameTree: {category}"
            ))
    except Exception as e:
        logger.debug("Name-tree walk failed: %s", e)
        threats.append(Threat(
            id="STR-NAMES-CORRUPT", category="Structure", severity=7,
            description=f"Could not parse object for [{key}] - potential corruption", location=f"NameTree: {category}"
        ))
        
    # Analyze JavaScript Payloads
    if category in ["/JavaScript", "/JS"]:
        js_scripts.add(key)
    
    # Analyze Embedded File Payloads
    elif category == "/EmbeddedFiles":
        embedded_files.add(key)
        
    # Analyze suspicious NameTree keys
    if key in SUSPICIOUS_KEYS:
        threats.append(Threat(
            id="STR-NAMES-SUSP-KEY", category="Structure", severity=10, 
            description=f"Suspicious key detected in NameTree: {key}", location=f"NameTree: {category}"
        ))
     
    # Collect Unexpected entries
    elif key not in whitelist:
        untrusted_items.add(key)
        
        
def analyze_streams_and_objects(reader, aggregator=None) -> list[Threat]:
    threats = []
    threat_map = {}
    visited_objects = set()
    suspicious_filters = ["/JBIG2Decode", "/Crypt"]
    
    def add_threat(t_id, severity, description, location):
        key = (t_id, "Stream/Object", severity, description)
        if key not in threat_map:
            threat_map[key] = []
        threat_map[key].append(location)
    
    # ---------------------------------------------------------------------
    # Retrieve all object numbers from cross-reference table
    # ---------------------------------------------------------------------
    
    try:
        all_obj_nums = reader.xref.get_object_numbers()
    except AttributeError:
        try:
            size_obj = reader.trailer.get("/Size", 100)
            all_obj_nums = range(1, int(size_obj))
        except Exception as e:
            logger.debug("Trailer /Size unavailable, falling back to page estimate: %s", e)
            all_obj_nums = range(1, len(reader.pages) * 50)

    # ---------------------------------------------------------------------
    # Process Individual Objects
    # ---------------------------------------------------------------------

    def process_obj(obj, location_label):
        try:
            if hasattr(obj, "get_object"):
                obj = obj.get_object()
                
            if obj is None: return

            obj_id = id(obj)
            if obj_id in visited_objects: return
            visited_objects.add(obj_id)

            # --------------------------------------------------------------
            # Process Individual Objects
            # --------------------------------------------------------------

            if isinstance(obj, dict):           
                
                # ----------------------------------------------------------
                # 1. Metadata XML / XXE Scan
                # ----------------------------------------------------------

                if obj.get("/Type") == "/Metadata":
                    try:
                        raw_xml = obj.get_data().decode("utf-8", errors="ignore")
                        dummy_content = ExtractedContent(extracted_text=raw_xml)
                        xml_threats = analyze_content(dummy_content, aggregator=aggregator)
                        for t in xml_threats:
                            t.location = f"{location_label} (Metadata XML)"
                            threats.append(t)
                    except Exception as e:
                        logger.debug("Metadata XML stream analysis failed: %s", e)
                    
                # ----------------------------------------------------------
                # 2. FontMatrix Injection Detection (CVE-2024-4367)
                # ----------------------------------------------------------
                
                if "/FontMatrix" in obj:
                    matrix_str = str(obj["/FontMatrix"])
                    if re.search(r'[a-zA-Z]{4,}', matrix_str):
                        keywords = ["fetch", "eval", "function", "xmlhttp", "axios", "xml", "script"]
                        if any(k in matrix_str.lower() for k in keywords):
                            add_threat("STR-OBJ-FONT-JS", 12, "Scripting indicator found in font object", location_label)
                            
                # ----------------------------------------------------------
                # 3. Remote Resource References
                # ----------------------------------------------------------

                if "/F" in obj:
                    if obj.get("/Subtype") == "/Image" or "/FS" in obj:
                        f_val = obj.get("/F")
                        if hasattr(f_val, "get_object"): f_val = f_val.get_object()
                        f_path = str(f_val.get("/F")) if isinstance(f_val, dict) and "/F" in f_val else str(f_val)
                        add_threat("STR-OBJ-REMOTE-RES", 12, f"Remote resource reference detected (Path: {f_path})", location_label)
            
                # ----------------------------------------------------------
                # 4. JavaScript Injection
                # ----------------------------------------------------------
     
                if "/JS" in obj or "/JavaScript" in obj:
                    js_content = obj.get("/JS") or obj.get("/JavaScript")
                    try:
                        js_str = js_content.get_object() if hasattr(js_content, "get_object") else js_content
                        content_to_scan = js_str.decode('utf-8', errors='ignore') if isinstance(js_str, bytes) else str(js_str)
                        
                        if aggregator:
                            aggregator.add_script(content_to_scan, location_label, source_object=location_label)
                            
                        dummy_content = ExtractedContent(extracted_text=content_to_scan)
                        c_threats = analyze_content(dummy_content, aggregator=aggregator)
                        for t in c_threats:
                            t.location = f"{location_label} (JS Stream)"
                            threats.append(t)
                    except Exception as e:
                        logger.debug("JS stream analysis failed: %s", e)
                    
                # ----------------------------------------------------------
                # 5. XFA / FormCalc Injection
                # ----------------------------------------------------------

                if "/XFA" in obj:
                    xfa_data = obj.get("/XFA")
                    try:
                        xfa_obj = xfa_data.get_object()
                        raw_xfa_bytes = xfa_obj.get_data() if hasattr(xfa_obj, "get_data") else (xfa_obj if isinstance(xfa_obj, bytes) else None)
                        if raw_xfa_bytes:
                            xfa_text = raw_xfa_bytes.decode('utf-8', errors='ignore')
                            if aggregator:
                                aggregator.add_script(xfa_text, location_label, script_type="XFA/XML-Form")
                                
                            dummy_content = ExtractedContent(extracted_text=xfa_text)
                            xfa_threats = analyze_content(dummy_content, aggregator=aggregator)
                            for t in xfa_threats:
                                t.location = f"{location_label} (XFA Stream)"
                                threats.append(t)
                    except Exception: pass

                # ----------------------------------------------------------
                # 6. Suspicious Compression Filters
                # ----------------------------------------------------------
                
                filt = obj.get("/Filter")
                if filt:
                    filt_list = filt if isinstance(filt, list) else [filt]
                    for f in filt_list:
                        f_name = str(f)
                        for s_filt in suspicious_filters:
                            if s_filt in f_name:
                                add_threat("STR-OBJ-SUSP-FILTER", 8, f"Suspicious stream filter ({f_name}) detected", location_label)
                                
                # ----------------------------------------------------------
                # 7. Deep EmbeddedFile Stream Scan (HTML / JS Carriers)
                # ----------------------------------------------------------

                if obj.get("/Type") == "/EmbeddedFile" or "/Subtype" in obj:
                    try:
                        if hasattr(obj, "get_data"):
                            raw_stream_data = obj.get_data()
                            if raw_stream_data:
                                decoded_stream_text = raw_stream_data.decode('utf-8', errors='ignore')
                                if any(k in decoded_stream_text.lower() for k in ["<script", "html", "javascript:"]):
                                    if aggregator:
                                        aggregator.add_script(decoded_stream_text, f"{location_label} (Embedded)", script_type="Embedded HTML/JS Payload")
                                    
                                    dummy_content = ExtractedContent(extracted_text=decoded_stream_text)
                                    emb_threats = analyze_content(dummy_content, aggregator=aggregator)
                                    for t in emb_threats:
                                        t.location = f"{location_label} (Embedded File)"
                                        threats.append(t)
                    except Exception: pass
                    
                # ----------------------------------------------------------
                # 8. Recursive Traversal of Nested Objects / Arrays
                # ----------------------------------------------------------
                
                for key, value in obj.items():
                    if isinstance(value, dict) or isinstance(value, list):
                        process_obj(value, location_label)
                        
                # ----------------------------------------------------------
                # 9. Execution Triggers (Zero-Click & Events)
                # ----------------------------------------------------------
                if "/AA" in obj:
                    aa = obj.get("/AA")
                    try:
                        aa_obj = aa.get_object() if hasattr(aa, "get_object") else aa
                        if isinstance(aa_obj, dict):
                            if "/E" in aa_obj:
                                add_threat("STR-OBJ-AA-E", 12, "Event-based execution trigger (Mouse-over /E)", location_label)
                            elif "/PV" in aa_obj or "/PC" in aa_obj:
                                add_threat("STR-OBJ-AA-PAGE", 12, "Event-based execution trigger (Page Visibility/Close)", location_label)
                            else:
                                found_keys = [k for k in ["/WC", "/WS", "/DS", "/WP", "/DP"] if k in aa_obj]
                                if found_keys:
                                    add_threat("STR-OBJ-AA-SILENT", 12, f"Silent background trigger detected (Found: '{', '.join(found_keys)}')", location_label)
                    except Exception as e:
                        logger.debug("/AA silent-trigger analysis failed: %s", e)

                if "/Names" in obj:
                    names = obj.get("/Names")
                    try:
                        names_obj = names.get_object() if hasattr(names, "get_object") else names
                        if isinstance(names_obj, dict) and "/JavaScript" in names_obj:
                            add_threat("STR-OBJ-NAMES-JS", 12, "Document-level automatic execution trigger (/Names -> /JavaScript)", location_label)
                    except Exception as e:
                        logger.debug("/Names -> /JavaScript analysis failed: %s", e)

            # --------------------------------------------------------------
            # Process Individual Objects
            # --------------------------------------------------------------
            
            elif isinstance(obj, list):
                for index, item in enumerate(obj, start=1):
                    process_obj(item, f"{location_label} (Element {index})")

        except Exception as e:
            logger.debug("Object processing failed for %s: %s", location_label, e)
        
    # ---------------------------------------------------------------------
    # Iterate Through All PDF Objects
    # ---------------------------------------------------------------------

    for obj_num in all_obj_nums:
        try:
            obj = reader.get_object(obj_num)
            if obj is not None:
                process_obj(obj, f"Obj {obj_num}")
        except Exception as e:
            logger.debug("Could not process object %s: %s", obj_num, e)
            continue

    # ---------------------------------------------------------------------
    # Deep Font Scan Inside Pages
    # ---------------------------------------------------------------------

    try:
        for i, page in enumerate(reader.pages):
            if "/Resources" in page and "/Font" in page["/Resources"]:
                fonts = page["/Resources"]["/Font"].get_object()
                for f_name in fonts:
                    process_obj(fonts[f_name], f"Page {i+1} Font:{f_name}")
    except Exception as e:
        logger.debug("Page font processing failed: %s", e)
    
    # ---------------------------------------------------------------------
    # Build Final Threats
    # ---------------------------------------------------------------------
    for (t_id, category, severity, desc), locations in threat_map.items():
        loc_counts = Counter(locations)
        loc_summary = ", ".join([f"{loc}" + (f" (x{count})" if count > 1 else "") for loc, count in loc_counts.items()])
        threats.append(Threat(
            id=t_id, category=category, severity=severity,
            description=desc, location=loc_summary
        ))

    return threats