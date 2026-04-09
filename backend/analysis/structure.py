import re

WHITELIST = ["/Dests", "/AP", "/Pages", "/Templates", "/IDS", "/URLS"]

def analyze_structure(reader):
    findings = []
    untrusted_items = set()
    root = None
       
    # -------------------------------------------------------------------------
    # 1. Header Analysis
    # -------------------------------------------------------------------------
    try:
        stream = reader.stream
        stream.seek(0)
        raw_start = stream.read(100)
        
        # Check for PDF Signature
        header_index = raw_start.find(b"%PDF-")
        
        if header_index == -1:
            header_display = "".join([chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in raw_start[:10]])
            findings.append(f"ALERT: Malformed PDF header (Found: '{header_display}' instead of %PDF- signature)")
            
        # Check for Signature Offset
        elif header_index > 0:
            findings.append(f"ALERT: PDF signature is not at the start (Offset: {header_index} bytes - potential hiding)")
        
        header_version = None
        
       # Extract and Validate PDF Version
        if header_index != -1:
            
            # Extract version
            version_area = raw_start[header_index+5 : header_index+15]
            version_match = re.search(b"^[0-9.]+", version_area)
            
            if version_match:
                header_version = version_match.group(0).decode('utf-8', errors='ignore').strip()
                
                # Validate version
                if is_version_older(header_version, "1.4"):
                    findings.append(f"ALERT: Old PDF version detected in header ({header_version})")
                else:
                    findings.append(f"INFO: PDF Header detected (Version: {header_version})")
            else:
                findings.append("ALERT: PDF version missing or malformed in header")
                
        # Check for Multiple Headers
        header_count = raw_start.count(b"%PDF-")
        if header_count > 1:
            findings.append(f"ALERT: Multiple PDF headers detected ({header_count} found - potential spoofing)")

    except Exception as e:
        findings.append(f"Header Analysis Error: {str(e)}")

    # -------------------------------------------------------------------------
    # 2. Root Analysis
    # -------------------------------------------------------------------------
    try:
        # Verify Catalog Object
        root_obj = reader.trailer.get("/Root")
        if root_obj:
            root = root_obj.get_object()
            findings.append("INFO: Valid PDF structure")
            
            # Check for Version Mismatch
            catalog_version = root.get("/Version")
            if catalog_version and header_version:
                cat_v_str = str(catalog_version).replace("/", "")
                if cat_v_str != header_version:
                    findings.append(f"ALERT: Version mismatch (Header: {header_version}, Catalog: {cat_v_str})")
            
            # Check for Auto-Execution
            if "/OpenAction" in root:
                findings.append("ALERT: Auto-executable action detected (/OpenAction)")
            
            # Check for Automatic Triggers
            if "/AA" in root:
                findings.append("ALERT: Automatic triggers detected in Catalog (/AA)")
                
    except Exception as e:
        findings.append(f"Root Analysis Error: {str(e)}")
        
    # -------------------------------------------------------------------------
    # 3. Names Analysis
    # -------------------------------------------------------------------------
    try:
        # Verify Names Dictionary
        if root and "/Names" in root:
            names = root["/Names"].get_object()
            
            # Iterate through all categories in the NameTree
            for category_key in names.keys():
                # Perform Recursive Walk for each category
                walk_names_tree(names[category_key], findings, WHITELIST, untrusted_items, category=category_key)
                
            if untrusted_items:
                items_str = ", ".join(sorted(untrusted_items))
                findings.append(f"ALERT: Unexpected/Hidden sections found in NameTree: [{items_str}]")
                
    except Exception as e:
        findings.append(f"NameTree Analysis Error: {str(e)}")

    # -------------------------------------------------------------------------
    # 4. Encryption Analysis
    # -------------------------------------------------------------------------            
    try:
        # Check for File Encryption
        if reader.is_encrypted:
            findings.append("ALERT: Encrypted PDF (Restricted access)")
    except Exception: pass

    return findings

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def is_version_older(current, target):
        try:
            return tuple(map(int, current.split('.'))) < tuple(map(int, target.split('.')))
        except:
            return False
        

def walk_names_tree(node, findings, whitelist, untrusted_items, category=None):

    if not node: return
    node = node.get_object()

    # Check for Child Nodes
    if "/Kids" in node:
        for kid in node["/Kids"]:
            walk_names_tree(kid, findings, whitelist, untrusted_items, category)

    # Check for Leaf Nodes with Data
    if "/Names" in node:
        names_list = node["/Names"]
        for i in range(0, len(names_list), 2):
            key = str(names_list[i])
            value_obj = names_list[i+1]   
            # Process each found name entry      
            process_name_node(key, value_obj, findings, whitelist, untrusted_items, category)
    
    # Check for Direct Hidden Sections
    if category and category not in whitelist:
        if category not in ["/JavaScript", "/JS", "/EmbeddedFiles"]:
             untrusted_items.add(category)
            
            
def process_name_node(key, value_obj, findings, whitelist, untrusted_items, category):

    # Verify Object Integrity and Access
    try:
        if value_obj.get_object() is None:
            findings.append(f"INFO: Entry [{key}] points to an empty object")
    except:
        findings.append(f"ALERT: Could not parse object for [{key}] - potential corruption")
        
    # Analyze JavaScript Payloads
    if category in ["/JavaScript", "/JS"]:
        findings.append(f"ALERT: Suspicious Scripting found in Names ({category}) with script: [{key}]")
    
    # Analyze Embedded File Payloads
    elif category == "/EmbeddedFiles":
        findings.append(f"ALERT: Embedded Files detected in Names ({category}) with file: [{key}]")
        
    # Collect Unexpected entries
    elif key not in whitelist:
        untrusted_items.add(key)
        