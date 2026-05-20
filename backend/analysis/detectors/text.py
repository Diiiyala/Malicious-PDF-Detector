import logging

# -------------------------------------------------------------------------
# Constants for Visual Anomaly Detection
# -------------------------------------------------------------------------
MIN_VISIBLE_FONT_SIZE = 1.0
OUT_OF_BOUNDS_THRESHOLD = -50

def extract_text(reader):
    full_text = []
    findings = set()

    # -------------------------------------------------------------------------
    # Internal Visitor Function
    # -------------------------------------------------------------------------
    def text_inspection_visitor(text, cm, tm, font_dict, font_size):
        if not text or not text.strip() or not tm or len(tm) < 6:
            return

        # ----------------------------
        # Transformation analysis
        # ----------------------------
        if cm and len(cm) >= 4:
            scale_x = cm[0]
            scale_y = cm[3]
            rotation_a = cm[1]
            rotation_b = cm[2]

            if rotation_a != 0 or rotation_b != 0:
                findings.add("INFO: Text transformation detected (rotation/skew)")

            if scale_x < 0 or scale_y < 0:
                findings.add("INFO: Flipped/mirrored text detected (possible obfuscation)")

        # ----------------------------
        # Font analysis
        # ----------------------------
        if font_dict:
            encoding = font_dict.get('/Encoding', 'Standard')
            if any(target in str(encoding).lower() for target in ['identity', 'custom', 'difference']):
                findings.add(f"INFO: Non-standard font encoding detected ({encoding})")

        # ----------------------------
        # Hidden text detection
        # ----------------------------
        x, y = tm[4], tm[5]
        clean_text = text.strip()

        if font_size is not None and font_size < MIN_VISIBLE_FONT_SIZE:
            findings.add(
                f"ALERT: Hidden text detected (Tiny Font: {font_size}pt): '{clean_text[:50]}'"
            )

        elif x < OUT_OF_BOUNDS_THRESHOLD or y < OUT_OF_BOUNDS_THRESHOLD:
            findings.add(
                f"ALERT: Hidden text detected (Off-Canvas at {int(x)},{int(y)}): '{clean_text[:50]}'"
            )

        full_text.append(text)

    # -------------------------------------------------------------------------
    # Main Extraction Loop
    # -------------------------------------------------------------------------
    try:
        try:
            pages_list = list(reader.pages)
            pages_iterator = enumerate(pages_list)
            
        except Exception:
            pages_iterator = []
            findings.add("ALERT: Text extraction skipped (Malformed or missing Pages tree)")

        for i, page in pages_iterator:
            text_count_before = len(full_text)
            try:
                page.extract_text(visitor_text=text_inspection_visitor)
                
            except Exception: continue
            
            text_count_after = len(full_text)

            if text_count_before == text_count_after and has_images(page):
                findings.add(f"INFO: Page {i+1} contains images but no extractable text")

    except Exception:
        logging.exception("Text Analysis collapsed during extraction")

    return "".join(full_text), sorted(findings)

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------

def has_images(page):
    try:
        if "/Resources" in page and "/XObject" in page["/Resources"]:
            x_objects = page["/Resources"]["/XObject"].get_object()
            for obj in x_objects:
                obj_data = x_objects[obj].get_object()
                if obj_data and obj_data.get("/Subtype") == "/Image":
                    return True
    except Exception:
        pass
    return False