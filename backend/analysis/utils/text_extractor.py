import logging
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Constants for Visual Anomaly Detection
# -------------------------------------------------------------------------
MIN_VISIBLE_FONT_SIZE = 1.0
OUT_OF_BOUNDS_THRESHOLD = -50

def extract_text_and_visuals(reader):
    full_text = []
    visual_anomalies = []
    image_only_pages = []
    has_malformed_tree = False

    # -------------------------------------------------------------------------
    # Internal Visitor Function
    # -------------------------------------------------------------------------
    def text_inspection_visitor(text, cm, tm, font_dict, font_size):
        if not text or not text.strip() or not tm or len(tm) < 6:
            return

        clean_text = text.strip()
        x, y = tm[4], tm[5]

        # ----------------------------
        # Transformation analysis
        # ----------------------------
        if cm and len(cm) >= 4:
            scale_x = cm[0]
            scale_y = cm[3]
            rotation_a = cm[1]
            rotation_b = cm[2]

            if rotation_a != 0 or rotation_b != 0:
                visual_anomalies.append({"type": "transformation", "details": "rotation/skew"})

            if scale_x < 0 or scale_y < 0:
                visual_anomalies.append({"type": "flipped", "details": "mirrored text"})

        # ----------------------------
        # Font analysis
        # ----------------------------
        if font_dict:
            encoding = str(font_dict.get('/Encoding', 'Standard')).lower()
            if any(target in encoding for target in ['identity', 'custom', 'difference']):
                visual_anomalies.append({"type": "encoding", "details": encoding})

        # ----------------------------
        # Hidden text detection
        # ----------------------------
        if font_size is not None and font_size < MIN_VISIBLE_FONT_SIZE:
            visual_anomalies.append({
                "type": "tiny_font",
                "size": font_size,
                "text": clean_text[:50]
            })

        elif x < OUT_OF_BOUNDS_THRESHOLD or y < OUT_OF_BOUNDS_THRESHOLD:
            visual_anomalies.append({
                "type": "off_canvas",
                "x": int(x),
                "y": int(y),
                "text": clean_text[:50]
            })

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
            has_malformed_tree = True

        for i, page in pages_iterator:
            text_count_before = len(full_text)
            try:
                page.extract_text(visitor_text=text_inspection_visitor)
            except Exception:
                continue

            text_count_after = len(full_text)

            if text_count_before == text_count_after and has_images(page):
                image_only_pages.append(i + 1)

    except Exception:
        logger.exception("Text Analysis collapsed during extraction")

    return {
        "text": "".join(full_text),
        "anomalies": visual_anomalies,
        "image_only_pages": image_only_pages,
        "malformed_tree": has_malformed_tree
    }

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