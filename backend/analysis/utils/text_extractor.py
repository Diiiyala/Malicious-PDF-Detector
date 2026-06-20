import logging, math
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Constants for Visual Anomaly Detection
# -------------------------------------------------------------------------
MIN_VISIBLE_FONT_SIZE = 1.0
OFF_CANVAS_MARGIN = 72
DEFAULT_PAGE_BOUNDS = (0.0, 0.0, 612.0, 792.0)

def extract_text_and_visuals(reader):
    full_text = []
    visual_anomalies = []
    image_only_pages = []
    has_malformed_tree = False
    page_bounds = DEFAULT_PAGE_BOUNDS

    # -------------------------------------------------------------------------
    # Internal Visitor Function
    # -------------------------------------------------------------------------
    def text_inspection_visitor(text, cm, tm, font_dict, font_size):
        if not text or not text.strip() or not tm or len(tm) < 6:
            return

        clean_text = text.strip()

        if not cm or len(cm) < 6:
            cm = [1, 0, 0, 1, 0, 0]

        # Composed 2x2 linear part (controls size / rotation / mirroring)
        a = tm[0] * cm[0] + tm[1] * cm[2]
        b = tm[0] * cm[1] + tm[1] * cm[3]
        c = tm[2] * cm[0] + tm[3] * cm[2]
        d = tm[2] * cm[1] + tm[3] * cm[3]

        # Composed origin (true device position of the text)
        dx = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
        dy = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]

        det = a * d - b * c
        eff_scale = math.sqrt(abs(det))
        nominal = font_size if (font_size and font_size > 0) else 1.0
        eff_size = nominal * eff_scale

        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------
        # Hidden text detection
        # ----------------------------------------------------------------------
        if eff_scale <= 1e-3 or eff_size < MIN_VISIBLE_FONT_SIZE:
            visual_anomalies.append({
                "type": "tiny_font",
                "size": round(eff_size, 3),
                "text": clean_text[:50]
            })

        else:
            x0, y0, x1, y1 = page_bounds
            mx = max(OFF_CANVAS_MARGIN, x1 - x0)
            my = max(OFF_CANVAS_MARGIN, y1 - y0)
            if dx < x0 - mx or dx > x1 + mx or dy < y0 - my or dy > y1 + my:
                visual_anomalies.append({
                    "type": "off_canvas",
                    "x": int(dx),
                    "y": int(dy),
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
            try:
                box = page.cropbox if page.cropbox is not None else page.mediabox
                page_bounds = (float(box[0]), float(box[1]), float(box[2]), float(box[3]))
            except Exception:
                page_bounds = DEFAULT_PAGE_BOUNDS

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