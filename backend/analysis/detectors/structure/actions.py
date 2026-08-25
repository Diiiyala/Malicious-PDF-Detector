import re, logging
from analysis.utils.models import Threat
from analysis.detectors.structure.collector import ThreatCollector
from analysis.signatures import SUSPICIOUS_URI_KEYWORDS

logger = logging.getLogger(__name__)

CLICKJACK_COVERAGE = 0.9
TRANSPARENT_WIDGET_MAX_COVERAGE = 0.05
WIDGET_GRID_THRESHOLD = 3


def perform_action_analysis(reader, root, aggregator=None) -> list[Threat]:
    collector = ThreatCollector("Action/Trigger")
    add_threat = collector.add

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

            except Exception as e:
                logger.debug("OpenAction parsing failed: %s", e)

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

                visible_widgets_on_page = 0

                if "/Annots" in page_obj:
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

                        coverage = None

                        if rect and page_area > 0:
                            try:
                                width = abs(float(rect[2]) - float(rect[0]))
                                height = abs(float(rect[3]) - float(rect[1]))
                                coverage = (width * height) / page_area
                            except (TypeError, ValueError, IndexError) as e:
                                logger.debug("Could not measure annotation /Rect on %s: %s", loc_str, e)

                        if coverage is not None:
                            if coverage > CLICKJACK_COVERAGE:
                                if has_js or is_widget or is_link_trigger:
                                    add_threat("STR-ACT-CLICKJACK", 13, f"Clickjacking overlay ({trigger_type})", loc_str)
                                    is_clickjacking = True

                            if is_widget and is_transparent and coverage < TRANSPARENT_WIDGET_MAX_COVERAGE:
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

                if visible_widgets_on_page > WIDGET_GRID_THRESHOLD:
                    add_threat("STR-ACT-CLICKJACK-GRID", 12, "Clickjacking Suspicious invisible button grid detected", loc_str)

            except Exception as page_error:
                logger.debug("Annotation analysis aborted on %s: %s", loc_str, page_error)
                continue

    except Exception as e:
        logger.debug("Could not iterate document pages: %s", e)
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

    return collector.render()


def check_outlines_recursive(node, add_threat_func, visited=None):
    if not node: return

    if visited is None:
        visited = set()

    marker = node.idnum if hasattr(node, "idnum") else id(node)
    if marker in visited: return
    visited.add(marker)

    node = node.get_object()

    # Check for Action in current Bookmark node
    if "/A" in node:
        title = node.get("/Title", "Untitled Bookmark")
        action = node["/A"]
        action_type = action.get("/S") if hasattr(action, "get") else None
        add_threat_func("STR-ACT-BOOKMARK", 4, f"Bookmark ({action_type})", f"Bookmark: {title}")

    # Traverse children and siblings
    for link in ("/First", "/Next"):
        if link in node:
            child = node.raw_get(link) if hasattr(node, "raw_get") else node[link]
            check_outlines_recursive(child, add_threat_func, visited)
