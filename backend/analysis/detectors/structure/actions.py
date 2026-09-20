import re, logging
from analysis.utils.models import Threat
from analysis.detectors.structure.collector import ThreatCollector
from analysis.signatures import SUSPICIOUS_URI_KEYWORDS, NAVIGATION_ACTIONS, AA_SILENT_TRIGGERS, DEST_FIT_TYPES

logger = logging.getLogger(__name__)

MAX_SEVERITY = 15
OBFUSCATION_BONUS = 2

DEFAULT_TARGET_PHRASE = "to redirect the user to"
TARGET_PHRASE = {
    "SubmitForm": "to submit the user's data to",
    "ImportData": "to import external data from",
}
CLICKJACK_COVERAGE = 0.9
TRANSPARENT_WIDGET_MAX_COVERAGE = 0.05
WIDGET_GRID_THRESHOLD = 3


def is_plain_destination(obj) -> bool:
    if isinstance(obj, list):
        if len(obj) < 2:
            return False
        fit = obj[1].get_object() if hasattr(obj[1], "get_object") else obj[1]
        if str(fit) not in DEST_FIT_TYPES:
            return False
        for item in obj[2:]:
            item = item.get_object() if hasattr(item, "get_object") else item
            if isinstance(item, (dict, list)):
                return False
        return True
    return isinstance(obj, str)  # named destination


def perform_action_analysis(reader, root, aggregator=None, conflicting_targets=None,
                            obfuscated_names=None, merged_names=None) -> list[Threat]:
    collector = ThreatCollector("Action/Trigger")
    add_threat = collector.add

    def obfuscation_note(action_type, host_severity):

        if not obfuscated_names or not action_type:
            return ""

        key = str(action_type).lower()
        entry = obfuscated_names.get(key)
        if not entry:
            return ""

        written, severity = entry
        if merged_names is not None and host_severity >= severity:
            merged_names.add(key)

        return written

    def with_obfuscation(severity, written):
        return min(MAX_SEVERITY, severity + OBFUSCATION_BONUS) if written else severity

    def obfuscation_clause(action_type, written):
        return f" (The {action_type} action is obfuscated as {written})" if written else ""

    def describe_clickjack(label, target, written):

        sentence = f"A Clickjacking overlay uses a {label} trigger" if label \
            else "A Clickjacking overlay uses an unidentified trigger"

        if target:
            sentence += f" {TARGET_PHRASE.get(label, DEFAULT_TARGET_PHRASE)} {target}"

        if written:
            sentence += f" (The {label} action is obfuscated as {written})"

        return sentence + decoy_note

    decoy_note = ""
    if conflicting_targets:
        decoy_note = (
            " (The displayed target may be a decoy - a duplicate action in the "
            "same object points elsewhere; see the parser-confusion finding)"
        )

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

                if is_plain_destination(oa_obj):
                    action_traced = True

                elif (isinstance(oa_obj, dict) and "/S" in oa_obj
                      and str(oa_obj.get("/S")) in NAVIGATION_ACTIONS
                      and "/Next" not in oa_obj):
                    action_traced = True

                elif isinstance(oa_obj, dict) and "/S" in oa_obj:
                    action_type = str(oa_obj.get("/S")).replace("/", "")

                    open_written = obfuscation_note(f"/{action_type}", 12)
                    add_threat("STR-ACT-OPEN-EXEC", with_obfuscation(12, open_written),
                               f"Automatic execution trigger (/OpenAction) executing Action (/{action_type})"
                               + (f" (The /{action_type} action is obfuscated as {open_written})" if open_written else ""),
                               "Catalog")
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

            for silent_trigger in AA_SILENT_TRIGGERS:
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
                        a_type = None
                        has_js = False
                        action_label = None
                        action_target = None
                        extracted_path = None

                        if "/A" in obj:
                            action_dict = obj["/A"].get_object()
                            a_type = action_dict.get("/S")
                            extracted_path = extract_action_path(action_dict)

                            if a_type:
                                action_label = str(a_type).replace("/", "")

                            if a_type == "/JavaScript":
                                has_js = True

                            elif a_type == "/URI":
                                uri_link = str(action_dict.get("/URI", "Unknown Link"))
                                extracted_path = uri_link
                                action_target = uri_link

                            elif a_type in ["/SubmitForm", "/Launch", "/GoToR",
                                            "/ImportData", "/Thread", "/GoToE"]:
                                action_target = extracted_path

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
                                    cj_written = obfuscation_note(a_type, 13)
                                    add_threat("STR-ACT-CLICKJACK", with_obfuscation(13, cj_written),
                                               describe_clickjack(action_label, action_target, cj_written),
                                               loc_str)
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
                                imp_written = obfuscation_note(a_type, 12)
                                add_threat("STR-ACT-IMPORTDATA", with_obfuscation(12, imp_written), f"External data import trigger (/ImportData) pointing to: ({extracted_path})" + obfuscation_clause("/ImportData", imp_written), loc_str)
                            elif a_type == "/GoToR":
                                gotor_written = obfuscation_note(a_type, 12)
                                add_threat("STR-ACT-GOTOR", with_obfuscation(12, gotor_written), f"Annotation (/GoToR) pointing to: ({extracted_path})" + obfuscation_clause("/GoToR", gotor_written), loc_str)
                            elif a_type == "/GoToE":
                                gotoe_written = obfuscation_note(a_type, 11)
                                add_threat("STR-ACT-GOTOE", with_obfuscation(11, gotoe_written), f"Suspicious /GoToE pointing to: {extracted_path if extracted_path else 'Internal'}" + obfuscation_clause("/GoToE", gotoe_written), loc_str)
                            elif a_type in ["/Launch", "/SubmitForm", "/Thread"]:
                                a_clean = str(a_type).replace("/", "")
                                desc = f"Annotation (/{a_clean}) pointing to: ({extracted_path})" if extracted_path else f"Annotation (/{a_clean})"
                                launch_written = obfuscation_note(a_type, 10)
                                add_threat(f"STR-ACT-{a_clean.upper()}", with_obfuscation(10, launch_written), desc + obfuscation_clause(a_type, launch_written), loc_str)
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

        if action_type is not None and str(action_type) not in NAVIGATION_ACTIONS:
            add_threat_func("STR-ACT-BOOKMARK", 4, f"Bookmark ({action_type})", f"Bookmark: {title}")

    # Traverse children and siblings
    for link in ("/First", "/Next"):
        if link in node:
            child = node.raw_get(link) if hasattr(node, "raw_get") else node[link]
            check_outlines_recursive(child, add_threat_func, visited)
