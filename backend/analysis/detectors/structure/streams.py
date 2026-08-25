import re, logging
from analysis.utils.models import ExtractedContent, Threat
from analysis.detectors.structure.collector import ThreatCollector
from analysis.detectors.content import analyze_content

logger = logging.getLogger(__name__)


def decode_pdf_text(raw: bytes) -> str:
    if raw[:2] in (b"\xfe\xff", b"\xff\xfe"):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def resolve_script_text(value):
    if value is None:
        return None

    if hasattr(value, "get_object"):
        value = value.get_object()

    if hasattr(value, "get_data"):
        try:
            return decode_pdf_text(value.get_data())
        except Exception as e:
            logger.debug("Could not decode JS stream: %s", e)
            return None

    if isinstance(value, bytes):
        return decode_pdf_text(value)

    if isinstance(value, str):
        return str(value)

    return None


def analyze_streams_and_objects(reader, aggregator=None) -> list[Threat]:
    threats = []
    collector = ThreatCollector("Stream/Object")
    add_threat = collector.add
    visited_objects = set()
    suspicious_filters = ["/JBIG2Decode", "/Crypt"]

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

            if isinstance(obj, dict):

                # 1. Metadata XML / XXE Scan
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

                # 2. FontMatrix Injection Detection (CVE-2024-4367)
                if "/FontMatrix" in obj:
                    matrix_str = str(obj["/FontMatrix"])
                    if re.search(r'[a-zA-Z]{4,}', matrix_str):
                        keywords = ["fetch", "eval", "function", "xmlhttp", "axios", "xml", "script"]
                        if any(k in matrix_str.lower() for k in keywords):
                            add_threat("STR-OBJ-FONT-JS", 12, "Scripting indicator found in font object", location_label)

                # 3. Remote Resource References
                if "/F" in obj:
                    if obj.get("/Subtype") == "/Image" or "/FS" in obj:
                        f_val = obj.get("/F")
                        if hasattr(f_val, "get_object"): f_val = f_val.get_object()
                        f_path = str(f_val.get("/F")) if isinstance(f_val, dict) and "/F" in f_val else str(f_val)
                        add_threat("STR-OBJ-REMOTE-RES", 12, f"Remote resource reference detected (Path: {f_path})", location_label)

                # 4. JavaScript Injection
                if "/JS" in obj or "/JavaScript" in obj:
                    js_content = obj.get("/JS")
                    if js_content is None:
                        js_content = obj.get("/JavaScript")

                    content_to_scan = resolve_script_text(js_content)

                    if not content_to_scan or not content_to_scan.strip():
                        logger.debug("No script text carried by /JS entry in %s", location_label)
                    else:
                        try:
                            if aggregator:
                                aggregator.add_script(content_to_scan, location_label, source_object=location_label)

                            dummy_content = ExtractedContent(extracted_text=content_to_scan)
                            c_threats = analyze_content(dummy_content, aggregator=aggregator)
                            for t in c_threats:
                                t.location = f"{location_label} (JS Stream)"
                                threats.append(t)
                        except Exception as e:
                            logger.debug("JS stream analysis failed: %s", e)


                # 5. XFA / FormCalc Injection
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
                    except Exception as e:
                        logger.debug("XFA stream analysis failed: %s", e)

                # 6. Suspicious Compression Filters
                filt = obj.get("/Filter")
                if filt:
                    filt_list = filt if isinstance(filt, list) else [filt]
                    for f in filt_list:
                        f_name = str(f)
                        for s_filt in suspicious_filters:
                            if s_filt in f_name:
                                add_threat("STR-OBJ-SUSP-FILTER", 8, f"Suspicious stream filter ({f_name}) detected", location_label)

                # 7. Deep EmbeddedFile Stream Scan (HTML / JS Carriers)
                if obj.get("/Type") == "/EmbeddedFile" or "/Subtype" in obj:
                    try:
                        if hasattr(obj, "get_data"):
                            raw_stream_data = obj.get_data()
                            if raw_stream_data:
                                decoded_stream_text = raw_stream_data.decode('utf-8', errors='ignore')
                                control = sum(1 for c in decoded_stream_text if ord(c) < 32 and c not in "\t\r\n")
                                text_like = decoded_stream_text and (control / len(decoded_stream_text)) <= 0.05
                                has_markup = any(k in decoded_stream_text.lower() for k in ["<script", "<html", "javascript:"])
                                if text_like and has_markup:
                                    if aggregator:
                                        aggregator.add_script(decoded_stream_text, f"{location_label} (Embedded)", script_type="Embedded HTML/JS Payload")

                                    dummy_content = ExtractedContent(extracted_text=decoded_stream_text)
                                    emb_threats = analyze_content(dummy_content, aggregator=aggregator)
                                    for t in emb_threats:
                                        t.location = f"{location_label} (Embedded File)"
                                        threats.append(t)
                    except Exception as e:
                        logger.debug("Embedded-file stream analysis failed: %s", e)

                # 8. Recursive Traversal of Nested Objects / Arrays
                for key, value in obj.items():
                    if isinstance(value, dict) or isinstance(value, list):
                        process_obj(value, location_label)

                # 9. Execution Triggers (Zero-Click & Events)
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
    threats.extend(collector.render())
    return threats
