import re, logging
from analysis.utils.models import Threat
from analysis.detectors.content import scan_text

logger = logging.getLogger(__name__)

def analyze_catalog(root, aggregator=None) -> list[Threat]:

    threats = []
    
    try:
        if root:
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

                                            content_threats = scan_text(decoded_text, aggregator=aggregator)

                                            for ct in content_threats:
                                                ct.category = "Structure"
                                                ct.location = f"Inside embedded file: {f_name}"
                                                threats.append(ct)

                                    except Exception:
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

    except Exception:
        pass

    return threats
