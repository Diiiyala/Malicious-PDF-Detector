from analysis.utils.models import ExtractedContent, Threat
from analysis.detectors.structure.header import analyze_header
from analysis.detectors.structure.catalog import analyze_catalog
from analysis.detectors.structure.names import analyze_names
from analysis.detectors.structure.actions import perform_action_analysis
from analysis.detectors.structure.streams import analyze_streams_and_objects
from analysis.detectors.structure.evasion import (
    analyze_dict_evasion,
    scan_name_obfuscation,
    name_obfuscation_index,
    build_name_obfuscation_threats,
)


def _resolve_root(reader):
    try:
        root_obj = reader.trailer.get("/Root")
        return root_obj.get_object() if root_obj else None
    except Exception:
        return None


def analyze_structure(content: ExtractedContent, reader, aggregator=None) -> list[Threat]:
    threats = list(analyze_header(content.raw_binary))

    name_records = []
    try:
        evasion_threats, conflicting_targets = analyze_dict_evasion(content.raw_binary)
        threats += evasion_threats
        name_records = scan_name_obfuscation(content.raw_binary)
    except Exception:
        conflicting_targets = []

    if reader is None:
        return threats + build_name_obfuscation_threats(name_records)

    root = _resolve_root(reader)

    threats += analyze_catalog(root, aggregator)
    threats += analyze_names(root)

    merged_names = set()
    try:
        threats += perform_action_analysis(
            reader, root, aggregator, conflicting_targets,
            name_obfuscation_index(name_records), merged_names,
        )
    except Exception:
        pass

    threats += build_name_obfuscation_threats(name_records, merged_names)

    try:
        threats += analyze_streams_and_objects(reader, aggregator)
    except Exception:
        pass

    if content.has_encryption:
        threats.append(Threat(
            id="STR-ENCRYPTED", category="Structure", severity=5,
            description="Encrypted PDF (Restricted access)", location="Document Settings"
        ))

    return threats
