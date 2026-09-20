import logging
from analysis.utils.models import Threat
from analysis.signatures import (
    SUSPICIOUS_NAME_KEYS, EXECUTABLE_EXTENSIONS, MACRO_EXTENSIONS, DECOY_EXTENSIONS,
    BIDI_CONTROL_CHARS, EXECUTABLE_MAGIC,
)

logger = logging.getLogger(__name__)

WHITELIST = ["/Dests", "/AP", "/Pages", "/Templates", "/IDS", "/URLS"]

def analyze_names(root) -> list[Threat]:

    threats = []
    js_scripts = set()
    embedded_files = {}
    unknown_items = set()

    try:
        if root and "/Names" in root:
            names = root["/Names"].get_object()

            # Iterate through all categories in the NameTree
            for category_key in names.keys():
                try:
                    walk_names_tree(names[category_key], threats, WHITELIST, unknown_items, js_scripts, embedded_files, category=category_key)
                except Exception as e:
                    logger.debug("NameTree category %s could not be walked: %s", category_key, e)
                    threats.append(Threat(
                        id="STR-NAMES-WALK-FAIL", category="Structure", severity=7,
                        description=f"NameTree branch could not be parsed: {category_key}", location="NameTree"
                    ))

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
                threats.extend(classify_embedded_files(embedded_files))
            if unknown_items:
                threats.append(Threat(
                    id="STR-NAMES-UNKNOWN", category="Structure", severity=2,
                    description=f"Unknown NameTree entries found: {sorted(unknown_items)}", location="NameTree"
                ))

    except Exception:
        pass

    return threats


def walk_names_tree(node, threats, whitelist, untrusted_items, js_scripts, embedded_files, category=None, visited=None):

    if not node: return

    if visited is None:
        visited = set()

    marker = node.idnum if hasattr(node, "idnum") else id(node)
    if marker in visited: return
    visited.add(marker)

    node = node.get_object()

    # Check for Child Nodes
    if "/Kids" in node:
        for kid in node["/Kids"]:
            walk_names_tree(kid, threats, whitelist, untrusted_items, js_scripts, embedded_files, category, visited)

    # Check for Leaf Nodes with Data
    if "/Names" in node:
        names_list = node["/Names"]

        if len(names_list) % 2:
            threats.append(Threat(
                id="STR-NAMES-MALFORMED", category="Structure", severity=7,
                description=f"Malformed NameTree leaf ({len(names_list)} entries in a key/value array)",
                location=f"NameTree: {category}"
            ))

        for i in range(0, len(names_list) - 1, 2):
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
        embedded_files[key] = value_obj

    # Analyze suspicious NameTree keys
    if key in SUSPICIOUS_NAME_KEYS:
        threats.append(Threat(
            id="STR-NAMES-SUSP-KEY", category="Structure", severity=10,
            description=f"Suspicious key detected in NameTree: {key}", location=f"NameTree: {category}"
        ))


# ---------------------------------------------------------------------------
# Embedded file classification (name, hidden /UF name, real payload)
# ---------------------------------------------------------------------------

def pdf_str(value) -> str:

    try:
        if hasattr(value, "get_object"):
            value = value.get_object()
        return str(value) if value is not None else ""
    except Exception:
        return ""


def extension_verdict(name: str):

    if any(ch in name for ch in BIDI_CONTROL_CHARS):
        return 14, "STR-NAMES-EMBEDDED-BIDI", "uses a hidden text-direction character to disguise its extension"

    parts = name.strip().rstrip(" .").lower().split(".")
    if len(parts) < 2:
        return None

    ext = parts[-1]
    if ext in EXECUTABLE_EXTENSIONS:
        if len(parts) >= 3 and parts[-2] in DECOY_EXTENSIONS:
            return 14, "STR-NAMES-EMBEDDED-DOUBLE-EXT", f"has a double extension (.{parts[-2]}.{ext}) disguising an executable"
        return 13, "STR-NAMES-EMBEDDED-EXEC", f"is an executable/script file (.{ext})"
    if ext in MACRO_EXTENSIONS:
        return 11, "STR-NAMES-EMBEDDED-MACRO", f"is a macro-enabled Office document (.{ext})"
    return None


def payload_kind(filespec: dict):

    try:
        ef = filespec.get("/EF")
        ef = ef.get_object() if hasattr(ef, "get_object") else ef
        stream = None
        if isinstance(ef, dict):
            stream = ef.get("/F") or ef.get("/UF")
        stream = stream.get_object() if hasattr(stream, "get_object") else stream
        if stream is None or not hasattr(stream, "get_data"):
            return None
        head = stream.get_data()[:4]
        for magic, label in EXECUTABLE_MAGIC.items():
            if head.startswith(magic):
                return label
    except MemoryError:
        return None
    except Exception as e:
        logger.debug("Embedded payload inspection failed: %s", e)
    return None


def classify_embedded_files(embedded_files: dict) -> list[Threat]:

    threats = []

    for key, value_obj in embedded_files.items():
        names = {pdf_str(key)}
        filespec = None

        try:
            filespec = value_obj.get_object() if hasattr(value_obj, "get_object") else value_obj
            if isinstance(filespec, dict):
                for field in ("/F", "/UF"):
                    if field in filespec:
                        names.add(pdf_str(filespec[field]))
            else:
                filespec = None
        except Exception as e:
            logger.debug("Filespec for %r unreadable: %s", key, e)

        for name in sorted(n for n in names if n):
            verdict = extension_verdict(name)
            if verdict:
                severity, t_id, reason = verdict
                shown = "".join(ch for ch in name if ch not in BIDI_CONTROL_CHARS) if t_id.endswith("BIDI") else name
                threats.append(Threat(
                    id=t_id, category="Structure", severity=severity,
                    description=f"Embedded file '{shown}' {reason}", location="NameTree"
                ))
                break

        if filespec is not None:
            kind = payload_kind(filespec)
            if kind:
                threats.append(Threat(
                    id="STR-NAMES-EMBEDDED-PAYLOAD", category="Structure", severity=14,
                    description=f"Embedded file '{pdf_str(key)}' contains an executable payload: {kind}", location="NameTree"
                ))

    return threats
