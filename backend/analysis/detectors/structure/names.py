import logging
from analysis.utils.models import Threat
from analysis.signatures import SUSPICIOUS_NAME_KEYS

logger = logging.getLogger(__name__)

WHITELIST = ["/Dests", "/AP", "/Pages", "/Templates", "/IDS", "/URLS"]

def analyze_names(root) -> list[Threat]:

    threats = []
    js_scripts = set()
    embedded_files = set()
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
        embedded_files.add(key)

    # Analyze suspicious NameTree keys
    if key in SUSPICIOUS_NAME_KEYS:
        threats.append(Threat(
            id="STR-NAMES-SUSP-KEY", category="Structure", severity=10,
            description=f"Suspicious key detected in NameTree: {key}", location=f"NameTree: {category}"
        ))
