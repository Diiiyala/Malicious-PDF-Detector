from pdfminer.high_level import extract_text as pdfminer_extract
import logging, re

from analysis.core.extractor import extract_all_data
from analysis.core.risk import calculate_risk, SEVERITY_MAX

from analysis.utils.normalizer import normalize_all
from analysis.utils.script_aggregator import ScriptAggregator
from analysis.utils.models import Threat, ExtractedContent

from analysis.detectors.text import detect_text_anomalies
from analysis.detectors.content import analyze_content
from analysis.detectors.structure.main import analyze_structure
from analysis.detectors.metadata import analyze_metadata
from analysis.detectors.binary import analyze_binary

logger = logging.getLogger(__name__)

CATEGORY_BUCKETS = {
    "Content": "content",
    "Structure": "structure",
    "Action/Trigger": "structure",
    "Stream/Object": "structure",
    "Metadata": "metadata",
    "Text Extraction": "text_extraction",
    "Binary Structure": "binary",
    "Binary Content": "binary",
    "Binary Discovery": "binary",
    "Network / Links": "binary",
}

def analyze_all_aspects(reader, file_stream, file_content, filename, initial_structure_findings=None):

    aggregator = ScriptAggregator()
    all_threats = []

    if initial_structure_findings:
        for finding in initial_structure_findings:
            all_threats.append(Threat(
                id="SYS-REPAIR", category="Structure", severity=10, 
                description=finding.replace("ALERT: ", ""), location="PDF Initialization"
            ))
            
    # -------------------------------------------------------------------------
    # 1. Extraction Layer
    # ------------------------------------------------------------------------- 
    
    try:
        content = extract_all_data(reader, file_content, filename)
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        content = ExtractedContent(filename=filename, raw_binary=file_content)
        
    # -------------------------------------------------------------------------
    # 2. Text Fallback & Normalization
    # -------------------------------------------------------------------------

    if not content.extracted_text and file_stream:
        try:
            logger.info("Attempting pdfminer.six for text extraction...")
            file_stream.seek(0)
            content.extracted_text = pdfminer_extract(file_stream)
        except Exception as e:
            logger.warning(f"pdfminer fallback failed: {e}")
            content.extracted_text = file_content.decode('utf-8', errors='ignore')

    if content.extracted_text:
        content.extracted_text = normalize_all(content.extracted_text, aggregator=aggregator)
        
    # -------------------------------------------------------------------------
    # 3. Detection Layer
    # -------------------------------------------------------------------------
    
    try:
        all_threats.extend(detect_text_anomalies(content))
    except Exception as e: logger.error(f"Text anomaly detection failed: {e}")

    try:
        all_threats.extend(analyze_content(content, aggregator=aggregator))
    except Exception as e: logger.error(f"Content analysis failed: {e}")

    try:
        all_threats.extend(analyze_structure(content, reader, aggregator=aggregator))
    except Exception as e: logger.error(f"Structure analysis failed: {e}")

    try:
        all_threats.extend(analyze_binary(content, aggregator=aggregator))
    except Exception as e: logger.error(f"Binary analysis failed: {e}")

    try:
        all_threats.extend(analyze_metadata(content))
    except Exception as e: logger.error(f"Metadata analysis failed: {e}")
    
    # -------------------------------------------------------------------------
    # 4. Deduplication
    # -------------------------------------------------------------------------   
    unique_threats = consolidate_threats(deduplicate_threats(all_threats))
    
    # -------------------------------------------------------------------------
    # 5. Risk Calculation
    # -------------------------------------------------------------------------
    score, risk_percentage, level, status = calculate_risk(unique_threats)
    
    # -------------------------------------------------------------------------
    # 6. Formatting Output 
    # -------------------------------------------------------------------------
    
    categorized_findings = {
        "content": {"results": [], "count": 0},
        "structure": {"results": [], "count": 0},
        "metadata": {"results": [], "count": 0},
        "text_extraction": {"results": [], "count": 0},
        "binary": {"results": [], "count": 0},
        "not_specified": {"results": [], "count": 0}
    }

    for t in unique_threats:
        formatted_string = f"[Severity: {t.severity}/{SEVERITY_MAX}] {t.description} | Location: {t.location}"
        
        target_cat = CATEGORY_BUCKETS.get(t.category)
        if target_cat is None:
            logger.warning("Unmapped threat category %r (id=%s) - filing under 'not_specified'", t.category, t.id)
            target_cat = "not_specified"

        categorized_findings[target_cat]["results"].append(formatted_string)
        categorized_findings[target_cat]["count"] += 1

    return {
        "findings": categorized_findings,
        "extracted_scripts": aggregator.get_all_scripts(),
        "risk_score": score,
        "risk_percentage": risk_percentage,
        "risk_level": level,
        "status": status
    }
    
# ----------------------------------------------------------------------------
#  Helpers
# ----------------------------------------------------------------------------
 
MAX_LOCATIONS_PER_THREAT = 20
MAX_FOUND_VALUES_PER_THREAT = 20

SUBSUMABLE_IDS = {
    "URI-OBFUSCATED",
    "URI-DETECTED",
    "URI-DETECTED-HEX",
    "STR-OBJ-REMOTE-RES",
    "BIN-STR-LAUNCH",
    "BIN-STR-OPEN",
    "BIN-STR-SILENT",
}

IOC_TOKEN_PATTERN = re.compile(
    r"""(?:[a-z][a-z0-9+.\-]{1,15}://[^\s'"()\[\]|]+|\\\\[^\s'"()\[\]|]+)""",
    re.IGNORECASE,
)

NAME_TOKEN_PATTERN = re.compile(r"/([A-Za-z][A-Za-z0-9]{1,24})")
WORD_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]*")


def extract_evidence(description: str):
    urls = {m.rstrip(".,;:'\"") for m in IOC_TOKEN_PATTERN.findall(description)}
    without_urls = IOC_TOKEN_PATTERN.sub(" ", description)
    names = {n.lower() for n in NAME_TOKEN_PATTERN.findall(without_urls)}
    return urls, names


def consolidate_threats(threats: list[Threat]) -> list[Threat]:

    url_evidence = {}
    word_evidence = {}

    for t in threats:
        if t.id in SUBSUMABLE_IDS:
            continue

        urls, _ = extract_evidence(t.description)
        for url in urls:
            url_evidence[url] = max(url_evidence.get(url, 0), t.severity)

        without_urls = IOC_TOKEN_PATTERN.sub(" ", t.description)
        for word in WORD_PATTERN.findall(without_urls):
            word = word.lower()
            word_evidence[word] = max(word_evidence.get(word, 0), t.severity)

    kept = []

    for t in threats:
        if t.id in SUBSUMABLE_IDS:
            urls, names = extract_evidence(t.description)

            covered = bool(urls or names) \
                and all(url_evidence.get(u, -1) >= t.severity for u in urls) \
                and all(word_evidence.get(n, -1) >= t.severity for n in names)

            if covered:
                logger.debug("Absorbed redundant finding %s (%s)", t.id, t.description)
                continue

        kept.append(t)

    return kept

FOUND_SUFFIX_PATTERN = re.compile(r"\s*\(Found:\s*'.*'\)\s*$")
FOUND_VALUES_PATTERN = re.compile(r"\(Found:\s*'([^']+)'\)")


def deduplicate_threats(threats: list[Threat]) -> list[Threat]:
    grouped = {}

    for t in threats:
        core_desc = FOUND_SUFFIX_PATTERN.sub("", t.description).strip()
        key = core_desc.lower()

        entry = grouped.get(key)

        if entry is None:
            entry = {"threat": t, "core_desc": core_desc, "locations": set(), "found": {}}
            grouped[key] = entry
        else:
            existing = entry["threat"]

            if t.severity > existing.severity:
                existing.severity = t.severity
                existing.id = t.id

        for location in t.location.split(","):
            location = location.strip()
            if location:
                entry["locations"].add(location)

        match = FOUND_VALUES_PATTERN.search(t.description)
        if match:
            for value in match.group(1).split("', '"):
                entry["found"].setdefault(value, None)

    merged = []

    for entry in grouped.values():
        threat = entry["threat"]
        threat.location = render_capped(sorted(entry["locations"]), MAX_LOCATIONS_PER_THREAT)

        if entry["found"]:
            values = list(entry["found"])
            shown = values[:MAX_FOUND_VALUES_PER_THREAT]
            remaining = len(values) - len(shown)
            joined = "', '".join(shown)
            suffix = f", +{remaining} more" if remaining else ""
            threat.description = f"{entry['core_desc']} (Found: '{joined}'{suffix})"

        merged.append(threat)

    return sorted(merged, key=lambda x: x.severity, reverse=True)


def render_capped(items: list[str], limit: int) -> str:
    shown = items[:limit]
    remaining = len(items) - len(shown)
    text = ", ".join(shown)

    if remaining > 0:
        text = f"{text}, (+{remaining} more)" if text else f"(+{remaining} more)"

    return text
