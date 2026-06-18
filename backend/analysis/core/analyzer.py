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
    unique_threats = deduplicate_threats(all_threats)
    
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
        "binary": {"results": [], "count": 0}
    }

    for t in unique_threats:
        formatted_string = f"[Severity: {t.severity}/{SEVERITY_MAX}] {t.description} | Location: {t.location}"
        
        cat_key = t.category.lower()
        if "metadata" in cat_key: target_cat = "metadata"
        elif any(k in cat_key for k in ["structure", "stream", "action"]): target_cat = "structure"
        elif "text" in cat_key: target_cat = "text_extraction"
        elif "binary" in cat_key: target_cat = "binary"
        else: target_cat = "content"

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
 
def deduplicate_threats(threats: list[Threat]) -> list[Threat]:
    grouped = {}
    
    for t in threats:
        core_desc = re.sub(r"\s*\(Found:\s*'.*'\)", "", t.description).strip()
        key = core_desc.lower()
        
        if key not in grouped:
            grouped[key] = t
        else:
            existing = grouped[key]
            
            if t.severity > existing.severity:
                existing.severity = t.severity
                existing.id = t.id 
            
            existing_locs = [l.strip() for l in existing.location.split(",")]
            new_locs = [l.strip() for l in t.location.split(",")]
            existing.location = ", ".join(sorted(list(set(existing_locs + new_locs))))
            
            match_new = re.search(r"\(Found:\s*'([^']+)'\)", t.description)
            match_existing = re.search(r"\(Found:\s*'([^']+)'\)", existing.description)
            
            if match_new and match_existing:
                existing_words = match_existing.group(1).split("', '")
                new_word = match_new.group(1)
                
                if new_word not in existing_words:
                    existing_words.append(new_word)
                
                combined_words = "', '".join(existing_words)
                existing.description = f"{core_desc} (Found: '{combined_words}')"

    return sorted(list(grouped.values()), key=lambda x: x.severity, reverse=True)