from pdfminer.high_level import extract_text as pdfminer_extract
import logging, re

from analysis.binary import binary_scan
from analysis.normalizer import normalize_all
from analysis.text import extract_text
from analysis.content import analyze_content
from analysis.structure import analyze_structure
from analysis.metadata import analyze_metadata
from analysis.risk import calculate_risk

logger = logging.getLogger(__name__)

def analyze_all_aspects(reader, file_stream, file_content, filename, initial_structure_findings=None):
    
    res_text, res_content, res_metadata = [], [], []
    res_structure = initial_structure_findings if initial_structure_findings else []
    text = ""
    
    # -------------------------------------------------------------------------
    # 1. Text Extraction
    # -------------------------------------------------------------------------
    if reader:
        try:
            text, res_text = extract_text(reader)
            
        except Exception as e:
            logger.warning(f"pypdf extraction failed, trying pdfminer fallback: {e}")
            try:
                file_stream.seek(0)
                text = pdfminer_extract(file_stream)
                res_text = ["INFO: Text extracted using fallback engine (pdfminer.six) after pypdf failure"]
            except Exception:
                text = file_content.decode('utf-8', errors='ignore')
                res_text = ["ALERT: Analysis process interrupted, using raw binary decode"]
    else:
        try:
            logger.info("Attempting pdfminer.six for text extraction (No Reader)...")
            file_stream.seek(0)
            text = pdfminer_extract(file_stream)
            res_text = ["INFO: Text extracted using fallback engine (pdfminer.six)"]
            
        except Exception as e:
            logger.error(f"pdfminer fallback failed: {e}")
            text = file_content.decode('utf-8', errors='ignore')
            res_text = ["INFO: Deep text extraction skipped, using raw binary decode"]


    # -------------------------------------------------------------------------
    # 2. Normalization
    # -------------------------------------------------------------------------
    clean_text = normalize_all(text)
    
    
    # -------------------------------------------------------------------------
    # 3. Content
    # -------------------------------------------------------------------------
    try:
        res_content = analyze_content(clean_text)
        
        raw_findings = binary_scan(file_content)
        res_content.extend(raw_findings)

        raw_uris = re.findall(rb'/URI\s*\((.*?)\)', file_content)
        for uri in raw_uris:
            uri_str = uri.decode('utf-8', errors='ignore')
            res_content.append(f"ALERT: Hidden URI found in raw scan: {uri_str}")
                       
    except Exception as e:
        logger.error(f"Internal Error during content analysis: {e}")
        res_content = ["ALERT: Analysis process interrupted during content scan"]


    # -------------------------------------------------------------------------
    # 4. Structure 
    # -------------------------------------------------------------------------
    try:
        file_stream.seek(0)
        res_structure.extend(analyze_structure(reader, file_stream))
    except Exception as e:
        logger.error(f"Internal Error during structure analysis: {e}")
        res_structure.append("ALERT: Analysis process interrupted during structural scan")


    # -------------------------------------------------------------------------
    # 5. Metadata 
    # -------------------------------------------------------------------------
    if reader:
        try:
            res_metadata = analyze_metadata(reader)
        except Exception:
            res_metadata = ["ALERT: Metadata analysis failed"]
    else:
        res_metadata = ["INFO: Metadata analysis skipped (Malformed Structure)"]


    # -------------------------------------------------------------------------
    # 6. Risk Calculation
    # -------------------------------------------------------------------------
    all_findings = sorted(set(res_content + res_structure + res_metadata + res_text))
    score, risk_percentage, level = calculate_risk(all_findings)
    
    return {
        "findings": {
            "content": {"results": sorted(res_content), "count": len(res_content)},
            "structure": {"results": sorted(res_structure), "count": len(res_structure)},
            "metadata": {"results": sorted(res_metadata), "count": len(res_metadata)},
            "text_extraction": {"results": sorted(res_text), "count": len(res_text)}
        },
        "risk_score": score,
        "risk_percentage": risk_percentage,
        "risk_level": level
    }
    