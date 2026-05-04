from flask import Flask, request, jsonify
from io import BytesIO
from pypdf import PdfReader
from pdfminer.high_level import extract_text as pdfminer_extract
import logging, re

from analysis.normalizer import normalize_all
from analysis.text import extract_text
from analysis.content import analyze_content
from analysis.structure import analyze_structure
from analysis.metadata import analyze_metadata
from analysis.risk import calculate_risk

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def deep_binary_scan(file_content):
    extra_findings = []
    patterns = {
        rb"/AA\s*<<\s*/O": "ALERT: Hidden automatic execution trigger (/AA /O) detected in raw stream",
        rb"/S\s*/URI": "ALERT: Direct URI action detected in hidden object",
        rb"/JS\s*\(": "ALERT: Scripting indicator found in malformed object",
        rb"/OpenAction": "ALERT: Automatic execution trigger found in raw data",
        rb"/AA": "ALERT: Event-based execution trigger found in raw data",
        rb"/Launch": "ALERT: Embedded file launch trigger (/Launch) found in raw data",
        rb"/SubmitForm": "ALERT: Form submission trigger (/SubmitForm) found in raw data",
        rb"/GoToE": "ALERT: Remote PDF embedded link (/GoToE) found in raw data",
        rb"/JavaScript": "ALERT: Scripting indicators found in raw binary data (JavaScript)",
        rb"/JS": "ALERT: Scripting indicators found in raw binary data (JavaScript)",
        rb"application/x-formcalc": "ALERT: Scripting indicators found in raw binary data (FormCalc)",
        rb"<?xml-stylesheet": "ALERT: Scripting indicators found in raw binary data (XSLT/XML)",
        rb"/RichMedia": "ALERT: RichMedia object (Potential exploit carrier) found in raw data",
        rb"/Crypt": "ALERT: Custom encryption filter (/Crypt) found in raw data",
        rb"/JBIG2Decode": "ALERT: Suspicious compression filter (/JBIG2Decode) detected"
    }
    
    for pattern, message in patterns.items():
        if re.search(pattern, file_content, re.IGNORECASE):
            extra_findings.append(message)
    return extra_findings


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Malicious PDF Detector API is running", "status": "OK"})

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "" or not file.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Unsupported file type. Please upload a PDF."}), 400

    # -------------------------------------------------------------------------
    # 1. Initialize & Read Raw Data
    # -------------------------------------------------------------------------
    file_content = file.read()
    file_stream = BytesIO(file_content)
    reader = None
    
    res_text, res_content, res_structure, res_metadata = [], [], [], []
    text = ""

    try:
        reader = PdfReader(file_stream, strict=False)
        _ = len(reader.pages) 
        logger.info(f"Successfully initialized pypdf for {file.filename}")
    except Exception as e:
        logger.warning(f"Metadata/Structure parsing failed for {file.filename}: {str(e)}")
        res_structure.append("ALERT: Malformed PDF structure detected (Potential Evasion/Corruption)")
        reader = None

    # -------------------------------------------------------------------------
    # 2. Text Extraction
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
    # 3. Normalization
    # -------------------------------------------------------------------------
    
    clean_text = normalize_all(text)
    
    # -------------------------------------------------------------------------
    # 4. Content
    # -------------------------------------------------------------------------
    try:
        res_content = analyze_content(clean_text)
        
        raw_findings = deep_binary_scan(file_content)
        res_content.extend(raw_findings)

        raw_uris = re.findall(rb'/URI\s*\((.*?)\)', file_content)
        for uri in raw_uris:
            uri_str = uri.decode('utf-8', errors='ignore')
            res_content.append(f"ALERT: Hidden URI found in raw scan: {uri_str}")
                       
    except Exception as e:
        logger.error(f"Internal Error during content analysis: {e}")
        res_content = ["ALERT: Analysis process interrupted during content scan"]

    # -------------------------------------------------------------------------
    # 5. Structure 
    # -------------------------------------------------------------------------
    try:
        file_stream.seek(0)
        res_structure.extend(analyze_structure(reader, file_stream))
    except Exception as e:
        logger.error(f"Internal Error during structure analysis: {e}")
        res_structure.append("ALERT: Analysis process interrupted during structural scan")

    # -------------------------------------------------------------------------
    # 6. Metadata 
    # -------------------------------------------------------------------------
    if reader:
        try:
            res_metadata = analyze_metadata(reader)
        except Exception:
            res_metadata = ["ALERT: Metadata analysis failed"]
    else:
        res_metadata = ["INFO: Metadata analysis skipped (Malformed Structure)"]

    # -------------------------------------------------------------------------
    # 7. Risk Calculation
    # -------------------------------------------------------------------------
    all_findings = sorted(set(res_content + res_structure + res_metadata + res_text))
    score, risk_percentage, level = calculate_risk(all_findings)
    
    return jsonify({
        "filename": file.filename,
        "findings": {
            "content": {"results": sorted(res_content), "count": len(res_content)},
            "structure": {"results": sorted(res_structure), "count": len(res_structure)},
            "metadata": {"results": sorted(res_metadata), "count": len(res_metadata)},
            "text_extraction": {"results": sorted(res_text), "count": len(res_text)}
        },
        "risk_score": score,
        "risk_percentage": risk_percentage,
        "risk_level": level
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)