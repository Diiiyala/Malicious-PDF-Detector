from flask import Flask, request, jsonify
from io import BytesIO
from pypdf import PdfReader
import logging

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
        except Exception:
            text = file_content.decode('utf-8', errors='ignore')
            res_text = ["ALERT: Analysis process interrupted during text extraction"]
    else:
        text = file_content.decode('utf-8', errors='ignore')
        res_text = ["INFO: Deep text extraction skipped due to malformed PDF structure"]

    # -------------------------------------------------------------------------
    # 3. Normalization
    # -------------------------------------------------------------------------
    
    clean_text = normalize_all(text)
    
    # -------------------------------------------------------------------------
    # 4. Content
    # -------------------------------------------------------------------------
    try:
        res_content = analyze_content(clean_text)
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