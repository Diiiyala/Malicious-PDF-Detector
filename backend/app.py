from flask import Flask, request, jsonify
from io import BytesIO
from pypdf import PdfReader
import logging

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

    try:
        file_content = file.read()
        file_stream = BytesIO(file_content)
        reader = PdfReader(file_stream, strict=False)
    except Exception:
        logger.exception(f"PDF Initialization error for file: {file.filename}")
        return jsonify({"error": "The provided PDF file is corrupt or invalid."}), 400

    res_visual, res_content, res_structure, res_metadata = [], [], [], []
    text = ""

    try:
        text, res_visual = extract_text(reader)
    except Exception:
        logger.error("Internal Error during text extraction", exc_info=True)
        res_visual = ["ALERT: Analysis process interrupted during visual scan"]

    try:
        res_content = analyze_content(text)
    except Exception:
        logger.error("Internal Error during content analysis", exc_info=True)
        res_content = ["ALERT: Analysis process interrupted during content scan"]

    try:
        file_stream.seek(0)
        res_structure = analyze_structure(reader, file_stream)
    except Exception:
        logger.error("Internal Error during structure analysis", exc_info=True)
        res_structure = ["ALERT: Analysis process interrupted during structural scan"]

    try:
        res_metadata = analyze_metadata(reader)
    except Exception:
        logger.error("Internal Error during metadata analysis", exc_info=True)
        res_metadata = ["ALERT: Analysis process interrupted during metadata scan"]

    all_findings = sorted(set(res_content + res_structure + res_metadata + res_visual))
    score, risk_percentage, level = calculate_risk(all_findings)
    
    return jsonify({
        "filename": file.filename,
        "findings": {
            "content": {"results": sorted(res_content), "count": len(res_content)},
            "structure": {"results": sorted(res_structure), "count": len(res_structure)},
            "metadata": {"results": sorted(res_metadata), "count": len(res_metadata)},
            "visual": {"results": sorted(res_visual), "count": len(res_visual)}
        },
        "risk_score": score,
        "risk_percentage": risk_percentage,
        "risk_level": level
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"})


@app.errorhandler(413)
def request_entity_too_large(_):
    return jsonify({"error": "File is too large. Maximum allowed size is 16MB."}), 413


@app.errorhandler(500)
def internal_error(_):
    return jsonify({"error": "An unexpected internal server error occurred."}), 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)