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
logging.basicConfig(level=logging.INFO)


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Malicious PDF Detector API is running", "status": "OK"})

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "" or not file.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Invalid file type"}), 400

    try:
        file_content = file.read()
        file_stream = BytesIO(file_content)
        reader = PdfReader(file_stream, strict=False)
    except Exception as e:
        logging.exception("Failed to initialize PDF Reader")
        return jsonify({"error": f"Invalid PDF format: {str(e)}"}), 400

    res_visual, res_content, res_structure, res_metadata = [], [], [], []
    text = ""

    try:
        text, res_visual = extract_text(reader)
    except Exception as e:
        logging.error(f"Text/Visual analysis failed: {e}")
        res_visual = [f"ERROR: Visual analysis failed ({type(e).__name__})"]

    try:
        res_content = analyze_content(text)
    except Exception as e:
        logging.error(f"Content analysis failed: {e}")
        res_content = [f"ERROR: Content analysis failed ({type(e).__name__})"]

    try:
        file_stream.seek(0)
        res_structure = analyze_structure(reader, file_stream)
    except Exception as e:
        logging.error(f"Structure analysis failed: {e}")
        res_structure = [f"ERROR: Structure analysis failed ({type(e).__name__})"]

    try:
        res_metadata = analyze_metadata(reader)
    except Exception as e:
        logging.error(f"Metadata analysis failed: {e}")
        res_metadata = [f"ERROR: Metadata analysis failed ({type(e).__name__})"]

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

if __name__ == "__main__":
    app.run(debug=False)