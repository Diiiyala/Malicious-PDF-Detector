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
        logging.exception("Invalid PDF file")
        return jsonify({"Error": f"Invalid PDF file: {str(e)}"}), 400

    text, res_visual = extract_text(reader)
    file_stream.seek(0)
    
    res_content = sorted(set(analyze_content(text)))
    res_structure = sorted(set(analyze_structure(reader, file_stream)))
    res_metadata = sorted(set(analyze_metadata(reader)))
    
    all_findings = sorted(set(res_content + res_structure + res_metadata + res_visual))
    
    score, risk_percentage, level = calculate_risk(all_findings)
    
    return jsonify({
        "filename": file.filename,
        "findings": {
            "content": {"results": res_content, "count": len(res_content)},
            "structure": {"results": res_structure, "count": len(res_structure)},
            "metadata": {"results": res_metadata, "count": len(res_metadata)},
            "visual": {"results": res_visual, "count": len(res_visual)}
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