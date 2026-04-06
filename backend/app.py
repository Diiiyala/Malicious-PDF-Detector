from flask import Flask, request, jsonify
import logging
from analysis.text import extract_text
from analysis.content import analyze_content
from analysis.structure import analyze_structure
from analysis.metadata import analyze_metadata
from analysis.risk import calculate_risk

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Malicious PDF Detector API is running", "status": "OK"})

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not file.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Only PDF files allowed"}), 400

    logging.info(f"Analyzing file: {file.filename}")

    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(file)
    except Exception as e:
        return jsonify({"error": f"Invalid PDF file: {str(e)}"}), 400

    text = extract_text(reader)
    findings = []
    findings += analyze_content(text)
    findings += analyze_structure(reader)
    findings += analyze_metadata(reader)
    findings = sorted(list(set(findings)))

    from analysis.risk import calculate_risk
    score, risk_percentage, level = calculate_risk(findings, reader)

    return jsonify({
        "filename": file.filename,
        "findings": findings,
        "risk_score": score,
        "risk_percentage": risk_percentage,
        "risk_level": level
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"})

if __name__ == "__main__":
    app.run(debug=True)