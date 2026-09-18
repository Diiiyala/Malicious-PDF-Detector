import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from analysis.core.analyzer import analyze_all_aspects
from analysis.core.loader import load_pdf

MAX_UPLOAD_MB = 100

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(_e):
    return jsonify({"error": f"File too large, maximum size is {MAX_UPLOAD_MB} MB."}), 413

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
        raw_file_content = file.read()

        reader, file_stream, current_content_to_analyze, initial_structure_findings = load_pdf(
            raw_file_content, filename=file.filename
        )

        # -------------------------------------------------------------------------
        # Security Analysis Pipeline Execution
        # -------------------------------------------------------------------------
        analysis_results = analyze_all_aspects(
            reader,
            file_stream,
            current_content_to_analyze,
            filename=file.filename,
            initial_structure_findings=initial_structure_findings
        )

        analysis_results["filename"] = file.filename
        return jsonify(analysis_results)

    except Exception as e:
        logger.error(f"Fatal error during processing {file.filename}: {e}")
        return jsonify({"error": "An internal error occurred during analysis"}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
