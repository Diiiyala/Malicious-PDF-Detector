from flask import Flask, request, jsonify
from io import BytesIO
from pypdf import PdfReader
import logging, pikepdf

from analysis.core.analyzer import analyze_all_aspects

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
    # Initialize & Read Raw Data
    # -------------------------------------------------------------------------
    try:
        file_content = file.read()
        file_stream = BytesIO(file_content)
        
        reader = None
        initial_structure_findings = []

        try:
            reader = PdfReader(file_stream, strict=False)
            _ = len(reader.pages) 
        
        except Exception as e:
            logger.warning(f"Metadata/Structure parsing failed for {file.filename}: {str(e)}")
            try:
                with pikepdf.open(BytesIO(file_content)) as pdf:
                    repaired_stream = BytesIO()
                    pdf.save(repaired_stream)
                    repaired_data = repaired_stream.getvalue()
                    file_stream = BytesIO(repaired_data)
                    file_content = repaired_data
                    reader = PdfReader(file_stream, strict=False)
                    initial_structure_findings.append("ALERT: Malformed structure repaired and analyzed")
                    
            except Exception as repair_e:
                logger.warning(f"Standard repair failed: {repair_e}, attempting manual wrapping...")
                initial_structure_findings.append("ALERT: Malformed PDF structure detected (Potential Evasion/Corruption)")
                        
        analysis_results = analyze_all_aspects(
            reader, 
            file_stream, 
            file_content, 
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