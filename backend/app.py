import logging, pikepdf
from flask import Flask, request, jsonify
from flask_cors import CORS
from io import BytesIO
from pypdf import PdfReader
from werkzeug.exceptions import RequestEntityTooLarge

from analysis.core.analyzer import analyze_all_aspects

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

    # -------------------------------------------------------------------------
    # Initial Structure Validation
    # -------------------------------------------------------------------------
    try:
        raw_file_content = file.read()
        file_stream = BytesIO(raw_file_content)
        
        reader = None
        initial_structure_findings = []
        
        current_content_to_analyze = raw_file_content

        # -------------------------------------------------------------------------
        #  Fallback Recovery (Malformed / Obfuscated PDF Repair Attempt)
        # -------------------------------------------------------------------------
        try:
            reader = PdfReader(file_stream, strict=False)
            _ = len(reader.pages)
            
        except Exception as e:
            logger.warning(f"Metadata/Structure parsing failed for {file.filename}: {str(e)}")
            
            try:
                with pikepdf.open(BytesIO(raw_file_content)) as pdf:
                    all_extracted_content = bytearray(raw_file_content)

                    for obj in pdf.objects:
                        if isinstance(obj, pikepdf.Stream):
                            try:
                                all_extracted_content.extend(obj.read_bytes())
                            except Exception as e:
                                logger.debug("Could not read stream object during repair: %s", e)
                                continue
                    
                    repaired_stream = BytesIO()
                    pdf.save(repaired_stream, static_id=True)
                    
                    current_content_to_analyze = bytes(all_extracted_content)
                    
                    file_stream = BytesIO(repaired_stream.getvalue())
                    reader = PdfReader(file_stream, strict=False)
                    
                    try:
                        _ = len(reader.pages)
                    except Exception as e:
                        logger.debug("Repaired PDF still unreadable: %s", e)
                        reader = None
                        
                    initial_structure_findings.append("ALERT: Malformed structure repaired and analyzed")
                    
            except Exception as repair_e:
                logger.error(f"Deep repair failed: {repair_e}")
                initial_structure_findings.append("ALERT: Malformed PDF structure detected (Potential Evasion/Corruption)")
                
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