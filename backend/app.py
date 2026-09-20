import logging, os

try:
    import resource
    HAS_RESOURCE_MODULE = True
except ImportError:
    HAS_RESOURCE_MODULE = False

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from analysis.core.analyzer import analyze_all_aspects
from analysis.core.loader import load_pdf

MAX_UPLOAD_MB = 100
MAX_PROCESS_MEMORY_MB = int(os.environ.get("MAX_PROCESS_MEMORY_MB", 1536))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def apply_memory_guard(limit_mb: int) -> None:

    if not HAS_RESOURCE_MODULE:
        logger.warning("Process memory guard unavailable on this platform (no 'resource' module)")
        return

    try:
        limit_bytes = limit_mb * 1024 * 1024
        _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_hard = hard if (hard != resource.RLIM_INFINITY and hard < limit_bytes) else limit_bytes
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, new_hard))
        logger.info("Process memory guard active: RLIMIT_AS capped at %d MB", limit_mb)
    except (ValueError, OSError) as e:
        logger.warning("Could not apply process memory guard: %s", e)


apply_memory_guard(MAX_PROCESS_MEMORY_MB)

DEFAULT_ORIGINS = ",".join(
    f"http://{host}:{port}"
    for port in range(5173, 5181)
    for host in ("localhost", "127.0.0.1")
)
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", DEFAULT_ORIGINS).split(",")

app = Flask(__name__)
CORS(app, origins=ALLOWED_ORIGINS)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(_e):
    return jsonify({"error": f"File too large, maximum size is {MAX_UPLOAD_MB} MB."}), 413

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

    except MemoryError:
        logger.error("Memory guard tripped analyzing %s (Decompression Bomb)", file.filename)
        return jsonify({"error": "File rejected: exceeded memory limits"}), 422

    except Exception as e:
        logger.error(f"Fatal error during processing {file.filename}: {e}")
        return jsonify({"error": "An internal error occurred during analysis"}), 500

if __name__ == "__main__":

    web_threads = int(os.environ.get("WEB_THREADS", 8))

    try:
        from waitress import serve
        logger.info("Starting with waitress, threads=%d", web_threads)
        serve(app, host="0.0.0.0", port=5000, threads=web_threads)
    except ImportError:
        logger.warning("waitress not installed, falling back to Flask's dev server")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)