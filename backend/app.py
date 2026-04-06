from flask import Flask, request, jsonify
import PyPDF2

app = Flask(__name__)

def analyze_pdf(file):
    reader = PyPDF2.PdfReader(file)
    text = ""

    for page in reader.pages:
        text += page.extract_text() or ""

    findings = []

    if "/JavaScript" in text:
        findings.append("JavaScript detected")

    if "/OpenAction" in text:
        findings.append("Auto action detected")

    if "http://" in text or "https://" in text:
        findings.append("Contains links")

    if not findings:
        findings.append("No obvious threats detected")

    return findings

@app.route("/")
def home():
    return "API is running"

@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]

    results = analyze_pdf(file)

    return jsonify({
        "results": results
    })

if __name__ == "__main__":
    app.run(debug=True)
