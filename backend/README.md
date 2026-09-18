# Malicious PDF Detector Backend

A Flask API that performs static PDF analysis and returns risk scores, categorized findings, and extracted scripts.

## Tech Stack

Python, Flask, Flask-Cors, `pypdf`, `pikepdf`, and `pdfminer.six`.

## Setup

Requires Python 3.10+.

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

On Windows Command Prompt, activate with `venv\Scripts\activate`.

The API runs at http://localhost:5000.

## Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/` | Health check |
| POST | `/upload` | Analyze a PDF sent in the `file` field |

```bash
curl -X POST http://localhost:5000/upload -F "file=@sample.pdf"
```

## Notes

- Upload request limit: **100 MB**.
- Recovered stream content limit: **200 MB**.
- Results are heuristic and do not guarantee that a PDF is safe.

See the [project README](../README.md) for the analysis pipeline and response format.
