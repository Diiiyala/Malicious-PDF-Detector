# Malicious PDF Detector

A web application that statically analyzes PDF files for potentially malicious content and suspicious behavior. Upload a PDF to view its risk score, categorized findings, and extracted scripts through a bilingual (English / Arabic) React interface powered by a Python/Flask analysis engine.

The detector checks for embedded JavaScript, automatic actions, suspicious links, embedded executables, structural evasion techniques, hidden text, anomalous metadata, and hidden execution indicators. Files are never opened or executed; all analysis is static.

![Malicious PDF Detector interface](Frontend.jpg)

## Key Features

* **Drag-and-drop uploads**: Upload a PDF (up to 100 MB) directly from your browser.
* **Five analysis modules**: Inspect text, content, document structure, metadata, and raw bytes.
* **Obfuscation detection**: Identify hex-escaped PDF names, octal/hex-encoded URIs, duplicate dictionary keys (parser confusion), Base64 layers, and string-concatenation or charcode tricks.
* **Parsing recovery**: Attempt to repair malformed PDFs with `pikepdf` and inspect the decompressed streams.
* **Decompression-bomb protection**: Streams that exceed memory limits are flagged instead of crashing the service.
* **Consolidated findings**: Merge duplicate indicators while preserving matched values and locations.
* **Risk assessment**: Display a weighted score, risk level, and status.
* **Script inspection**: Review extracted and de-obfuscated script content (JavaScript, XFA/FormCalc, XML/XXE, decoded Base64 payloads) alongside the findings, with one-click copy.
* **Bilingual UI**: English and Arabic, including right-to-left layout.
* **Report export**: Save or share the scan result as an A4 PDF report, and copy the file's SHA-256 (computed in the browser).

## Tech Stack

| Layer          | Technologies                                        |
| -------------- | --------------------------------------------------- |
| Backend        | Python, Flask, Flask-Cors, Waitress                 |
| PDF processing | `pypdf`, `pikepdf`, `pdfminer.six`                  |
| Frontend       | React 19, Vite, Tailwind CSS 3                      |
| UI utilities   | `react-dropzone`, `html-to-image`                   |

## How It Works

1. **Upload**: The frontend sends the PDF to the Flask backend (`POST /upload`).
2. **Parse and recover**: `load_pdf` parses the file with `pypdf`. If parsing fails, it attempts a repair pass with `pikepdf`, appends the decompressed stream content (capped at 200 MB) to the bytes that are scanned, and records a finding that the structure was malformed.
3. **Extract and normalize**: Text, metadata, and `/URI` strings are extracted. Text comes from `pypdf` (with `pdfminer.six` as a fallback), and is then normalized to reveal obfuscated content (PDF `#xx` name escapes, `\uXXXX`/`\xXX`/octal escapes, string concatenation, `atob()`, Base64 layers, and similar).
4. **Analyze**: Five detector modules inspect the parsed document, extracted content, and raw bytes. They run one after another, and a failure in one detector is logged without stopping the others.
5. **Consolidate and score**: Duplicate findings are merged (locations and matched values are combined and capped), redundant URI findings already covered by stronger ones are absorbed, and a weighted risk score is calculated.
6. **Display results**: The frontend presents the risk assessment, categorized findings, extracted scripts, and file details.

### Detection Modules

| Module        | What it checks                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Text**      | Hidden text (tiny or zero-scale fonts, text placed far off the page) and pages whose tree is malformed so that text extraction was skipped.                                                                                                                                                                                                                                                                                                                |
| **Content**   | Execution patterns (`eval()`, `exec()`, `String.fromCharCode`, `app.launchURL`, `app.openDoc`, `new WebSocket()`, `<script>`), logic obfuscation, suspicious links (shorteners, direct IPs, UNC paths, malicious query parameters), ransomware and stealer indicators, registry tampering, security-disabling commands, XXE and XFA/SOAP payloads, environment leaks, cryptocurrency addresses, the EICAR test string, recursive Base64 decoding, high-entropy content, and multi-signal correlations (for example NTLM relay and multi-stage payloads). |
| **Structure** | Header anomalies (missing, offset, or multiple `%PDF-` headers), catalog entries (Optional Content Groups coupled with scripts or triggers, PDF 2.0 `/AF` associated files), `/OpenAction`, document and page `/AA` triggers, the `/Names` tree (JavaScript and embedded files, with executable-extension, macro, and magic-byte classification of attachments), annotation and form actions (`/Launch`, `/GoToR`, `/GoToE`, `/SubmitForm`, `/ImportData`, `/URI`), clickjacking overlays and transparent widget grids, stored XSS in annotations, streams and objects (metadata XML, font-matrix injection, injected PostScript Type 4 functions, suspicious filters such as `/JBIG2Decode` and `/Crypt`, remote resource references, decompression bombs), encryption, hex-escaped names, and duplicate dictionary keys. |
| **Metadata**  | Suspicious authoring tools or sources, hacking-tool references, XSS attempts and oversized fields, links inside metadata, and implausible or potentially tampered timestamps.                                                                                                                                                                                                                                                                              |
| **Binary**    | Launch, open, and silent-execution strings, raw `/JS`, `/JavaScript`, `/SubmitForm`, `/RichMedia`, `/Crypt`, and `/JBIG2Decode` markers, XFA/XXE/XSS patterns, obfuscated or hex-encoded `/URI` values, and suspicious `/F` paths that may not appear through normal object parsing.                                                                                                                                                                      |

### Risk Scoring

Findings are deduplicated before scoring. Every finding has a severity from `1` to `15`. Each finding ID contributes at most three times to the score, so a repeated indicator cannot inflate the result without limit.

The assessment includes:

| Field             | Output                                                            |
| ----------------- | ----------------------------------------------------------------- |
| `risk_score`      | Sum of the severities of the scored findings                      |
| `risk_percentage` | Score capped to a `0` to `100` scale                              |
| `risk_level`      | `LOW RISK`, `MEDIUM RISK`, or `HIGH RISK`                         |
| `status`          | `safe`, `warning`, or `danger`                                    |

Thresholds:

| Condition                                                                    | Result                          |
| ---------------------------------------------------------------------------- | ------------------------------- |
| `risk_percentage` is `70` or more, or any finding has severity `12` or more  | `HIGH RISK` (`danger`)          |
| `risk_percentage` is `30` to `69`                                            | `MEDIUM RISK` (`warning`)       |
| Otherwise                                                                    | `LOW RISK`                      |
| Highest severity is `5` or less and `risk_percentage` is below `30`          | `safe`; otherwise `warning`     |

## Project Structure

| Path                                                 | Purpose                                                                          |
| ---------------------------------------------------- | -------------------------------------------------------------------------------- |
| `backend/app.py`                                     | Flask app, `/` and `/upload` endpoints, CORS, size limit, memory guard, Waitress |
| `backend/requirements.txt`                           | Python dependencies                                                              |
| `backend/analysis/signatures.py`                     | Shared keywords, severities, and regex patterns                                  |
| `backend/analysis/core/loader.py`                    | PDF parsing, `pikepdf` repair, and decompression-bomb handling                   |
| `backend/analysis/core/extractor.py`                 | Text, metadata, and URI extraction                                               |
| `backend/analysis/core/analyzer.py`                  | Analysis pipeline, deduplication, consolidation, and output assembly             |
| `backend/analysis/core/risk.py`                      | Risk score, level, and status calculation                                        |
| `backend/analysis/detectors/text.py`                 | Hidden-text and text-extraction anomalies                                        |
| `backend/analysis/detectors/content.py`              | Pattern, obfuscation, Base64, entropy, and correlation checks                    |
| `backend/analysis/detectors/metadata.py`             | Metadata and timestamp checks                                                    |
| `backend/analysis/detectors/binary.py`               | Raw-byte pattern, URI, and path checks                                           |
| `backend/analysis/detectors/structure/`              | Header, catalog, names, actions, streams, and evasion checks                     |
| `backend/analysis/utils/`                            | Normalizer, script aggregator, link analysis, text extraction, and models        |
| `frontend/src/App.jsx`                               | Upload flow, results view, risk gauge, report export, and info sections          |
| `frontend/src/LightHome.jsx`, `lightHome.css`        | Landing hero, upload dropzone, and animated illustration                         |
| `frontend/src/main.jsx`, `index.css`                 | React entry point and global styles                                              |
| `frontend/tailwind.config.js`                        | Design tokens and Tailwind configuration                                         |

## Getting Started

### Prerequisites

* Python 3.10+
* Node.js 18+ and npm

### 1. Start the Backend

Create a virtual environment:

```bash
cd backend
python3 -m venv venv
```

Activate it on macOS or Linux:

```bash
source venv/bin/activate
```

Or on Windows Command Prompt:

```bat
venv\Scripts\activate
```

Install dependencies and start the API:

```bash
pip install -r requirements.txt
python app.py
```

The API runs at http://localhost:5000. It is served with Waitress when installed and falls back to Flask's development server otherwise. It listens on all network interfaces (`0.0.0.0`), so restrict access with a firewall if the machine is not private.

### 2. Start the Frontend

Open a separate terminal from the project root:

```bash
cd frontend
npm install
npm run dev
```

Open the URL shown by Vite (usually http://localhost:5173).

Keep both servers running.

The frontend sends analysis requests to `http://localhost:5000/upload`. This address is hard-coded in `frontend/src/App.jsx`; update it before deploying.

## API Reference

### `GET /`

Returns the API health status.

**Example response**

```json
{
  "message": "Malicious PDF Detector API is running",
  "status": "OK"
}
```

### `POST /upload`

Uploads a PDF for analysis using `multipart/form-data`.

| Parameter | Type | Required | Description                |
| --------- | ---- | -------- | -------------------------- |
| `file`    | File | Yes      | The `.pdf` file to analyze |

**Size limits**

* Maximum upload size: **100 MB**
* Repaired or decompressed content analyzed: up to **200 MB**

**Example request**

```bash
curl -X POST http://localhost:5000/upload \
  -F "file=@example.pdf"
```

**Example response**

```json
{
  "filename": "example.pdf",
  "risk_score": 0,
  "risk_percentage": 0,
  "risk_level": "LOW RISK",
  "status": "safe",
  "findings": {
    "content": { "results": [], "count": 0 },
    "structure": { "results": [], "count": 0 },
    "metadata": { "results": [], "count": 0 },
    "text_extraction": { "results": [], "count": 0 },
    "binary": { "results": [], "count": 0 },
    "not_specified": { "results": [], "count": 0 }
  },
  "extracted_scripts": []
}
```

Each entry in a category's `results` array is a formatted string:

```text
[Severity: X/15] <description> | Location: <location>
```

## Limitations

This application uses heuristic detection to identify suspicious indicators.

A low-risk result does not guarantee that a PDF is safe, and a flagged finding does not confirm malicious intent.

Use the results alongside sandbox analysis, antivirus or EDR scanning, and your organization's security procedures when handling untrusted PDFs.

## License

Copyright © 2026 Diyala Alturki. All rights reserved.

Use, copying, modification, and distribution require prior written
permission. See [LICENSE](LICENSE) for details.
