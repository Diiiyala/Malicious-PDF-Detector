# Malicious PDF Detector Frontend

A bilingual React interface for uploading PDFs and viewing risk scores, categorized findings, and extracted scripts. 

Supports English, Arabic, RTL layouts, and PNG results export.

## Tech Stack

React 19, Vite, Tailwind CSS, `react-dropzone`, and `html-to-image`.

## Setup

Requires Node.js 18+ and npm.

```bash
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite, usually http://localhost:5173.

The backend must be running at `http://localhost:5000`. The upload endpoint is configured in `src/App.jsx`; update it before deployment.

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the development server |
| `npm run build` | Build to `dist/` |
| `npm run preview` | Preview the production build |
| `npm run lint` | Run ESLint |

See the [project README](../README.md) for features and API documentation.
