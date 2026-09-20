import { useState, useCallback, useEffect, useRef } from 'react';
import LightHome from './LightHome.jsx';


const Icon = {
  shield: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 3v5c0 4.5-3 8.5-7 9.5C8 19.5 5 15.5 5 11V6l7-3z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12l1.8 1.8L15 10" />
    </svg>
  ),
  globe: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <circle cx="12" cy="12" r="9" />
      <path strokeLinecap="round" d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18" />
    </svg>
  ),
  upload: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 16V4m0 0L8 8m4-4l4 4" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" />
    </svg>
  ),
  arrowDown: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 5v14m0 0l-6-6m6 6l6-6" />
    </svg>
  ),
  close: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  ),
  alert: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
    </svg>
  ),
  check: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  ),
  shieldCheck: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l8 3.5V11c0 5-3.4 9.4-8 10.5C7.4 20.4 4 16 4 11V6.5L12 3z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4" />
    </svg>
  ),
  code: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16M18 8l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
  ),
  copy: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path strokeLinecap="round" d="M5 15V5a2 2 0 012-2h10" />
    </svg>
  ),
  share: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 16V4m0 0L8 8m4-4l4 4" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 14v4a2 2 0 002 2h12a2 2 0 002-2v-4" />
    </svg>
  ),
  scanFrame: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 8V6a2 2 0 012-2h2M16 4h2a2 2 0 012 2v2M20 16v2a2 2 0 01-2 2h-2M8 20H6a2 2 0 01-2-2v-2M3 12h18" />
    </svg>
  ),
  scan: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 7V5a1 1 0 011-1h2M20 7V5a1 1 0 00-1-1h-2M4 17v2a1 1 0 001 1h2M20 17v2a1 1 0 01-1 1h-2M3 12h18" />
    </svg>
  ),
  bolt: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" />
    </svg>
  ),
  layers: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l9 5-9 5-9-5 9-5z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l9 5 9-5M3 16l9 5 9-5" />
    </svg>
  ),
  github: (p) => (
    <svg viewBox="0 0 24 24" fill="currentColor" {...p}>
      <path d="M12 .5C5.73.5.5 5.74.5 12.02c0 5.08 3.29 9.39 7.86 10.91.58.1.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 015.79 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.8 1.19 1.83 1.19 3.09 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.05.78 2.12 0 1.53-.01 2.76-.01 3.14 0 .31.21.67.8.56A11.52 11.52 0 0023.5 12.02C23.5 5.74 18.27.5 12 .5z" />
    </svg>
  ),
  mail: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}>
      <rect x="3" y="5" width="18" height="14" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 7l9 6 9-6" />
    </svg>
  ),
  linkedin: (p) => (
    <svg viewBox="0 0 24 24" fill="currentColor" {...p}>
      <path d="M20.45 20.45h-3.55v-5.57c0-1.33-.02-3.03-1.85-3.03-1.86 0-2.14 1.45-2.14 2.94v5.66H9.36V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.06 2.06 0 110-4.12 2.06 2.06 0 010 4.12zM7.12 20.45H3.56V9h3.56v11.45z" />
    </svg>
  ),
};


const truncateAtWord = (value, limit) => {
  const slice = value.slice(0, limit);
  const lastSpace = slice.lastIndexOf(' ');
  return `${lastSpace > limit * 0.6 ? slice.slice(0, lastSpace) : slice}...`;
};

const ExpandableText = ({ text, maxLength = 150, isAr, forceExpand = false }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  if (!text || text.length <= maxLength) return <span>{text}</span>;
  const expanded = isExpanded || forceExpand;
  return (
    <div className="inline-block">
      <span className="break-words whitespace-pre-wrap">
        {expanded ? text : truncateAtWord(text, maxLength)}
      </span>
      {!forceExpand && (
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="inline-flex items-center text-brand-ink hover:text-brand font-bold transition-colors text-sm mx-2"
        >
          {isExpanded ? (isAr ? 'عرض أقل' : 'Show Less') : (isAr ? 'قراءة المزيد' : 'Read More')}
        </button>
      )}
    </div>
  );
};


const RiskGauge = ({ score = 0, tone = 'danger' }) => {
  const R = 52;
  const C = 2 * Math.PI * R;
  const pct = Math.min(100, Math.max(0, score));
  const offset = C - (pct / 100) * C;
  const colors = {
    safe: '#22A466',
    warn: '#E3A600',
    danger: '#D33A3A',
  };
  const stroke = colors[tone] || colors.danger;
  return (
    <div className="relative w-28 h-28 shrink-0" dir="ltr">
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
        <circle cx="60" cy="60" r={R} fill="none" stroke="#EDEDED" strokeWidth="10" />
        <circle
          cx="60" cy="60" r={R} fill="none" stroke={stroke} strokeWidth="10"
          strokeLinecap="round" strokeDasharray={C} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.16,1,0.3,1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-display font-bold" style={{ color: tone === 'safe' ? '#136B41' : tone === 'warn' ? '#7F5A00' : '#B92626' }}>{pct}%</span>
      </div>
    </div>
  );
};


const DETECTORS = [
  { k: 'text', icon: 'file', en: 'Text', ar: 'النص', enD: 'Anomalies in the extracted text layer', arD: 'شذوذ في طبقة النص المستخرجة',
    checks: [{ tok: 'hidden text', sev: 'medium', en: 'Hidden text layer', ar: 'طبقة نص مخفية' }] },
  { k: 'content', icon: 'code', en: 'Content', ar: 'المحتوى', enD: 'Suspicious code, keywords and URLs', arD: 'شيفرة وكلمات وروابط مشبوهة',
    checks: [
      { tok: 'short link', sev: 'medium', en: 'Shortened link', ar: 'رابط مختصر' },
      { tok: 'eval()', sev: 'high', en: 'Obfuscated code', ar: 'شيفرة مموّهة' },
      { tok: 'cmd.exe', sev: 'critical', en: 'System command strings', ar: 'نصوص أوامر النظام' },
    ] },
  { k: 'structure', icon: 'layers', en: 'Structure', ar: 'الهيكل', enD: 'Catalog, actions, streams and names', arD: 'الفهرس والإجراءات والتدفقات والأسماء',
    checks: [
      { tok: '/JavaScript', sev: 'high', en: 'Embedded JavaScript', ar: 'جافاسكريبت مضمَّن' },
      { tok: '/OpenAction', sev: 'high', en: 'Runs automatically on open', ar: 'تشغيل تلقائي عند الفتح' },
      { tok: '/AA', sev: 'medium', en: 'Additional actions', ar: 'إجراءات إضافية' },
      { tok: '/URI', sev: 'low', en: 'External link', ar: 'رابط خارجي' },
      { tok: '/SubmitForm', sev: 'high', en: 'Form submission', ar: 'إرسال نموذج' },
      { tok: '/GoToR', sev: 'medium', en: 'Reaches an outside file', ar: 'يستدعي ملفًا خارجيًا' },
      { tok: '/EmbeddedFile', sev: 'medium', en: 'Embedded file', ar: 'ملف مضمَّن' },
      { tok: '/RichMedia', sev: 'medium', en: 'Rich media content', ar: 'وسائط غنية' },
      { tok: '/XFA', sev: 'medium', en: 'XFA form', ar: 'نموذج XFA' },
      { tok: '#xx', sev: 'medium', en: 'Hex-escaped names', ar: 'أسماء مشفّرة بالست عشري' },
      { tok: '%PDF / %%EOF', sev: 'low', en: 'Malformed structure', ar: 'بنية غير سليمة' },
    ] },
  { k: 'metadata', icon: 'tag', en: 'Metadata', ar: 'البيانات الوصفية', enD: 'Authoring tool and timestamps', arD: 'أداة الإنشاء والطوابع الزمنية',
    checks: [
      { tok: '/Producer', sev: 'high', en: 'Suspicious producer', ar: 'أداة إنشاء مشبوهة' },
      { tok: '/CreationDate', sev: 'low', en: 'Implausible timestamp', ar: 'طابع زمني غير منطقي' },
    ] },
  { k: 'binary', icon: 'cpu', en: 'Binary', ar: 'المحتوى الثنائي', enD: 'Raw launch and execute strings', arD: 'نصوص التشغيل والتنفيذ الخام',
    checks: [{ tok: '/Launch', sev: 'critical', en: 'Launch action', ar: 'إجراء تشغيل برنامج' }] },
];

const DET_ICONS = {
  file: ['M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z', 'M14 3v5h5'],
  code: ['M10 20l4-16M18 8l4 4-4 4M6 16l-4-4 4-4'],
  layers: ['M12 3l9 5-9 5-9-5 9-5z', 'M3 12l9 5 9-5M3 16l9 5 9-5'],
  tag: ['M20 12l-8 8-9-9V4h7l10 8z', 'M7.5 7.5h.01'],
  cpu: ['M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3'],
};

const DetIcon = ({ n, className }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
    {n === 'cpu' && <rect x="6" y="6" width="12" height="12" rx="2" />}
    {DET_ICONS[n].map((d) => <path key={d} d={d} />)}
  </svg>
);

const DET_COLORS = { text: '#12B5A6', content: '#F5A524', structure: '#5271FF', metadata: '#7C5CF0', binary: '#EF4B5B' };
const SEV_DOT = { critical: 'bg-danger-dot', high: 'bg-orange-dot', medium: 'bg-warn-dot', low: 'bg-info-dot' };

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

const TERMINAL_TEXT = {
  secure:   { en: 'Establishing secure connection...', ar: 'جاري إنشاء اتصال آمن مع الخادم...' },
  upload:   { en: 'Uploading file to analysis engine...', ar: 'جاري رفع الملف لمحرك الفحص...' },
  analyze:  { en: 'Analyzing structure and metadata...', ar: 'جاري تحليل الهيكل والبيانات الوصفية...' },
  complete: { en: 'Scan complete. Displaying report...', ar: 'اكتمل الفحص. جاري عرض التقرير...' },
  err_too_large:  { en: 'File too large, maximum size is 100 MB.', ar: 'الملف كبير جدًا، الحد الأقصى 100 ميجابايت.' },
  err_server:     { en: 'Scan failed on the server.', ar: 'فشل الفحص على الخادم.' },
  err_connection: { en: 'Connection failed! Ensure Flask is running.', ar: 'فشل الاتصال! تأكد من تشغيل خادم Flask.' },
};

const CATEGORY_TEXT = {
  content:         { en: 'CONTENT',         ar: 'المحتوى' },
  structure:       { en: 'STRUCTURE',       ar: 'البنية' },
  metadata:        { en: 'METADATA',        ar: 'البيانات الوصفية' },
  text_extraction: { en: 'TEXT EXTRACTION', ar: 'استخراج النص' },
  binary:          { en: 'BINARY',          ar: 'المحتوى الثنائي' },
  not_specified:   { en: 'NOT SPECIFIED',   ar: 'غير محدد' },
};

const fmtSize = (n) => {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
};

const sha256Hex = async (file) => {
  const buf = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
};

const DET_CATEGORY = { text: 'text_extraction', content: 'content', structure: 'structure', metadata: 'metadata', binary: 'binary' };

const categoryLabel = (key, isAr) =>
  (CATEGORY_TEXT[key] || {})[isAr ? 'ar' : 'en'] || String(key || '').replace(/_/g, ' ').toUpperCase();

function App() {
  const [lang, setLang] = useState('en');
  const isAr = lang === 'ar';
  const [appState, setAppState] = useState('upload');
  const [terminalLines, setTerminalLines] = useState([]);
  const [uploadError, setUploadError] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isLoaded, setIsLoaded] = useState(false);
  const [langFading, setLangFading] = useState(false);
  const [openDet, setOpenDet] = useState('structure');
  const [scanStep, setScanStep] = useState(0);
  const [resultTab, setResultTab] = useState('findings');
  const [copiedSha, setCopiedSha] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState(null);
  const [fileName, setFileName] = useState('');
  const [sharing, setSharing] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [scanFailed, setScanFailed] = useState(false);
  const resultRef = useRef(null);

  useEffect(() => {
    setTimeout(() => setIsLoaded(true), 100);
  }, []);

  useEffect(() => {
    if (appState !== 'scanning' || scanFailed) return undefined;
    const interval = setInterval(() => setScanStep((prev) => Math.min(prev + 1, 4)), 700);
    return () => clearInterval(interval);
  }, [appState, scanFailed]);

  const processFile = async (file) => {
    setAppState('scanning');
    setScanStep(0);
    setTerminalLines([]);
    setFileName(file.name);
    setScanFailed(false);
    let fileSha = null;
    sha256Hex(file).then((h) => { fileSha = h; }).catch(() => { /* hashing unavailable */ });

    const lines = ['secure', 'upload', 'analyze'];

    const progressTimers = lines.map((code, index) =>
      setTimeout(() => setTerminalLines(prev => [...prev, code]), index * 800)
    );

    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch("http://localhost:5000/upload", { method: "POST", body: formData });
      if (!response.ok) {
        let serverMsg = "";
        try { serverMsg = (await response.json())?.error || ""; } catch { /* no JSON body */ }
        const err = new Error(serverMsg || "Scan failed on server");
        err.serverReached = true;
        err.tooLarge = response.status === 413;
        throw err;
      }
      const data = await response.json();

      setTimeout(() => {
        setTerminalLines(prev => [...prev, 'complete']);
      }, lines.length * 800);

      let parsedThreats = [];
      let threatId = 1;
      if (data.findings) {
        Object.keys(data.findings).forEach(category => {
          const categoryData = data.findings[category];
          if (categoryData.count > 0 && categoryData.results) {
            categoryData.results.forEach(resultString => {
              const match = resultString.match(/\[Severity:\s*(.*?)\]\s*(.*?)\s*\|\s*Location:\s*(.*)/i);
              let riskLevel = "N/A", threatName = resultString, location = "N/A";
              if (match) {
                riskLevel = match[1];
                threatName = match[2].trim();
                location = match[3].trim();
              }
              parsedThreats.push({
                id: threatId++,
                name: threatName,
                categoryKey: category,
                offset: location,
                risk: riskLevel,
              });
            });
          }
        });
      }

      setTimeout(() => {
        const validStatuses = ['safe', 'warning', 'danger'];
        const fileStatus = validStatuses.includes(data.status)
          ? data.status
          : (parsedThreats.length === 0 ? 'safe' : 'warning');

        setScanResult({
          status: fileStatus,
          size: file.size,
          scannedAt: Date.now(),
          sha: fileSha,
          riskLevel: data.risk_level || '',
          overallScore: data.risk_percentage || 0,
          threats: parsedThreats,
          extractedScripts: data.extracted_scripts || [],
        });
        setResultTab('findings');
        setAppState('result');
      }, (lines.length * 800) + 1000);
    } catch (error) {
      progressTimers.forEach(clearTimeout);
      const code = error?.tooLarge ? 'err_too_large'
        : error?.serverReached ? 'err_server'
        : 'err_connection';
      setScanFailed(true);
      setTerminalLines([code]);
      console.error("Upload error:", error);
    }
  };

  const onDrop = useCallback(acceptedFiles => {
    setUploadError(null);
    const file = acceptedFiles[0];
    if (!file) return;

    if (file.size > MAX_UPLOAD_BYTES) {
      setUploadError({ type: 'too_large' });
      return;
    }
    processFile(file);
  }, [isAr]);

  const onDropRejected = useCallback((fileRejections) => {
    setUploadError({ type: 'unsupported', fileName: fileRejections[0].file.name });
  }, []);


  const onHeroFile = (files) => {
    onDrop(files);
    if (files[0] && files[0].size <= MAX_UPLOAD_BYTES) {
      setTimeout(() => document.getElementById('workspace')?.scrollIntoView({ behavior: 'smooth' }), 80);
    }
  };

  const toggleLang = () => {
    if (langFading) return;
    const next = isAr ? 'en' : 'ar';
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) { setLang(next); return; }
    setLangFading(true);
    setTimeout(() => {
      setLang(next);
      requestAnimationFrame(() => requestAnimationFrame(() => setLangFading(false)));
    }, 220);
  };

  const copyCode = (code, idx) => {
    try {
      navigator.clipboard.writeText(code || '');
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 1500);
    } catch { /* ignore */ }
  };

  const nextFrame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

  const shareResult = async () => {
    if (!resultRef.current || sharing) return;
    setSharing(true);

    const node = resultRef.current;
    const parent = node.parentNode;
    const rect = node.getBoundingClientRect();

    const placeholder = node.cloneNode(true);
    parent.insertBefore(placeholder, node);

    const prev = {
      position: node.style.position, left: node.style.left, top: node.style.top,
      width: node.style.width, zIndex: node.style.zIndex, pointerEvents: node.style.pointerEvents,
    };
    node.style.position = 'fixed';
    node.style.top = '0';
    node.style.left = '-100000px';
    node.style.width = `${rect.width}px`;
    node.style.zIndex = '-1';
    node.style.pointerEvents = 'none';

    const scrollers = node.querySelectorAll('.overflow-x-auto, .overflow-y-auto, .overflow-auto');
    scrollers.forEach((el) => { el.style.overflow = 'visible'; el.style.maxHeight = 'none'; });
    const codeBlocks = node.querySelectorAll('pre');
    codeBlocks.forEach((el) => { el.style.whiteSpace = 'pre-wrap'; el.style.wordBreak = 'break-all'; el.style.overflow = 'visible'; });

    setCapturing(true);
    await nextFrame();

    try {
      const { toBlob } = await import('html-to-image');
      const blob = await toBlob(node, {
        pixelRatio: 2,
        backgroundColor: '#FFFFFF',
        cacheBust: true,
        width: node.scrollWidth,
        height: node.scrollHeight,
        style: { overflow: 'visible', position: 'static', left: '0', top: '0', margin: '0' },
      });
      if (!blob) throw new Error('Capture returned no image');

      const safeName = (fileName || 'result').replace(/\.pdf$/i, '');
      const file = new File([blob], `scan-${safeName}.png`, { type: 'image/png' });

      if (navigator.canShare && navigator.canShare({ files: [file] })) {
        await navigator.share({ files: [file] });
      } else {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.name;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (e) {
      if (e?.name !== 'AbortError') console.error('Share failed:', e);
    } finally {
      setCapturing(false);
      await nextFrame();
      node.style.position = prev.position;
      node.style.left = prev.left;
      node.style.top = prev.top;
      node.style.width = prev.width;
      node.style.zIndex = prev.zIndex;
      node.style.pointerEvents = prev.pointerEvents;
      scrollers.forEach((el) => { el.style.overflow = ''; el.style.maxHeight = ''; });
      codeBlocks.forEach((el) => { el.style.whiteSpace = ''; el.style.wordBreak = ''; el.style.overflow = ''; });
      placeholder.remove();
      setSharing(false);
    }
  };

  const tones = {
    safe: { text: 'text-safe', pill: 'bg-safe-bg border-transparent text-safe' },
    warning: { text: 'text-warn', pill: 'bg-warn-bg border-transparent text-warn' },
    danger: { text: 'text-danger', pill: 'bg-danger-bg border-transparent text-danger' },
  };
  const sevPill = (risk, fallback) => {
    const k = String(risk || '').toLowerCase();
    if (k.includes('crit')) return 'bg-danger-bg text-danger';
    if (k.includes('high')) return 'bg-orange-bg text-orange';
    if (k.includes('med')) return 'bg-warn-bg text-warn';
    if (k.includes('low')) return 'bg-info-bg text-info';
    return fallback;
  };


  return (
    <div className={`relative min-h-screen bg-white text-ink font-sans selection:bg-brand selection:text-white overflow-x-hidden transition-[opacity,filter] duration-200 ease-out ${langFading ? 'opacity-0 blur-[3px]' : 'opacity-100'}`} dir={isAr ? 'rtl' : 'ltr'}>

      {/* Light landing: navbar + hero (see LightHome.jsx) */}
      <LightHome
        isAr={isAr}
        isLoaded={isLoaded}
        onToggleLang={toggleLang}
        onFile={onHeroFile}
        onRejected={onDropRejected}
        uploadError={uploadError}
        onDismissError={() => setUploadError(null)}
      />

      {/* Workspace */}
      {appState !== 'upload' && (
      <section id="workspace" className="relative z-10 min-h-screen flex flex-col justify-center items-center px-5 py-24 bg-white">

        {/* Scanning state */}
        {appState === 'scanning' && (() => {
          const allDone = terminalLines.includes('complete');
          const step = allDone ? 5 : Math.min(scanStep, 4);
          const errCode = terminalLines.find((c) => c.startsWith('err_'));
          const LINES = [96, 88, 92, 70, 94, 84, 90, 66, 80, 90, 58];
          const label = (st) => (st === 'done' ? (isAr ? 'اكتمل' : 'Done') : st === 'run' ? (isAr ? 'قيد التشغيل' : 'Running') : (isAr ? 'بالانتظار' : 'Waiting'));
          return (
            <div className="w-full max-w-5xl animate-fade-in">
              <div className="grid md:grid-cols-[minmax(220px,320px)_minmax(0,1fr)] gap-10 md:gap-14 items-center">
                {/* Document preview with scan sweep */}
                <div className="hidden md:block" dir="ltr">
                  <div className="relative aspect-[3/4] overflow-hidden rounded-xl bg-white border border-line shadow-[0_18px_36px_-24px_rgba(20,20,20,0.16)] p-6 flex flex-col gap-3">
                    <div className="h-3 w-1/2 rounded bg-line-2 shrink-0" />
                    {LINES.map((w, i) => <div key={i} className="h-1.5 rounded bg-[#E8E8E8] shrink-0" style={{ width: `${w}%` }} />)}
                    {!scanFailed && !allDone && (
                      <div className="absolute inset-x-0 h-14 -mt-14 border-b-[3px] border-brand animate-scan-beam pointer-events-none" />
                    )}
                  </div>
                </div>

                <div className={isAr ? 'text-right' : 'text-left'}>
                  <h2 className="text-3xl sm:text-4xl font-display font-bold">
                    {scanFailed ? (isAr ? 'فشل الفحص' : 'Scan Failed') : `${isAr ? 'جاري الفحص' : 'Scanning'}…`}
                  </h2>
                  {fileName && (
                    <div className="mt-4 inline-flex items-center gap-2 max-w-full bg-white border border-line rounded-full px-3.5 py-1.5" dir="ltr">
                      <Icon.layers className="w-4 h-4 text-ink-3 shrink-0" />
                      <span className="text-sm text-ink-2 truncate font-mono" title={fileName}>{fileName}</span>
                    </div>
                  )}

                  {scanFailed ? (
                    <div className="mt-6 flex items-start gap-3 rounded-2xl bg-danger-bg text-danger px-4 py-3.5 font-semibold" role="alert">
                      <Icon.alert className="w-5 h-5 shrink-0 mt-0.5" />
                      <span>{(TERMINAL_TEXT[errCode] || {})[isAr ? 'ar' : 'en'] || errCode}</span>
                    </div>
                  ) : (
                    <>
                      <div className="mt-6 h-2 rounded-full bg-white border border-line overflow-hidden" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round((step / 5) * 100)} dir="ltr">
                        <div className="h-full rounded-full bg-brand transition-[width] duration-700 ease-out" style={{ width: `${Math.max(6, (step / 5) * 100)}%` }} />
                      </div>
                      <ul className="mt-6 space-y-3">
                        {DETECTORS.map((d, i) => {
                          const st = i < step ? 'done' : i === step ? 'run' : 'wait';
                          return (
                            <li key={d.k} className="flex items-center gap-4 bg-white border border-line rounded-2xl px-5 py-3.5">
                              <span className={`grid place-items-center w-[26px] h-[26px] rounded-full shrink-0 ${st === 'done' ? 'bg-[#12B5A6] text-white' : st === 'run' ? 'border-[3px] border-brand-line border-t-brand animate-spin' : 'border-2 border-line-2'}`}>
                                {st === 'done' && <Icon.check className="w-3.5 h-3.5" />}
                              </span>
                              <b className="text-lg font-bold flex-1">{isAr ? d.ar : d.en}</b>
                              <small className={`text-base ${st === 'wait' ? 'text-ink-3' : st === 'run' ? 'text-brand-ink font-semibold' : 'text-ink-3'}`}>{label(st)}</small>
                            </li>
                          );
                        })}
                      </ul>
                    </>
                  )}

                  {scanFailed && (
                    <div className="mt-8">
                      <button
                        onClick={() => {
                          setScanFailed(false);
                          setTerminalLines([]);
                          setFileName('');
                          setAppState('upload');
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                        className="inline-flex items-center gap-2 bg-brand hover:bg-brand-600 text-white px-8 py-3.5 rounded-full font-bold transition-all active:translate-y-px"
                      >
                        <Icon.scanFrame className="w-5 h-5" />
                        {isAr ? 'فحص ملف آخر' : 'Scan Another File'}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* Results state */}
        {appState === 'result' && scanResult && (
          <div className="w-full max-w-6xl animate-fade-up">
            <div ref={resultRef} className="bg-white rounded-2xl p-2 sm:p-4">
            {/* Brand header — included in the shared image */}
            {capturing && (
              <div className="flex items-center gap-2.5 px-4 pt-2 pb-6" dir="ltr">
                <div className="text-lg font-display font-bold tracking-tight">
                  Malicious PDF <span className="text-brand">Detector</span>
                </div>
              </div>
            )}
            {scanResult.status === 'safe' && scanResult.threats.length === 0 ? (
              <div className="tile p-12 text-center">
                <div className="relative mx-auto mb-6 grid place-items-center w-[88px] h-[88px] rounded-[26px] bg-[#12B5A6] text-white shadow-[0_16px_30px_-12px_rgba(20,20,60,0.4)]">
                  <Icon.shieldCheck className="w-11 h-11" />
                </div>
                <h2 className="relative text-3xl font-display font-bold text-[#0B8479] mb-3">
                  {isAr ? 'الملف آمن تماماً' : 'File is completely safe'}
                </h2>
                <p className="relative text-ink-2 max-w-xl mx-auto">
                  {isAr ? 'لم يتم العثور على أي تهديدات أو أنماط مشبوهة داخل هذا الملف.' : 'No threats or suspicious patterns were found in this file.'}
                </p>
                {fileName && (
                  <div className="relative mt-5 inline-flex items-center gap-2 max-w-full bg-white border border-line rounded-xl px-3 py-1.5" dir="ltr">
                    <Icon.layers className="w-4 h-4 text-[#12B5A6] shrink-0" />
                    <span className="text-sm text-ink-2 truncate font-mono" title={fileName}>{fileName}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="grid md:grid-cols-3 gap-4">
                {/* Verdict + score tiles */}
                {(() => {
                  const t = tones[scanResult.status] || tones.danger;
                  const headline = scanResult.status === 'safe'
                    ? (isAr ? 'لا توجد مؤشرات خطرة' : 'No Risky Indicators')
                    : scanResult.status === 'warning'
                    ? (isAr ? 'تهديدات محتملة' : 'Possible Threats Detected')
                    : (isAr ? 'تم اكتشاف تهديدات!' : 'Threats Detected!');
                  const sub = scanResult.status === 'safe'
                    ? (isAr ? 'لم يُعثر على ما يدل على ضرر. الملاحظات أدناه للاطلاع فقط.' : 'Nothing harmful was found. The observations below are for your information only.')
                    : scanResult.status === 'warning'
                    ? (isAr ? 'يحتوي هذا الملف على روابط أو عناصر منخفضة الخطورة يجب الانتباه لها.' : 'This file contains low-risk elements or links worth reviewing.')
                    : (isAr ? 'يحتوي هذا الملف على عناصر خبيثة ومؤشرات اختراق.' : 'This file contains malicious elements and indicators of compromise.');
                  return (
                    <div className="tile md:col-span-3 flex flex-col md:flex-row md:items-center md:justify-between">
                      <div className={`px-8 py-6 flex flex-col justify-center items-start ${isAr ? 'text-right' : ''}`}>
                        <div className={`inline-flex items-center gap-2 ${t.pill} border rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wider mb-4`}>
                          {scanResult.status === 'safe'
                            ? <Icon.shieldCheck className="w-3.5 h-3.5" />
                            : <Icon.alert className="w-3.5 h-3.5" />}
                          {isAr ? 'تقرير الفحص' : 'Scan Report'}
                        </div>
                        <h2 className={`text-3xl font-display font-bold mb-2 ${t.text}`}>{headline}</h2>
                        <p className="text-ink-3">{sub}</p>
                      </div>

                      <div className="px-8 py-5 md:px-14 flex flex-col items-center justify-center shrink-0">
                        <RiskGauge score={scanResult.overallScore} tone={scanResult.status === 'safe' ? 'safe' : scanResult.status === 'warning' ? 'warn' : 'danger'} />
                        <div className="text-[11px] text-ink-3 uppercase tracking-widest mt-1">{isAr ? 'نسبة الخطورة' : 'Risk Score'}</div>
                      </div>
                    </div>
                  );
                })()}

                {/* Tabs (hidden while capturing the shared image, where all sections are shown) */}
                {!capturing && (
                  <div className="md:col-span-3 flex gap-1" role="tablist" dir="ltr">
                    {[
                      { k: 'findings', en: 'Findings', ar: 'النتائج', n: scanResult.threats.length },
                      { k: 'scripts', en: 'Scripts', ar: 'السكريبتات', n: scanResult.extractedScripts.length },
                      { k: 'details', en: 'File details', ar: 'تفاصيل الملف', n: null },
                    ].map((tb) => (
                      <button
                        key={tb.k}
                        type="button"
                        role="tab"
                        aria-selected={resultTab === tb.k}
                        onClick={() => setResultTab(tb.k)}
                        className={`flex items-center gap-2 px-4 py-3 -mb-px font-semibold whitespace-nowrap border-b-[3px] transition-colors ${resultTab === tb.k ? 'text-ink border-brand' : 'text-ink-3 border-transparent hover:text-ink'}`}
                      >
                        {isAr ? tb.ar : tb.en}
                        {tb.n !== null && <span className="font-mono text-xs bg-white border border-line rounded-full px-2 leading-5">{tb.n}</span>}
                      </button>
                    ))}
                  </div>
                )}

                {/* Findings */}
                {(capturing || resultTab === 'findings') && (() => {
                  const t = tones[scanResult.status] || tones.danger;
                  return (
                    <div className="tile md:col-span-3 overflow-hidden">
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="text-ink-3 text-xs uppercase tracking-wider bg-page">
                            <tr>
                              <th className={`px-6 py-4 font-semibold ${isAr ? 'text-right' : 'text-left'}`}>{isAr ? 'التهديد' : 'Threat'}</th>
                              <th className="px-6 py-4 font-semibold text-center">{isAr ? 'التصنيف' : 'Category'}</th>
                              <th className="px-6 py-4 font-semibold text-center">{isAr ? 'الموقع' : 'Location'}</th>
                              <th className="px-6 py-4 font-semibold text-center">{isAr ? 'الخطورة' : 'Risk'}</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-line">
                            {scanResult.threats.map((threat) => (
                              <tr key={threat.id} className="hover:bg-page transition">
                                <td className={`px-6 py-4 font-medium text-ink ${isAr ? 'text-right' : 'text-left'}`}>
                                  <ExpandableText text={threat.name} maxLength={220} isAr={isAr} forceExpand={capturing} />
                                </td>
                                <td className="px-6 py-4 align-middle whitespace-nowrap text-center">
                                  <span className={`inline-block whitespace-nowrap text-xs px-2.5 py-1 rounded-lg bg-page border border-line text-ink-2 ${isAr ? 'font-sans' : 'font-mono'}`}>
                                    {categoryLabel(threat.categoryKey, isAr)}
                                  </span>
                                </td>
                                <td className="px-6 py-4 text-ink-3 font-mono text-sm text-center align-middle" dir="ltr">{threat.offset}</td>
                                <td className="px-6 py-4 text-center align-middle whitespace-nowrap">
                                  <span className={`inline-block px-3.5 py-1 rounded-full text-xs font-bold tracking-wider ${sevPill(threat.risk, t.pill)}`} dir="ltr">{threat.risk}</span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })()}

                {/* Scripts */}
                {(capturing || resultTab === 'scripts') && (
                  <div className="tile md:col-span-3 overflow-hidden">
                    {scanResult.extractedScripts.length > 0 ? (
                      <>
                    <div className="p-6 space-y-5">
                      {scanResult.extractedScripts.map((script, index) => (
                        <div key={index} className="bg-page border border-line rounded-2xl overflow-hidden">
                          <div className={`flex flex-wrap justify-between items-center gap-3 px-4 py-3 border-b border-line ${isAr ? 'flex-row-reverse' : ''}`}>
                            <span className="bg-brand-soft border border-brand-line text-brand-ink px-3 py-1 rounded-lg text-xs font-bold tracking-wider uppercase">
                              {script.script_type || 'Unknown Type'}
                            </span>
                            <div className="flex items-center gap-3" dir="ltr">
                              <span className="text-ink-3 text-xs font-mono">{script.locations ? script.locations.join(', ') : 'Unknown Location'}</span>
                              <button
                                onClick={() => copyCode(script.code, index)}
                                className="flex items-center gap-1.5 text-xs text-ink-3 hover:text-brand-ink bg-page hover:bg-brand-soft border border-line rounded-lg px-2.5 py-1 transition"
                              >
                                {copiedIdx === index ? <Icon.check className="w-3.5 h-3.5 text-safe" /> : <Icon.copy className="w-3.5 h-3.5" />}
                                {copiedIdx === index ? (isAr ? 'تم النسخ' : 'Copied') : (isAr ? 'نسخ' : 'Copy')}
                              </button>
                            </div>
                          </div>
                          <pre className="bg-white p-5 overflow-x-auto" dir="ltr">
                            <code className="text-ink font-mono text-sm leading-relaxed">
                              <ExpandableText text={script.code} maxLength={300} isAr={isAr} forceExpand={capturing} />
                            </code>
                          </pre>
                        </div>
                      ))}
                    </div>
                      </>
                    ) : (
                      <p className="p-8 text-center text-ink-3">{isAr ? 'لم يتم استخراج أي سكريبتات من هذا الملف.' : 'No scripts were extracted from this file.'}</p>
                    )}
                  </div>
                )}

                {/* File details */}
                {(capturing || resultTab === 'details') && (
                  <div className="tile md:col-span-3 overflow-hidden">
                    <dl className="grid grid-cols-[130px_minmax(0,1fr)] sm:grid-cols-[170px_minmax(0,1fr)] text-sm">
                      {[
                        [isAr ? 'اسم الملف' : 'File name', <span className="font-mono break-all" dir="ltr">{fileName || '—'}</span>],
                        [isAr ? 'الحجم' : 'Size', <bdi>{fmtSize(scanResult.size)}</bdi>],
                        [isAr ? 'نسبة الخطورة' : 'Risk score', <bdi>{scanResult.overallScore}%{scanResult.riskLevel ? ` · ${scanResult.riskLevel}` : ''}</bdi>],
                        ['SHA-256', scanResult.sha ? (
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-xs break-all" dir="ltr">{scanResult.sha}</span>
                            {!capturing && (
                              <button
                                type="button"
                                onClick={() => {
                                  try { navigator.clipboard.writeText(scanResult.sha); setCopiedSha(true); setTimeout(() => setCopiedSha(false), 1500); } catch { /* ignore */ }
                                }}
                                className="inline-flex items-center gap-1.5 text-xs text-ink-3 hover:text-brand-ink bg-white border border-line-2 rounded-full px-3 py-1 transition"
                              >
                                {copiedSha ? <Icon.check className="w-3.5 h-3.5 text-safe" /> : <Icon.copy className="w-3.5 h-3.5" />}
                                {copiedSha ? (isAr ? 'تم النسخ' : 'Copied') : (isAr ? 'نسخ' : 'Copy')}
                              </button>
                            )}
                          </span>
                        ) : <span className="text-ink-3">{isAr ? 'غير متاح' : 'Not available'}</span>],
                        [isAr ? 'وقت الفحص' : 'Scanned', <bdi>{new Date(scanResult.scannedAt).toLocaleString(isAr ? 'ar-SA-u-ca-gregory-nu-latn' : 'en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</bdi>],
                        [isAr ? 'الكواشف' : 'Detectors', (
                          <span className="flex flex-wrap gap-2">
                            {DETECTORS.map((d) => (
                              <span key={d.k} className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white border border-line text-[13px]">
                                <b className="font-semibold">{isAr ? d.ar : d.en}</b>
                                <span className="font-mono text-xs text-ink-3">{scanResult.threats.filter((x) => x.categoryKey === DET_CATEGORY[d.k]).length}</span>
                              </span>
                            ))}
                          </span>
                        )],
                      ].map(([label, value], i, arr) => (
                        <div key={i} className="contents">
                          <dt className={`px-5 py-3.5 text-ink-3 bg-page ${i < arr.length - 1 ? 'border-b border-line' : ''}`}>{label}</dt>
                          <dd className={`px-5 py-3.5 min-w-0 ${i < arr.length - 1 ? 'border-b border-line' : ''}`}>{value}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                )}
              </div>
            )}

            {/* Page footer — included in the shared image */}
            {capturing && (
              <div className="mt-6 pt-4 border-t border-line bg-page text-center text-sm">
                <p className="text-ink-3">
                  {isAr ? 'تم تطويره بواسطة ديالى التركي' : 'Developed by Diyala Alturki'}
                </p>
                <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 mt-2" dir="ltr">
                  <span className="flex items-center gap-2 text-ink-3"><span className="h-5 w-4 flex items-center justify-center flex-shrink-0"><Icon.github className="w-4 h-4" /></span> Diiiyala</span>
                  <span className="text-line-2">|</span>
                  <span className="flex items-center gap-2 text-ink-3"><span className="h-5 w-4 flex items-center justify-center flex-shrink-0"><Icon.mail className="w-4 h-4" /></span> diyala.alturki@gmail.com</span>
                </div>
              </div>
            )}
            </div>

            <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
              <button
                onClick={shareResult}
                disabled={sharing}
                className={`inline-flex items-center gap-2 bg-white hover:border-brand hover:text-brand-ink text-ink border border-line-2 px-5 py-2 rounded-full text-sm font-bold transition-all active:translate-y-px ${sharing ? 'opacity-60 cursor-wait' : ''}`}
              >
                <Icon.share className="w-4 h-4" />
                {sharing ? (isAr ? 'جارٍ التحضير...' : 'Preparing...') : (isAr ? 'مشاركة النتيجة' : 'Share result')}
              </button>
              <button
                onClick={() => {
                  setAppState('upload');
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }}
                className="inline-flex items-center gap-2 bg-brand hover:bg-brand-600 text-white px-5 py-2 rounded-full text-sm font-bold transition-all active:translate-y-px"
              >
                <Icon.scanFrame className="w-4 h-4" />
                {isAr ? 'فحص ملف آخر' : 'Scan Another File'}
              </button>
            </div>
          </div>
        )}
      </section>
      )}

      {/* How it works */}
      <section id="how-it-works" className="relative z-10 px-5 sm:px-8 py-24 bg-white">
        <div className="mx-auto max-w-6xl">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <h2 className="text-3xl sm:text-4xl font-display font-extrabold tracking-tight">{isAr ? 'من الرفع إلى الإجابة في ثلاث خطوات' : 'From upload to answer in three steps'}</h2>
          </div>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              { enT: 'Upload a PDF', arT: 'ارفع ملف PDF', enD: 'Drag and drop your file or browse to select it.', arD: 'اسحب وأفلت الملف أو اختره من جهازك.' },
              { enT: 'Deep analysis', arT: 'تحليل عميق', enD: 'The engine inspects structure, scripts, links, and metadata.', arD: 'يفحص المحرك الهيكل والسكريبتات والروابط والبيانات الوصفية.' },
              { enT: 'Get your report', arT: 'احصل على تقريرك', enD: 'See detected threats, a risk score, and any extracted scripts.', arD: 'اطّلع على التهديدات ودرجة الخطورة والسكريبتات المستخرجة.' },
            ].map((st, i) => (
              <div key={i} className="flex flex-col items-center gap-3 text-center">
                <span className="grid place-items-center w-14 h-14 rounded-full bg-brand text-white font-display font-extrabold text-[22px] shadow-[0_0_0_8px_#EEF1FF]" dir="ltr">{i + 1}</span>
                <h3 className="text-[19px] font-bold">{isAr ? st.arT : st.enT}</h3>
                <p className="text-ink-2 max-w-[32ch]">{isAr ? st.arD : st.enD}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Detectors */}
      <section id="detectors" className="relative z-10 px-5 sm:px-8 py-24 bg-white">
        <div className="mx-auto max-w-6xl">
          <div className="text-center max-w-2xl mx-auto mb-9">
            <h2 className="text-3xl sm:text-4xl font-display font-extrabold tracking-tight">{isAr ? 'ما الذي نفحصه داخل كل ملف' : 'What we look at inside every PDF'}</h2>
            <p className="text-ink-2 mt-3 text-base">
              {isAr ? 'خمسة كواشف تعمل معًا. اختر أحدها لترى الفحوصات التي يجريها.' : 'Five detectors work together. Pick one to see the checks it runs.'}
            </p>
          </div>

          {(() => {
            const d = DETECTORS.find((x) => x.k === openDet) || DETECTORS[0];
            const col = DET_COLORS[d.k];
            const n = d.checks.length;
            return (
              <div className="rounded-[32px] bg-page p-3 sm:p-4 grid md:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] gap-3 sm:gap-4">
                <div className="flex flex-col gap-1.5 md:justify-between" role="tablist">
                  {DETECTORS.map((x) => {
                    const on = x.k === d.k;
                    const c = DET_COLORS[x.k];
                    return (
                      <button
                        key={x.k}
                        type="button"
                        role="tab"
                        aria-selected={on}
                        onClick={() => setOpenDet(x.k)}
                        className={`flex items-center gap-4 text-start rounded-[20px] px-4 py-3.5 transition ${on ? 'bg-white shadow-[0_10px_30px_-18px_rgba(20,20,20,0.35)]' : 'hover:bg-white/60'}`}
                      >
                        <span className="grid place-items-center w-12 h-12 rounded-[15px] text-white shrink-0" style={{ backgroundColor: c }}>
                          <DetIcon n={x.icon} className="w-6 h-6" />
                        </span>
                        <span className="min-w-0 flex-1">
                          <b className="block text-[17px] font-bold leading-tight">{isAr ? x.ar : x.en}</b>
                          <span className="block text-sm text-ink-2 mt-0.5">{isAr ? x.arD : x.enD}</span>
                        </span>
                        <span className={`text-xs font-bold px-2.5 py-1 rounded-full shrink-0 ${on ? 'bg-page text-ink' : 'text-ink-3'}`}>{x.checks.length}</span>
                      </button>
                    );
                  })}
                </div>

                <div key={d.k} className="rounded-[24px] bg-white p-6 sm:p-8 animate-fade-in flex flex-col h-[500px] min-h-0">
                  <div className="flex items-center gap-4">
                    <span className="grid place-items-center w-14 h-14 rounded-[18px] text-white shrink-0" style={{ backgroundColor: col }}>
                      <DetIcon n={d.icon} className="w-7 h-7" />
                    </span>
                    <div className="min-w-0">
                      <h3 className="text-2xl font-display font-extrabold leading-tight">{isAr ? d.ar : d.en}</h3>
                      <p className="text-ink-2 mt-0.5">{isAr ? d.arD : d.enD}</p>
                    </div>
                  </div>
                  <div className="mt-6 text-xs font-bold uppercase tracking-wider text-ink-3">
                    {isAr ? `${n} ${n === 1 ? 'فحص' : 'فحوصات'}` : `${n} ${n === 1 ? 'check' : 'checks'}`}
                  </div>
                  <ul className="mt-3 grid gap-2 content-start flex-1 min-h-0 overflow-y-auto pe-1 -me-1">
                    {d.checks.map((c) => (
                      <li key={c.tok} className="flex items-center gap-3 rounded-2xl px-4 py-3 bg-[#F6F6F6]">
                        <i className={`w-2.5 h-2.5 rounded-full shrink-0 ${SEV_DOT[c.sev]}`} />
                        <b className="font-semibold text-ink flex-1 min-w-0">{isAr ? c.ar : c.en}</b>
                        <span className="font-mono text-xs text-ink-3 truncate max-w-[40%]" dir="ltr">{c.tok}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            );
          })()}
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 bg-white py-10 px-5 sm:px-8 text-sm">
        <div className="mx-auto max-w-6xl flex flex-col md:flex-row md:items-center md:justify-between gap-6 text-center md:text-left" dir="ltr">
        <div dir={isAr ? 'rtl' : 'ltr'} className="md:text-left">
          <div className="font-display font-bold text-ink-2">
            Malicious PDF <span className="text-brand">Detector</span>
          </div>
          <p className="text-ink-3 mt-1.5">
            {isAr ? 'تم تطويره بواسطة ديالى التركي' : 'Developed by Diyala Alturki'}
          </p>
        </div>
        <div className="flex items-center justify-center gap-3" dir="ltr">
          {[
            { href: 'https://github.com/Diiiyala', src: '/github.svg', label: 'GitHub', ext: true },
            { href: 'mailto:diyala.alturki@gmail.com', src: '/mail.svg', label: 'Email' },
            { href: 'https://www.linkedin.com/in/diyala-alturki', src: '/linkedin.svg', label: 'LinkedIn', ext: true },
          ].map((s) => (
            <a
              key={s.label}
              href={s.href}
              aria-label={s.label}
              title={s.label}
              {...(s.ext ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
              className="group grid place-items-center w-11 h-11 rounded-full bg-[#5271FF] hover:bg-[#3F5AE0] hover:-translate-y-0.5 transition"
            >
              <img src={s.src} alt="" className="w-5 h-5 brightness-0 invert" />
            </a>
          ))}
        </div>
        </div>
      </footer>
    </div>
  );
}

export default App;