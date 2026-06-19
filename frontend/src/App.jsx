import { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';


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
  logo: (p) => (
    <svg viewBox="0 0 48 48" fill="none" {...p}>
      {/* document with folded corner */}
      <path d="M13 8 H29 L35 14 V40 H13 Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      <path d="M29 8 V14 H35" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      {/* fingerprint, centered inside the document */}
      <g transform="translate(13.75 15.25) scale(0.82)" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" opacity="0.9">
        <path d="M18.9 7a8 8 0 0 1 1.1 5v1a6 6 0 0 0 .8 3" />
        <path d="M8 11a4 4 0 0 1 8 0v1a10 10 0 0 0 2 6" />
        <path d="M12 11v2a14 14 0 0 0 2.5 8" />
        <path d="M8 15a18 18 0 0 0 1.8 6" />
        <path d="M4.9 19a22 22 0 0 1 -.9 -7a8 8 0 0 1 12 -7" />
      </g>
      {/* scan bar */}
      <rect x="7" y="14.5" width="34" height="3" fill="#6366f1" />
    </svg>
  ),
  copy: (p) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path strokeLinecap="round" d="M5 15V5a2 2 0 012-2h10" />
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
};


const ExpandableText = ({ text, maxLength = 150, isAr }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  if (!text || text.length <= maxLength) return <span>{text}</span>;
  return (
    <div className="inline-block">
      <span className="break-all whitespace-pre-wrap">
        {isExpanded ? text : `${text.substring(0, maxLength)}...`}
      </span>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="inline-flex items-center text-brand-400 hover:text-brand-300 font-bold transition-colors text-sm mx-2"
      >
        {isExpanded ? (isAr ? 'عرض أقل' : 'Show Less') : (isAr ? 'قراءة المزيد' : 'Read More')}
      </button>
    </div>
  );
};


const RiskGauge = ({ score = 0, tone = 'danger' }) => {
  const R = 52;
  const C = 2 * Math.PI * R;
  const pct = Math.min(100, Math.max(0, score));
  const offset = C - (pct / 100) * C;
  const colors = {
    safe: '#34d399',
    warn: '#fbbf24',
    danger: '#fb7185',
  };
  const stroke = colors[tone] || colors.danger;
  return (
    <div className="relative w-40 h-40 shrink-0" dir="ltr">
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
        <circle cx="60" cy="60" r={R} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" />
        <circle
          cx="60" cy="60" r={R} fill="none" stroke={stroke} strokeWidth="10"
          strokeLinecap="round" strokeDasharray={C} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.16,1,0.3,1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-display font-bold" style={{ color: stroke }}>{pct}%</span>
      </div>
    </div>
  );
};


const ScanIllustration = ({ isAr }) => {
  const [found, setFound] = useState(0);

  useEffect(() => {
    const timers = [700, 1500, 2300].map((t, i) => setTimeout(() => setFound(i + 1), t));
    return () => timers.forEach(clearTimeout);
  }, []);

  const markers = [
    { top: '23%', left: '12%', label: 'JS', delay: '0.7s' },
    { top: '50%', left: '66%', label: '/Launch', delay: '1.5s' },
    { top: '73%', left: '26%', label: 'URI', delay: '2.3s' },
  ];

  return (
    <div className="relative w-full max-w-md mx-auto">
      <div className="relative animate-float">
        <div className="relative">
          {/* PDF document card */}
          <div className="relative glass border border-white/10 rounded-2xl p-6 overflow-hidden shadow-[0_30px_80px_-24px_rgba(0,0,0,0.9)]">
            <div className="flex items-center justify-between mb-5" dir="ltr">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-2xl bg-white/10 border border-white/25 grid place-items-center text-white font-bold text-[11px]">PDF</div>
                <div>
                  <div className="h-2.5 w-24 rounded bg-white/20" />
                  <div className="h-2 w-16 rounded bg-white/10 mt-1.5" />
                </div>
              </div>
              <Icon.scan className="w-5 h-5 text-brand-400 animate-pulse" />
            </div>

            <div className="space-y-3">
              {[100, 92, 97, 78, 88, 70, 95, 83, 90].map((w, i) => (
                <div key={i} className="h-2.5 rounded bg-white/10" style={{ width: w + '%' }} />
              ))}
            </div>

            {/* threat markers */}
            {markers.map((m, i) => (
              <div key={i} className="absolute animate-pop-in" style={{ top: m.top, left: m.left, animationDelay: m.delay }}>
                <div className="flex items-center gap-1.5" dir="ltr">
                  <span className="relative flex h-3 w-3">
                    <span className="absolute inline-flex h-full w-full rounded-full bg-white opacity-60 animate-ping" />
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-white animate-blip" />
                  </span>
                  <span className="text-[10px] font-mono font-bold text-white bg-white/10 border border-white/25 rounded px-1.5 py-0.5">{m.label}</span>
                </div>
              </div>
            ))}
          </div>

          {/* floating live-count chip */}
          <div className="absolute -bottom-5 -right-4 glass border border-white/10 rounded-2xl px-4 py-2.5 flex items-center gap-2.5 shadow-2xl" dir="ltr">
            <div className="grid place-items-center w-8 h-8 rounded-2xl bg-white/10 border border-white/25 text-white">
              <Icon.alert className="w-4 h-4" />
            </div>
            <div className="text-left">
              <div className="text-lg font-display font-bold text-white leading-none transition-all">{found}</div>
              <div className="text-[10px] text-slate-400 uppercase tracking-wider">{isAr ? 'تهديدات' : 'threats'}</div>
            </div>
          </div>

          {/* floating "secured" chip */}
          <div className="absolute -top-4 -left-4 glass border border-white/10 rounded-2xl px-3 py-2 flex items-center gap-2 shadow-2xl animate-float" style={{ animationDelay: '1.5s' }} dir="ltr">
            <Icon.shieldCheck className="w-4 h-4 text-brand-400" />
            <span className="text-xs text-slate-300 font-medium">Deep scan</span>
          </div>
        </div>
      </div>
    </div>
  );
};


function App() {
  const [lang, setLang] = useState('en');
  const isAr = lang === 'ar';
  const [appState, setAppState] = useState('upload');
  const [terminalLines, setTerminalLines] = useState([]);
  const [uploadError, setUploadError] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isScrolled, setIsScrolled] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);
  const [dots, setDots] = useState('');
  const [copiedIdx, setCopiedIdx] = useState(null);
  const [fileName, setFileName] = useState('');

  useEffect(() => {
    setTimeout(() => setIsLoaded(true), 100);
    const handleScroll = () => setIsScrolled(window.scrollY > 50);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    if (appState !== 'scanning') return;
    const interval = setInterval(() => setDots(prev => (prev.length >= 3 ? '' : prev + '.')), 150);
    return () => {
      clearInterval(interval);
      setDots('');
    };
  }, [appState]);

  const processFile = async (file) => {
    setAppState('scanning');
    setTerminalLines([]);
    setFileName(file.name);

    const lines = isAr
      ? ["جاري إنشاء اتصال آمن مع الخادم...", "جاري رفع الملف لمحرك الفحص...", "جاري تحليل الهيكل والبيانات الوصفية..."]
      : ["Establishing secure connection...", "Uploading file to analysis engine...", "Analyzing structure and metadata..."];

    lines.forEach((line, index) => {
      setTimeout(() => setTerminalLines(prev => [...prev, line]), index * 800);
    });

    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch("http://localhost:5000/upload", { method: "POST", body: formData });
      if (!response.ok) throw new Error("Scan failed on server");
      const data = await response.json();

      setTimeout(() => {
        setTerminalLines(prev => [...prev, isAr ? "اكتمل الفحص. جاري عرض التقرير..." : "Scan complete. Displaying report..."]);
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
                category: category.replace('_', ' ').toUpperCase(),
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
          overallScore: data.risk_percentage || 0,
          threats: parsedThreats,
          extractedScripts: data.extracted_scripts || [],
        });
        setAppState('result');
      }, (lines.length * 800) + 1000);
    } catch (error) {
      setTimeout(() => {
        setTerminalLines(prev => [...prev, isAr ? "[ERROR] فشل الاتصال! تأكدي من تشغيل خادم Flask." : "[ERROR] Connection failed! Ensure Flask is running."]);
      }, 1000);
      console.error("Upload error:", error);
    }
  };

  const onDrop = useCallback(acceptedFiles => {
    setUploadError(null);
    if (acceptedFiles.length > 0) processFile(acceptedFiles[0]);
  }, [isAr]);

  const onDropRejected = useCallback((fileRejections) => {
    const fileName = fileRejections[0].file.name;
    setUploadError(isAr
      ? `عذراً، الملف "${fileName}" غير مدعوم. يرجى رفع ملفات PDF فقط.`
      : `Sorry, "${fileName}" is not supported. Please upload PDF files only.`);
  }, [isAr]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, onDropRejected, multiple: false, accept: { 'application/pdf': ['.pdf'] },
  });

  const copyCode = (code, idx) => {
    try {
      navigator.clipboard.writeText(code || '');
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 1500);
    } catch { /* ignore */ }
  };

  const tones = {
    warning: { text: 'text-warn', ring: 'ring-warn/30', bg: 'bg-warn/5', border: 'border-warn/25', pill: 'bg-warn/10 border-warn/30 text-warn', glow: '' },
    danger: { text: 'text-danger', ring: 'ring-danger/30', bg: 'bg-danger/5', border: 'border-danger/25', pill: 'bg-danger/10 border-danger/30 text-danger', glow: '' },
  };

  return (
    <div className="relative min-h-screen bg-ink text-white font-sans selection:bg-brand selection:text-white overflow-x-hidden" dir={isAr ? 'rtl' : 'ltr'}>

      {/* Ambient background */}
      <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
        {/* square grid */}
        <div className="absolute inset-0 bg-grid [background-size:92px_92px] opacity-100 [mask-image:linear-gradient(to_bottom,black,transparent_95%)]" />
      </div>

      {/* Navbar */}
      <div
        className={`fixed top-0 inset-x-0 z-50 transition-all duration-700 ease-out ${!isLoaded ? '-translate-y-full opacity-0 pointer-events-none' : 'translate-y-0 opacity-100'}`}
        dir="ltr"
      >
        <header className="mx-auto max-w-7xl mt-4 px-5 sm:px-6">
          <div className={`relative px-4 py-3 flex justify-between items-center transition-all duration-300 ${isScrolled ? 'backdrop-blur-md rounded-2xl border border-white/10' : 'border border-transparent'}`}>
            <div className="flex items-center gap-2.5">
              <Icon.logo className="w-8 h-8 text-slate-100" />
              <div className="text-base sm:text-lg font-display font-bold tracking-tight">
                Malicious PDF <span className="text-gradient">Detector</span>
              </div>
            </div>

            <nav className="hidden sm:flex items-center gap-8 absolute left-1/2 -translate-x-1/2" dir={isAr ? 'rtl' : 'ltr'}>
              {[
                { en: 'Home', ar: 'الرئيسية', href: '#' },
                { en: 'Scan', ar: 'افحص', href: '#workspace' },
                { en: 'How it works', ar: 'كيف يعمل', href: '#how-it-works' },
              ].map((l, i) => (
                <a key={i} href={l.href} className="text-sm font-medium text-slate-300 hover:text-white transition">
                  {isAr ? l.ar : l.en}
                </a>
              ))}
            </nav>

            <button
              onClick={() => setLang(isAr ? 'en' : 'ar')}
              className="group flex items-center justify-center gap-2 text-slate-300 hover:text-white transition bg-white/5 hover:bg-white/10 px-4 py-2 border border-white/10 rounded-2xl leading-none"
            >
              <Icon.globe className="w-4 h-4 text-brand-400 group-hover:rotate-12 transition-transform shrink-0" />
              <span className="font-display font-medium text-sm leading-none -mt-px" dir="ltr">{isAr ? 'EN' : 'AR'}</span>
            </button>
          </div>
        </header>
      </div>

      {/* Hero */}
      <section className="relative z-10 min-h-screen flex items-center px-5 sm:px-8 pt-28 pb-20">
        <div className={`mx-auto max-w-7xl w-full transition-all duration-1000 ${isLoaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'}`}>
          <div className="grid lg:grid-cols-3 gap-4">

            {/* Headline */}
            <div className="lg:col-span-2 p-2 sm:p-6 flex flex-col justify-center text-center lg:text-start">
              <h1 className={`text-4xl sm:text-5xl lg:text-6xl font-display font-bold mb-6 ${isAr ? 'leading-[1.5] tracking-normal' : 'leading-[1.07] tracking-tight'}`}>
                {isAr ? 'اكشف' : 'Detect'}{' '}
                {!isAr && <br className="hidden sm:block" />}
                <span className={`text-gradient ${isAr ? 'inline-block pb-1.5' : ''}`}>{isAr ? 'ملفات PDF الخبيثة' : 'Malicious PDFs'}</span>{' '}
                <br className="hidden sm:block" />
                {isAr ? 'قبل أن تشكل تهديدًا' : 'Before They Strike'}
              </h1>

              <p className="text-lg sm:text-xl text-slate-400 max-w-xl mx-auto lg:mx-0 leading-relaxed">
                {isAr
                  ? 'اكشف عن التهديدات المخفية، الأنماط المشبوهة، والمؤشرات الخبيثة داخل مستندات PDF قبل أن تعرض أمانك للخطر.'
                  : 'Uncover hidden threats, suspicious patterns, and indicators of compromise inside PDF documents before they put your security at risk.'}
              </p>

              <div className="mt-8 flex justify-center lg:justify-start">
                <a href="#workspace" className="group">
                  <span className="inline-flex items-center px-10 py-3.5 rounded-2xl bg-brand-gradient text-white font-bold transition-all hover:-translate-y-0.5">
                    {isAr ? 'ابدأ الفحص الآن' : 'Start Scanning Now'}
                  </span>
                </a>
              </div>
            </div>

            {/* Illustration */}
            <div className="p-6 flex items-center justify-center">
              <ScanIllustration isAr={isAr} />
            </div>

            {/* Feature tiles */}
            {[
              { icon: Icon.scan, ar: 'تحليل الهيكل', en: 'Structure analysis', arD: 'فحص الكائنات وهيكل المستند', enD: 'Objects & document tree' },
              { icon: Icon.code, ar: 'كشف السكريبتات', en: 'Script detection', arD: 'جافاسكربت والأكواد المضمّنة', enD: 'JavaScript & embedded code' },
              { icon: Icon.bolt, ar: 'نتائج فورية', en: 'Instant results', arD: 'تقرير مفصّل خلال ثوانٍ', enD: 'A detailed report in seconds' },
            ].map((f, i) => {
              const F = f.icon;
              return (
                <div key={i} className={`tile tile-hover p-6 ${isAr ? 'text-right' : ''}`}>
                  <span className="inline-grid place-items-center w-11 h-11 rounded-xl bg-brand/10 border border-brand/20 text-brand-400 mb-4">
                    <F className="w-5 h-5" />
                  </span>
                  <h3 className="font-display font-bold mb-1">{isAr ? f.ar : f.en}</h3>
                  <p className="text-sm text-slate-400">{isAr ? f.arD : f.enD}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Workspace */}
      <section id="workspace" className="relative z-10 min-h-screen flex flex-col justify-center items-center px-5 py-24 border-t border-white/5">

        {/* Upload state */}
        {appState === 'upload' && (
          <div className="w-full max-w-3xl">
            <div className="text-center mb-10">
              <h2 className="text-3xl sm:text-4xl font-display font-bold mb-3">{isAr ? 'ابدأ الفحص الآن' : 'Start Scanning Now'}</h2>
              <p className="text-slate-400">{isAr ? 'ارفع ملف PDF لفحصه بحثاً عن المخاطر.' : 'Upload a PDF to scan it for risks.'}</p>
            </div>

            {uploadError && (
              <div className="mb-6 glass border border-danger/30 text-white px-5 py-4 rounded-2xl flex items-center justify-between gap-4 animate-fade-in">
                <div className="flex items-center gap-3">
                  <Icon.alert className="w-6 h-6 text-danger shrink-0" />
                  <span className="font-medium">{uploadError}</span>
                </div>
                <button onClick={() => setUploadError(null)} className="text-white/60 hover:text-white transition">
                  <Icon.close className="w-5 h-5" />
                </button>
              </div>
            )}

            <div
              {...getRootProps()}
              className={`relative w-full rounded-2xl p-14 sm:p-20 text-center cursor-pointer transition-all duration-300 group overflow-hidden glass
                border-2 border-dashed
                ${isDragActive ? 'border-brand bg-brand/10 scale-[1.02]' : 'border-white/15 hover:border-brand/60'}`}
            >
              <input {...getInputProps()} />
              <div className="absolute inset-0 bg-brand/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
              <div className={`relative mx-auto mb-6 grid place-items-center w-20 h-20 rounded-2xl transition-all duration-300
                ${isDragActive ? 'bg-brand text-white scale-110' : 'bg-brand/10 text-brand-400 group-hover:scale-105'}`}>
                <Icon.upload className="w-9 h-9" />
              </div>
              <p className="text-slate-200 text-lg sm:text-xl font-medium relative">
                {isDragActive
                  ? (isAr ? 'أفلت ملف الـ PDF هنا...' : 'Drop the PDF here...')
                  : (isAr ? 'اسحب وأفلت ملف الـ PDF هنا، أو اضغط للاختيار' : 'Drag & drop a PDF here, or click to browse')}
              </p>
              <p className="text-sm text-brand-400/80 mt-3 font-semibold tracking-wide relative">
                {isAr ? 'يدعم ملفات PDF فقط' : 'Supports PDF files only'}
              </p>
            </div>
          </div>
        )}

        {/* Scanning state */}
        {appState === 'scanning' && (
          <div className="w-full max-w-3xl animate-fade-in">
            <div className="flex flex-col items-center mb-8">
              <div className="relative grid place-items-center w-24 h-24 mb-4">
                <div className="absolute inset-0 rounded-full border-2 border-white/10 border-t-brand-400 animate-spin-slow" />
                <Icon.scan className="w-9 h-9 text-slate-300" />
              </div>
              <h2 className="text-2xl font-display font-bold">
                {isAr ? 'جاري الفحص' : 'Scanning'}<span className="text-brand-400">{dots}</span>
              </h2>
              {fileName && (
                <div className="mt-3 inline-flex items-center gap-2 max-w-full glass border border-white/10 rounded-xl px-3 py-1.5" dir="ltr">
                  <Icon.layers className="w-4 h-4 text-brand-400 shrink-0" />
                  <span className="text-sm text-slate-300 truncate font-mono" title={fileName}>{fileName}</span>
                </div>
              )}
            </div>

            <div className="relative glass border border-white/10 rounded-2xl p-6 shadow-2xl font-mono text-sm md:text-base overflow-hidden">
              <div className={`flex gap-2 mb-4 pb-4 border-b border-white/10 ${isAr ? 'flex-row-reverse' : ''}`}>
                <div className="w-3 h-3 rounded-full bg-danger/80" />
                <div className="w-3 h-3 rounded-full bg-warn/80" />
                <div className="w-3 h-3 rounded-full bg-safe/80" />
              </div>
              <div className={`space-y-3 ${isAr ? 'text-right' : 'text-left'}`} dir={isAr ? 'rtl' : 'ltr'}>
                {terminalLines.map((line, idx) => {
                  const isError = line.includes('[ERROR]');
                  return (
                    <div key={idx} className="flex items-center gap-2.5 animate-fade-in">
                      {isError
                        ? <Icon.alert className="w-4 h-4 text-danger shrink-0" />
                        : <Icon.check className="w-4 h-4 text-safe shrink-0" />}
                      <span className={isError ? 'text-danger' : 'text-slate-300'}>{line}</span>
                    </div>
                  );
                })}
                <div className="inline-block text-brand-400 font-bold text-xl tracking-widest min-w-[32px]" dir="ltr">{dots}</div>
              </div>
            </div>
          </div>
        )}

        {/* Results state */}
        {appState === 'result' && scanResult && (
          <div className="w-full max-w-6xl animate-fade-up">
            {scanResult.status === 'safe' ? (
              <div className="tile p-12 text-center">
                <div className="relative mx-auto mb-6 grid place-items-center w-24 h-24 rounded-full bg-safe/10 border border-safe/30">
                  <Icon.shieldCheck className="w-12 h-12 text-safe" />
                </div>
                <h2 className="relative text-3xl font-display font-bold text-safe mb-3">
                  {isAr ? 'الملف آمن تماماً' : 'File is completely safe'}
                </h2>
                <p className="relative text-slate-300 max-w-xl mx-auto">
                  {isAr ? 'لم يتم العثور على أي تهديدات أو أنماط مشبوهة داخل هذا الملف.' : 'No threats or suspicious patterns were found in this file.'}
                </p>
                {fileName && (
                  <div className="relative mt-5 inline-flex items-center gap-2 max-w-full glass border border-white/10 rounded-xl px-3 py-1.5" dir="ltr">
                    <Icon.layers className="w-4 h-4 text-safe shrink-0" />
                    <span className="text-sm text-slate-300 truncate font-mono" title={fileName}>{fileName}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="grid md:grid-cols-3 gap-4">
                {/* Verdict + score tiles */}
                {(() => {
                  const t = tones[scanResult.status] || tones.danger;
                  const headline = scanResult.status === 'warning'
                    ? (isAr ? 'تهديدات محتملة' : 'Possible Threats Detected')
                    : (isAr ? 'تم اكتشاف تهديدات!' : 'Threats Detected!');
                  const sub = scanResult.status === 'warning'
                    ? (isAr ? 'يحتوي هذا الملف على روابط أو عناصر منخفضة الخطورة يجب الانتباه لها.' : 'This file contains low-risk elements or links worth reviewing.')
                    : (isAr ? 'يحتوي هذا الملف على عناصر خبيثة ومؤشرات اختراق.' : 'This file contains malicious elements and indicators of compromise.');
                  return (
                    <>
                      <div className={`tile md:col-span-2 p-8 flex flex-col justify-center items-start ${isAr ? 'text-right' : ''}`}>
                        <div className={`inline-flex items-center gap-2 ${t.pill} border rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wider mb-4`}>
                          <Icon.alert className="w-3.5 h-3.5" />
                          {isAr ? 'تقرير الفحص' : 'Scan Report'}
                        </div>
                        <h2 className={`text-3xl font-display font-bold mb-2 ${t.text}`}>{headline}</h2>
                        <p className="text-slate-400">{sub}</p>
                        <div className="flex flex-wrap gap-3 mt-6">
                          {fileName && (
                            <span className="inline-flex items-center gap-2 max-w-[16rem] text-sm text-slate-300 bg-white/5 border border-white/10 rounded-xl px-3 py-1.5 font-mono" dir="ltr" title={fileName}>
                              <Icon.layers className="w-4 h-4 text-slate-500 shrink-0" /><span className="truncate">{fileName}</span>
                            </span>
                          )}
                          <span className="inline-flex items-center gap-2 text-sm text-slate-300 bg-white/5 border border-white/10 rounded-xl px-3 py-1.5 font-mono"><Icon.alert className="w-4 h-4 text-slate-500" />{scanResult.threats.length} {isAr ? 'تهديد' : 'threats'}</span>
                          <span className="inline-flex items-center gap-2 text-sm text-slate-300 bg-white/5 border border-white/10 rounded-xl px-3 py-1.5 font-mono"><Icon.code className="w-4 h-4 text-slate-500" />{scanResult.extractedScripts.length} {isAr ? 'سكريبت' : 'scripts'}</span>
                        </div>
                      </div>

                      <div className="tile p-8 flex flex-col items-center justify-center">
                        <RiskGauge score={scanResult.overallScore} tone={scanResult.status === 'warning' ? 'warn' : 'danger'} />
                        <div className="text-xs text-slate-400 uppercase tracking-widest mt-2">{isAr ? 'نسبة الخطورة' : 'Risk Score'}</div>
                      </div>
                    </>
                  );
                })()}

                {/* Threats table tile */}
                {(() => {
                  const t = tones[scanResult.status] || tones.danger;
                  return (
                    <div className="tile md:col-span-3 overflow-hidden">
                      <div className={`px-6 py-4 border-b border-white/10 flex items-center gap-3 ${isAr ? 'flex-row-reverse text-right' : ''}`}>
                        <Icon.layers className={`w-5 h-5 ${t.text}`} />
                        <h3 className="text-lg font-display font-bold">{isAr ? 'التهديدات المكتشفة' : 'Detected Threats'}</h3>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="text-slate-400 text-xs uppercase tracking-wider bg-white/[0.02]">
                            <tr>
                              <th className={`px-6 py-4 font-semibold ${isAr ? 'text-right' : 'text-left'}`}>{isAr ? 'التهديد' : 'Threat'}</th>
                              <th className={`px-6 py-4 font-semibold ${isAr ? 'text-right' : 'text-left'}`}>{isAr ? 'التصنيف' : 'Category'}</th>
                              <th className={`px-6 py-4 font-semibold ${isAr ? 'text-right' : 'text-left'}`}>{isAr ? 'الموقع' : 'Location'}</th>
                              <th className={`px-6 py-4 font-semibold ${isAr ? 'text-right' : 'text-left'}`}>{isAr ? 'الخطورة' : 'Risk'}</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-white/5">
                            {scanResult.threats.map((threat) => (
                              <tr key={threat.id} className="hover:bg-white/[0.03] transition">
                                <td className={`px-6 py-4 font-medium text-white ${isAr ? 'text-right' : 'text-left'}`}>
                                  <ExpandableText text={threat.name} maxLength={120} isAr={isAr} />
                                </td>
                                <td className={`px-6 py-4 ${isAr ? 'text-right' : 'text-left'}`}>
                                  <span className="text-xs font-mono px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300">{threat.category}</span>
                                </td>
                                <td className={`px-6 py-4 text-slate-400 font-mono text-sm ${isAr ? 'text-right' : 'text-left'}`}>{threat.offset}</td>
                                <td className={`px-6 py-4 ${isAr ? 'text-right' : 'text-left'}`}>
                                  <span className={`inline-block px-3.5 py-1 rounded-full text-xs font-bold tracking-wider border ${t.pill}`}>{threat.risk}</span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })()}

                {/* Extracted scripts tile */}
                {scanResult.extractedScripts && scanResult.extractedScripts.length > 0 && (
                  <div className="tile md:col-span-3 overflow-hidden">
                    <div className={`px-6 py-4 border-b border-white/10 flex items-center gap-3 ${isAr ? 'flex-row-reverse text-right' : ''}`}>
                      <Icon.code className="w-5 h-5 text-cyan-glow" />
                      <h3 className="text-lg font-display font-bold text-slate-100">{isAr ? 'السكريبتات المستخرجة' : 'Extracted Scripts'}</h3>
                    </div>
                    <div className="p-6 space-y-5">
                      {scanResult.extractedScripts.map((script, index) => (
                        <div key={index} className="bg-black/30 border border-white/10 rounded-2xl overflow-hidden">
                          <div className={`flex flex-wrap justify-between items-center gap-3 px-4 py-3 border-b border-white/5 ${isAr ? 'flex-row-reverse' : ''}`}>
                            <span className="bg-cyan-glow/10 border border-cyan-glow/30 text-cyan-glow px-3 py-1 rounded-lg text-xs font-bold tracking-wider uppercase">
                              {script.script_type || 'Unknown Type'}
                            </span>
                            <div className="flex items-center gap-3" dir="ltr">
                              <span className="text-slate-500 text-xs font-mono">{script.locations ? script.locations.join(', ') : 'Unknown Location'}</span>
                              <button
                                onClick={() => copyCode(script.code, index)}
                                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg px-2.5 py-1 transition"
                              >
                                {copiedIdx === index ? <Icon.check className="w-3.5 h-3.5 text-safe" /> : <Icon.copy className="w-3.5 h-3.5" />}
                                {copiedIdx === index ? (isAr ? 'تم النسخ' : 'Copied') : (isAr ? 'نسخ' : 'Copy')}
                              </button>
                            </div>
                          </div>
                          <pre className="bg-black/40 p-5 overflow-x-auto" dir="ltr">
                            <code className="text-white font-mono text-sm leading-relaxed">
                              <ExpandableText text={script.code} maxLength={300} isAr={isAr} />
                            </code>
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="mt-10 text-center">
              <button
                onClick={() => {
                  setAppState('upload');
                  setTimeout(() => {
                    document.getElementById('workspace')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                  }, 60);
                }}
                className="inline-flex items-center gap-2 bg-brand-gradient text-white px-8 py-3.5 rounded-2xl font-bold transition-all hover:-translate-y-0.5"
              >
                <Icon.upload className="w-5 h-5" />
                {isAr ? 'فحص ملف آخر' : 'Scan Another File'}
              </button>
            </div>
          </div>
        )}
      </section>

      {/* How it works */}
      <section id="how-it-works" className="relative z-10 px-5 sm:px-8 py-24 border-t border-white/5">
        <div className="mx-auto max-w-6xl">
          <div className="text-center mb-14">
            <h2 className="text-3xl sm:text-4xl font-display font-bold mb-3">{isAr ? 'كيف يعمل' : 'How it works'}</h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              {isAr ? 'ثلاث خطوات بسيطة من الرفع إلى التقرير الكامل.' : 'Three simple steps from upload to a full report.'}
            </p>
          </div>

          {/* Bento grid */}
          <div className="grid md:grid-cols-3 gap-4">
            {[
              { n: '01', icon: Icon.upload, enT: 'Upload a PDF', arT: 'ارفع ملف PDF', enD: 'Drag and drop your file or browse to select it.', arD: 'اسحب وأفلت الملف أو اختره من جهازك.' },
              { n: '02', icon: Icon.scan, enT: 'Deep analysis', arT: 'تحليل عميق', enD: 'The engine inspects structure, scripts, links, and metadata.', arD: 'يفحص المحرك الهيكل والسكربتات والروابط والبيانات الوصفية.' },
              { n: '03', icon: Icon.layers, enT: 'Get your report', arT: 'احصل على تقريرك', enD: 'See detected threats, a risk score, and any extracted scripts.', arD: 'اطّلع على التهديدات ودرجة الخطورة والسكربتات المستخرجة.' },
            ].map((s, i) => {
              const S = s.icon;
              return (
                <div key={i} className={`tile tile-hover p-7 ${isAr ? 'text-right' : ''}`}>
                  <div className="flex items-center gap-3 mb-4">
                    <span className="grid place-items-center w-11 h-11 rounded-xl border border-white/10 bg-white/[0.04] text-brand-400">
                      <S className="w-5 h-5" />
                    </span>
                    <span className="font-mono text-sm text-brand-400">{s.n}</span>
                  </div>
                  <h3 className="text-lg font-display font-bold mb-2">{isAr ? s.arT : s.enT}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed">{isAr ? s.arD : s.enD}</p>
                </div>
              );
            })}

            {/* Checks tile */}
            <div className="tile p-7 md:col-span-2">
              <h3 className={`text-lg font-display font-bold mb-5 ${isAr ? 'text-right' : 'text-left'}`}>
                {isAr ? 'ما الذي يفحصه المحرك' : 'What the engine checks for'}
              </h3>
              <ul className="grid sm:grid-cols-2 gap-x-8 gap-y-3">
                {[
                  { en: 'Document structure and objects', ar: 'هيكل المستند وكائناته' },
                  { en: 'JavaScript and embedded scripts', ar: 'السكربتات وأكواد جافاسكربت' },
                  { en: 'Suspicious links and URIs', ar: 'الروابط والعناوين المشبوهة' },
                  { en: 'Launch and embedded-file actions', ar: 'إجراءات التشغيل والملفات المضمّنة' },
                  { en: 'Metadata and encoding anomalies', ar: 'شذوذ البيانات الوصفية والترميز' },
                ].map((c, i) => (
                  <li key={i} className={`flex items-center gap-3 text-slate-300 ${isAr ? 'text-right' : ''}`}>
                    <Icon.check className="w-4 h-4 text-brand-400 shrink-0" />
                    <span>{isAr ? c.ar : c.en}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Privacy tile */}
            <div className={`tile p-7 flex flex-col justify-center ${isAr ? 'text-right items-start' : ''}`}>
              <Icon.shieldCheck className="w-7 h-7 text-brand-400 mb-3" />
              <h3 className="text-lg font-display font-bold mb-2">{isAr ? 'خصوصيتك' : 'Your privacy'}</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                {isAr ? 'تتم معالجة ملفك محليًا ولا يُرسَل إلى أي خادم خارجي.' : 'Your file is processed locally and never sent to any third-party server.'}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 glass border-t border-white/10 py-10 px-5 text-center text-sm">
        <div className="font-display text-slate-300">
          Malicious PDF <span className="text-gradient">Detector</span>
        </div>
        <p className="text-slate-400 mt-4">
          {isAr ? 'تم تطويره بواسطة ديالى التركي' : 'Developed by Diyala Alturki'}
        </p>
        <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 mt-4" dir="ltr">
          <a
            href="https://github.com/Diiiyala"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-slate-400 hover:text-white transition"
          >
            <Icon.github className="w-4 h-4" /> Diiiyala
          </a>
          <span className="text-white/15">|</span>
          <a
            href="mailto:diyala.alturki@gmail.com"
            className="flex items-center gap-2 text-slate-400 hover:text-white transition"
          >
            <Icon.mail className="w-4 h-4" /> diyala.alturki@gmail.com
          </a>
        </div>
      </footer>
    </div>
  );
}

export default App;