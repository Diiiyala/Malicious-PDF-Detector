import { useEffect, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import './lightHome.css';


const PATHS = {
  upload: 'M12 16V4m0 0L8 8m4-4l4 4M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2',
  alert: 'M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z',
  check: 'M5 13l4 4L19 7',
  shield: ['M12 3l8 3.5V11c0 5-3.4 9.4-8 10.5C7.4 20.4 4 16 4 11V6.5L12 3z', 'M9 12l2 2 4-4'],
  code: 'M10 20l4-16M18 8l4 4-4 4M6 16l-4-4 4-4',
  globe: ['M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18'],
  link: ['M10 13a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1', 'M14 11a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1'],
  clip: 'M21 11l-8.5 8.5a5 5 0 01-7-7L14 4a3.5 3.5 0 015 5l-8.5 8.5a2 2 0 01-3-3L15 7',
  x: 'M6 18L18 6M6 6l12 12',
  scan: 'M4 8V6a2 2 0 012-2h2M16 4h2a2 2 0 012 2v2M20 16v2a2 2 0 01-2 2h-2M8 20H6a2 2 0 01-2-2v-2M3 12h18',
};

const Ic = ({ n }) => {
  const d = PATHS[n];
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {n === 'globe' && <circle cx="12" cy="12" r="9" />}
      {(Array.isArray(d) ? d : [d]).map((p) => <path key={p} d={p} />)}
    </svg>
  );
};

const COPY = {
  en: {
    nav: ['Home', 'Scan', 'How it works'],
    lang: 'العربية',
    eyebrow: 'PDF safety check',
    h1a: 'Check any PDF ',
    h1b: 'before you open it.',
    lede: 'Upload a file and get a clear verdict in seconds: a risk score, every suspicious indicator, and where it hides.',
    drop: 'Drag & drop a PDF here',
    dropOver: 'Drop the PDF here...',
    note: 'Supports PDF files only',
    choose: 'Choose PDF file',
    tr1: 'Processed locally, never shared',
    tr2: 'Five detectors on every file',
    tooLarge: 'File too large, maximum size is 100 MB.',
    unsupported: (n) => `Sorry, "${n}" is not supported. Please upload PDF files only.`,
    illo: 'Live scan preview',
    tips: { shield: 'Verdict in seconds', js: 'Scripts that run on open', uri: 'Hidden and short links', launch: 'Programs the file can launch', clip: 'Files hidden inside' },
    verdict: 'Malicious', scanning: 'Scanning', tryIt: 'Try it now',
  },
  ar: {
    nav: ['الرئيسية', 'افحص', 'كيف يعمل'],
    lang: 'English',
    eyebrow: 'فحص أمان ملفات PDF',
    h1a: 'افحص أي ملف PDF ',
    h1b: 'قبل أن تفتحه.',
    lede: 'ارفع الملف واحصل على حكم واضح خلال ثوانٍ: نسبة خطورة وكل مؤشر مشبوه وأين يختبئ.',
    drop: 'اسحب ملف PDF وأفلته هنا',
    dropOver: 'أفلت ملف الـ PDF هنا...',
    note: 'يدعم ملفات PDF فقط',
    choose: 'اختر ملف PDF',
    tr1: 'تُعالج محليًا ولا تُشارك',
    tr2: 'خمسة كواشف لكل ملف',
    tooLarge: 'الملف كبير جدًا، الحد الأقصى 100 ميجابايت.',
    unsupported: (n) => `عذراً، الملف "${n}" غير مدعوم. يرجى رفع ملفات PDF فقط.`,
    illo: 'معاينة حية للفحص',
    tips: { shield: 'حكم خلال ثوانٍ', js: 'سكريبتات تعمل عند الفتح', uri: 'روابط مخفية ومختصرة', launch: 'برامج يستطيع الملف تشغيلها', clip: 'ملفات مخبأة بالداخل' },
    verdict: 'خبيث', scanning: 'جاري الفحص', tryIt: 'جرّب الآن',
  },
};

/* ---- animated illustration -------------------------------------------- */
const SWP = [0, 30, 60, 96, 100, 100, 100];
const CURP = [[46, 24], [30, 40], [66, 58], [30, 72], [26, 88], [26, 88], [26, 88]];
const LINES = [96, 88, 92, 70, 94, 84, 90, 66, 80];
const MARKERS = [
  { n: 1, sev: 'high', k: 'js', label: 'JS', pos: { left: '6%', top: '15%', width: '50%', height: '11%' } },
  { n: 2, sev: 'critical', k: 'launch', label: '/Launch', pos: { left: '38%', top: '44%', width: '52%', height: '11%' } },
  { n: 3, sev: 'low', k: 'uri', label: 'URI', pos: { left: '8%', top: '68%', width: '40%', height: '11%' } },
];
const TILES = [
  { k: 'shield', icon: 'shield', color: '#5271FF', pos: { left: '30%', top: '3%' }, delay: 0 },
  { k: 'js', icon: 'code', color: '#F5A524', pos: { left: '62%', top: '2%' }, delay: 0.8 },
  { k: 'uri', icon: 'link', color: '#7C5CF0', pos: { right: 0, top: '38%' }, delay: 1.6 },
  { k: 'launch', icon: 'alert', color: '#EF4B5B', pos: { right: '9%', bottom: '8%' }, delay: 0.4 },
  { k: 'clip', icon: 'clip', color: '#12B5A6', pos: { left: 0, top: '52%' }, delay: 1.2 },
];

const HeroIllustration = ({ c }) => {
  const [step, setStep] = useState(4);

  useEffect(() => {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return undefined;
    const id = setInterval(() => setStep((s) => (s + 1) % 7), 1500);
    return () => clearInterval(id);
  }, []);

  const done = step >= 4;

  return (
    <div className="illo-wrap">
      <div
        className={`illo${done ? ' done' : ''}`}
        role="group"
        aria-label={c.illo}
        data-step={step}
        style={{ '--sw': `${SWP[step]}%`, '--cx': `${CURP[step][0]}%`, '--cy': `${CURP[step][1]}%` }}
      >

        <div className="win" dir="ltr">
          <div className="win-bar"><b>Malicious PDF Detector</b><span className="tb"><i /><i /></span></div>
          <div className="win-body">
            <div className="pg">
              <div className="ln" style={{ width: '52%', height: '1.6cqw', background: '#CDCDCD' }} />
              {LINES.map((w, i) => <div key={i} className="ln" style={{ width: `${w}%` }} />)}
              <div className="sweep" />
              {MARKERS.map((m) => (
                <div key={m.n} className={`mkr${step > 0 && step >= m.n ? ' on' : ''}`} data-n={m.n} data-sev={m.sev} style={m.pos}><em>{m.label}</em></div>
              ))}
            </div>
          </div>
        </div>

        <a className="vc" href="#workspace" style={{ display: 'flex' }}>
          <span className="vc-a"><span className="dot" data-status="danger" /><b>{c.verdict} · <bdi dir="ltr">99%</bdi></b></span>
          <span className="vc-s"><span className="spin" /><b>{c.scanning}…</b></span>
          <span className="mini" data-status="danger"><i style={{ width: '99%' }} /></span>
          <small>{c.tryIt} →</small>
        </a>

        {TILES.map((t) => (
          <span
            key={t.k}
            className="tl"
            data-k={t.k}
            tabIndex={0}
            role="img"
            aria-label={c.tips[t.k]}
            data-tip={c.tips[t.k]}
            style={{ background: t.color, width: '10.5%', aspectRatio: '1', animationDelay: `${t.delay}s`, ...t.pos }}
          >
            <Ic n={t.icon} />
          </span>
        ))}

        <svg className="cur" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 2l16 9-7 2-3 7z" fill="#141414" stroke="#fff" strokeWidth="1.6" strokeLinejoin="round" /></svg>
      </div>
    </div>
  );
};

/* ---- navbar + hero ------------------------------------------------------ */
const scrollToId = (id) => {
  if (!id) { window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
};

export default function LightHome({ isAr, isLoaded, onToggleLang, onFile, onRejected, uploadError, onDismissError }) {
  const c = COPY[isAr ? 'ar' : 'en'];

  const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
    multiple: false,
    accept: { 'application/pdf': ['.pdf'] },
    noClick: true,
    noKeyboard: true,
    onDrop: (files) => onFile(files),
    onDropRejected: onRejected,
  });

  const err = uploadError
    ? (uploadError.type === 'too_large' ? c.tooLarge : c.unsupported(uploadError.fileName))
    : null;

  const links = [null, 'workspace', 'how-it-works'];

  return (
    <div className="lp" dir={isAr ? 'rtl' : 'ltr'}>
      <header className={`topbar${isLoaded ? '' : ' hide'}`} dir="ltr">
        <div className="top-in">
          <button type="button" className="brand" aria-label="Malicious PDF Detector" onClick={() => scrollToId(null)}>
            <b>Malicious PDF <span>Detector</span></b>
          </button>
          <nav className="nav" aria-label="Main">
            {c.nav.map((label, i) => (
              <button type="button" key={label} onClick={() => scrollToId(links[i])}>{label}</button>
            ))}
          </nav>
          <div className="top-r">
            <button type="button" className="lang" onClick={onToggleLang}>
              <Ic n="globe" /><span>{c.lang}</span>
            </button>
          </div>
        </div>
      </header>

      <section className={`band hero${isLoaded ? ' ready' : ''}`}>
        <div className="inner">
          <div className="hero-l">
            <span className="eyebrow"><Ic n="shield" />{c.eyebrow}</span>
            <h1>{c.h1a}<mark className="hi">{c.h1b}</mark></h1>
            <p className="lede">{c.lede}</p>

            <div {...getRootProps({ className: `drop c${isDragActive ? ' over' : ''}`, onClick: open, role: 'button', tabIndex: 0, onKeyDown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } } })}>
              <input {...getInputProps()} />
              <span className="up"><Ic n="upload" /></span>
              <span className="dtxt">
                <b>{isDragActive ? c.dropOver : c.drop}</b>
                <small>{c.note}</small>
              </span>
              <span className="btn pri lg">{c.choose}</span>
            </div>

            {err && (
              <div className="err" role="alert">
                <Ic n="alert" /><span>{err}</span>
                <button type="button" onClick={onDismissError} aria-label="Close"><Ic n="x" /></button>
              </div>
            )}

            <div className="trust">
              <span><Ic n="shield" />{c.tr1}</span>
              <span><Ic n="check" />{c.tr2}</span>
            </div>
          </div>

          <HeroIllustration c={c} />
        </div>
      </section>
    </div>
  );
}
