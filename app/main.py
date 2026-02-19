from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.llm import analyze_log

app = FastAPI(title="Log Analyzer", version="2.0.0")


class AnalyzeRequest(BaseModel):
    log: str


HTML = r"""
<!doctype html>
<html lang="he" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Log Analyzer</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <style>
    :root{
      --bg:#0b1220; --card:#0f1a2e; --text:#e8eefc; --muted:#9fb0d0;
      --border:#233454; --green:#22c55e; --orange:#f59e0b; --red:#ef4444;
      --blue:#2b6ef2; --accent:#00d4ff; --accent2:#7c4dff;
    }

    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,Segoe UI,Arial;background:linear-gradient(180deg,#070b14,#0b1220);color:var(--text);min-height:100vh}

    /* Grid overlay */
    body::before{
      content:'';position:fixed;inset:0;
      background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);
      background-size:40px 40px;pointer-events:none;z-index:0
    }

    .wrap{max-width:920px;margin:0 auto;padding:28px;position:relative;z-index:1}

    /* Header */
    header{text-align:center;margin-bottom:36px}
    h1{margin:0 0 6px;font-size:2.6rem;font-weight:900;
      background:linear-gradient(135deg,var(--accent),var(--accent2));
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
      letter-spacing:-1px}
    .sub{color:var(--muted);margin-bottom:0;font-size:.95rem}

    .grid{display:grid;grid-template-columns:1fr;gap:14px}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}

    /* Card */
    .card{background:rgba(15,26,46,.85);border:1px solid var(--border);border-radius:18px;padding:16px;backdrop-filter:blur(4px)}

    /* Drop Zone */
    .drop-zone{
      border:2px dashed var(--border);border-radius:12px;padding:26px;
      text-align:center;cursor:pointer;transition:all .3s;position:relative;
      background:rgba(0,212,255,.02);margin-bottom:4px
    }
    .drop-zone:hover,.drop-zone.dragover{border-color:var(--accent);background:rgba(0,212,255,.07);box-shadow:inset 0 0 30px rgba(0,212,255,.05)}
    .drop-zone.dragover{transform:scale(1.01)}
    .drop-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
    .drop-icon{font-size:1.8rem;margin-bottom:6px}
    .drop-label{color:var(--muted);font-size:.88rem}
    .drop-label strong{color:var(--accent)}

    /* File badge */
    .file-badge{
      display:none;align-items:center;gap:8px;
      background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);
      border-radius:8px;padding:8px 12px;margin-bottom:10px;
      font-size:.82rem;color:var(--green);font-family:monospace
    }
    .file-badge.show{display:flex}
    .file-badge button{margin-right:auto;background:none;border:none;color:var(--red);cursor:pointer;font-size:1rem;padding:0 4px}

    /* Divider */
    .divider{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:.8rem;margin:10px 0}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}

    textarea{
      width:100%;min-height:200px;border:1px solid var(--border);
      background:#071023;color:var(--text);border-radius:14px;
      padding:14px;resize:vertical;outline:none;
      font-family:monospace;font-size:.82rem;line-height:1.7;direction:ltr
    }
    textarea::placeholder{color:var(--muted)}

    /* Buttons */
    .btn{border:0;border-radius:14px;padding:10px 18px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:6px;font-size:.88rem;transition:all .2s}
    .btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 4px 18px rgba(0,212,255,.25)}
    .btn-primary:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 28px rgba(0,212,255,.4)}
    .btn-primary:disabled{opacity:.5;cursor:not-allowed;transform:none}
    .btn-ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
    .btn-ghost:hover{border-color:var(--muted)}
    .btn-export{background:rgba(124,77,255,.12);color:#b39ddb;border:1px solid rgba(124,77,255,.25)}
    .btn-export:hover{background:rgba(124,77,255,.22)}

    /* Spinner */
    .loader{display:none;flex-direction:column;align-items:center;gap:16px;padding:50px 20px}
    .loader.active{display:flex}
    .spinner{width:48px;height:48px;position:relative}
    .spinner::before{content:'';position:absolute;inset:0;border-radius:50%;border:3px solid rgba(0,212,255,.1)}
    .spinner::after{content:'';position:absolute;inset:0;border-radius:50%;border:3px solid transparent;border-top-color:var(--accent);animation:spin .85s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .loader-text{color:var(--muted);font-size:.85rem;font-family:monospace;animation:pulse 1.4s ease-in-out infinite}
    @keyframes pulse{0%,100%{opacity:.3}50%{opacity:1}}

    /* Results toolbar */
    .results-bar{
      display:flex;align-items:center;gap:8px;flex-wrap:wrap;
      padding:10px 14px;background:rgba(7,16,35,.8);border-radius:12px;
      margin-bottom:12px;border:1px solid var(--border)
    }
    .results-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);flex:1;display:flex;align-items:center;gap:6px}
    .results-title .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}

    /* Summary badges */
    .badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:.75rem;font-family:monospace;font-weight:700}
    .badge-error{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.2)}
    .badge-warn{background:rgba(245,158,11,.1);color:var(--orange);border:1px solid rgba(245,158,11,.2)}
    .badge-info{background:rgba(0,212,255,.08);color:var(--accent);border:1px solid rgba(0,212,255,.15)}
    .badge-ok{background:rgba(34,197,94,.08);color:var(--green);border:1px solid rgba(34,197,94,.15)}

    /* Result cards */
    .pill{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;border:1px solid var(--border);color:var(--muted)}
    .k{font-size:13px;color:var(--muted);margin-bottom:8px}
    .title-row{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .tag{font-weight:900;padding:6px 10px;border-radius:999px;color:#0b1220}
    .tag.green{background:var(--green)}.tag.orange{background:var(--orange)}.tag.red{background:var(--red)}
    ul{margin:0;padding-inline-start:18px}
    li{margin:6px 0}
    .muted{color:var(--muted)}
    .err{color:var(--red);font-weight:800}
    pre{white-space:pre-wrap;word-break:break-word;margin:0}

    /* Syntax highlight classes */
    .hl-error{color:var(--red);font-weight:700}
    .hl-warn{color:var(--orange);font-weight:600}
    .hl-ok{color:var(--green)}
    .hl-info{color:var(--accent)}
    .hl-debug{color:var(--muted)}
    .hl-ts{color:#78909c;font-size:.78rem}
    .hl-ip{color:#b39ddb}
    .hl-num{color:#ffd740}
    .hl-path{color:#80cbc4}
    .hl-key{color:var(--accent2);font-weight:600}
    .section-hdr{
      display:block;margin:14px 0 6px;padding:5px 10px;
      background:rgba(0,212,255,.08);border-right:3px solid var(--accent);
      border-radius:4px;color:var(--accent);font-weight:700;
      font-size:.82rem;text-transform:uppercase;letter-spacing:.5px
    }

    /* Result slide-in */
    #results-section{animation:slideIn .4s ease}
    @keyframes slideIn{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}

    @media(max-width:600px){h1{font-size:1.9rem}.row{flex-direction:column;align-items:stretch}}
  </style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <header>
    <h1>🔍 Log Analyzer</h1>
    <div class="sub">גרור קובץ לוג או הדבק טקסט — קבל ניתוח מלא תוך שניות</div>
  </header>

  <!-- Input Card -->
  <div class="card">

    <!-- Drag & Drop -->
    <div class="drop-zone" id="dropZone">
      <input type="file" id="file" accept=".log,.txt,.json,.csv">
      <div class="drop-icon">📂</div>
      <div class="drop-label"><strong>גרור קובץ לכאן</strong> או לחץ לבחירה</div>
      <div class="drop-label" style="font-size:.73rem;margin-top:3px;opacity:.7">.log · .txt · .json · .csv</div>
    </div>

    <!-- File badge -->
    <div class="file-badge" id="fileBadge">
      <span>📄</span>
      <span id="fileName"></span>
      <span id="fileSize" style="opacity:.6"></span>
      <button id="removeFile" title="הסר קובץ">✕</button>
    </div>

    <div class="divider">או הדבק טקסט</div>

    <textarea id="log" placeholder="[2024-01-15 10:23:45] ERROR: Connection refused&#10;[2024-01-15 10:23:46] WARN: Retry attempt 1/3&#10;..."></textarea>

    <div style="height:12px"></div>
    <div class="row">
      <button class="btn btn-primary" id="analyzeBtn" onclick="analyze()">⚡ נתח לוג</button>
      <button class="btn btn-ghost" onclick="clearAll()">🗑 נקה</button>
      <span id="status" class="muted"></span>
    </div>
  </div>

  <!-- Loader -->
  <div class="loader" id="loader">
    <div class="spinner"></div>
    <div class="loader-text" id="loaderText">מנתח לוגים...</div>
  </div>

  <!-- Results Section -->
  <div id="results-section" style="display:none">

    <!-- Toolbar with export buttons -->
    <div class="results-bar">
      <div class="results-title"><span class="dot"></span>תוצאות ניתוח</div>
      <div id="summaryBadges"></div>
      <button class="btn btn-export" onclick="exportMarkdown()" title="ייצא כ-Markdown">📝 Markdown</button>
      <button class="btn btn-export" onclick="exportPDF()" title="ייצא כ-PDF">📄 PDF</button>
    </div>

    <div id="out" class="grid"></div>
  </div>

</div>

<script>
// ─── State ────────────────────────────────────────────────────
let lastResult = null;

// ─── Drag & Drop ──────────────────────────────────────────────
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('file');

['dragenter','dragover'].forEach(e =>
  dropZone.addEventListener(e, ev => { ev.preventDefault(); dropZone.classList.add('dragover'); }));
['dragleave','drop'].forEach(e =>
  dropZone.addEventListener(e, ev => { ev.preventDefault(); dropZone.classList.remove('dragover'); }));

dropZone.addEventListener('drop', ev => {
  const f = ev.dataTransfer.files[0];
  if (f) loadFile(f);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) loadFile(fileInput.files[0]);
});
document.getElementById('removeFile').addEventListener('click', e => {
  e.stopPropagation();
  fileInput.value = '';
  document.getElementById('fileBadge').classList.remove('show');
  document.getElementById('log').value = '';
});

function loadFile(file) {
  const size = file.size > 1024*1024
    ? (file.size/1024/1024).toFixed(1)+' MB'
    : (file.size/1024).toFixed(1)+' KB';
  document.getElementById('fileName').textContent = file.name;
  document.getElementById('fileSize').textContent = '('+size+')';
  document.getElementById('fileBadge').classList.add('show');
  const reader = new FileReader();
  reader.onload = e => { document.getElementById('log').value = e.target.result; };
  reader.readAsText(file);
}

// ─── Loader ───────────────────────────────────────────────────
const loaderMsgs = ['מנתח לוגים...','מזהה שגיאות...','בודק דפוסים...','מסכם תוצאות...'];
let loaderInterval;

function showLoader() {
  document.getElementById('loader').classList.add('active');
  document.getElementById('results-section').style.display = 'none';
  document.getElementById('analyzeBtn').disabled = true;
  let i = 0;
  loaderInterval = setInterval(() => {
    document.getElementById('loaderText').textContent = loaderMsgs[i++ % loaderMsgs.length];
  }, 900);
}

function hideLoader() {
  document.getElementById('loader').classList.remove('active');
  document.getElementById('analyzeBtn').disabled = false;
  clearInterval(loaderInterval);
}

// ─── Helpers ──────────────────────────────────────────────────
function escapeHtml(s){
  return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");
}

function textFromMaybeObj(x){
  if (x == null) return "";
  if (typeof x === "string") return x;
  if (typeof x === "object"){
    if ("text" in x && x.text != null) return String(x.text);
    if ("title" in x && x.title != null) return String(x.title);
    try { return JSON.stringify(x); } catch(e) { return String(x); }
  }
  return String(x);
}

function severityTagFromSteps(nextSteps){
  const text = (nextSteps || []).map(textFromMaybeObj).join(" ").toLowerCase();
  if (text.includes("immediately")||text.includes("urgent")||text.includes("rotate")||text.includes("breach")) return ["דחוף","red"];
  if (text.includes("check")||text.includes("inspect")||text.includes("validate")||text.includes("metrics")) return ["בינוני","orange"];
  return ["לא דחוף","green"];
}

// ─── Syntax Highlighting ──────────────────────────────────────
function highlightText(text){
  return text.split('\n').map(line => {
    if (!line.trim()) return '';
    // Section headers
    if (/^#{1,3}\s/.test(line))
      return `<span class="section-hdr">${escapeHtml(line.replace(/^#{1,3}\s/,''))}</span>`;

    const low = line.toLowerCase();
    let cls = '';
    if (/\b(error|fatal|exception|critical)\b/.test(low)) cls = 'hl-error';
    else if (/\bwarn/.test(low)) cls = 'hl-warn';
    else if (/\b(success|ok|passed|done)\b/.test(low)) cls = 'hl-ok';
    else if (/\binfo\b/.test(low)) cls = 'hl-info';
    else if (/\bdebug\b/.test(low)) cls = 'hl-debug';

    let out = escapeHtml(line);
    out = out.replace(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/g, m => `<span class="hl-ts">${m}</span>`);
    out = out.replace(/\b(\d{1,3}\.){3}\d{1,3}\b/g, m => `<span class="hl-ip">${m}</span>`);
    out = out.replace(/(\/[\w.\-_/]+)/g, m => `<span class="hl-path">${m}</span>`);
    out = out.replace(/\b(\d+)(ms|s|KB|MB|GB|%)?\b/g, (m,n,u) => `<span class="hl-num">${n}${u||''}</span>`);

    return cls ? `<span class="${cls}">${out}</span>` : out;
  }).join('\n');
}

// ─── Summary badges ───────────────────────────────────────────
function buildSummaryBadges(result){
  const text = JSON.stringify(result).toLowerCase();
  const count = (patterns) => patterns.reduce((a,p) => a+(text.match(p)||[]).length, 0);
  const errors = count([/error/g,/fatal/g,/exception/g]);
  const warns  = count([/warn/g]);
  const ok     = count([/success/g]);
  let html = '';
  if (errors) html += `<span class="badge badge-error">🔴 ${errors} שגיאות</span> `;
  if (warns)  html += `<span class="badge badge-warn">🟠 ${warns} אזהרות</span> `;
  if (ok)     html += `<span class="badge badge-ok">🟢 ${ok} הצלחות</span>`;
  document.getElementById('summaryBadges').innerHTML = html;
}

// ─── Render ───────────────────────────────────────────────────
function card(title, contentHtml, tag){
  const [label, color] = tag || ["לא דחוף","green"];
  return `
    <div class="card">
      <div class="title-row">
        <div style="font-size:18px;font-weight:900">${title}</div>
        <span class="tag ${color}">${label}</span>
      </div>
      <div style="height:10px"></div>
      ${contentHtml}
    </div>
  `;
}

function list(items){
  if (!items || !items.length) return '<div class="muted">—</div>';
  const html = items.map(x => {
    if (x && typeof x === "object" && x.text != null){
      const u = x.urgency ? ` <span class="muted">(${escapeHtml(x.urgency)})</span>` : "";
      return `<li>${escapeHtml(x.text)}${u}</li>`;
    }
    return `<li>${escapeHtml(textFromMaybeObj(x))}</li>`;
  }).join("");
  return `<ul>${html}</ul>`;
}

function render(result){
  lastResult = result;
  const out = document.getElementById("out");
  out.innerHTML = "";

  buildSummaryBadges(result);

  const nextStepsTag = severityTagFromSteps(result.next_steps);

  // Confirmed facts with syntax highlighting
  const factsHtml = (result.confirmed_facts||[]).length
    ? `<pre style="font-family:monospace;font-size:.82rem;line-height:1.8">${highlightText((result.confirmed_facts||[]).map(textFromMaybeObj).join('\n'))}</pre>`
    : '<div class="muted">—</div>';
  out.innerHTML += card("עובדות מאושרות ✅", factsHtml, ["לא דחוף","green"]);

  const primaryHtml = `<pre style="font-family:monospace;font-size:.85rem;line-height:1.7">${highlightText(result.primary_failure||"—")}</pre>`;
  out.innerHTML += card("הכשל הראשי 🎯", primaryHtml, ["בינוני","orange"]);

  const rcHtml = `<pre style="font-family:monospace;font-size:.85rem;line-height:1.7">${highlightText(result.root_cause||"—")}</pre>`;
  out.innerHTML += card("Root Cause 🧠", rcHtml, ["בינוני","orange"]);

  const hyp = result.hypotheses_ranked || [];
  const hypHtml = hyp.length
    ? `<ul>${hyp.map(h => `<li><b>#${h.rank}</b> ${escapeHtml(h.description)} <span class="muted">— ${escapeHtml(h.justification||"")}</span></li>`).join("")}</ul>`
    : `<div class="muted">—</div>`;
  out.innerHTML += card("השערות מדורגות 📌", hypHtml, ["בינוני","orange"]);

  out.innerHTML += card("NEXT STEPS ➜", list(result.next_steps), nextStepsTag);

  const conTag = (result.contradictions&&result.contradictions.length) ? ["דחוף","red"] : ["לא דחוף","green"];
  out.innerHTML += card("סתירות / נקודות חשודות 🧩", list(result.contradictions), conTag);

  document.getElementById('results-section').style.display = 'block';
}

// ─── Analyze ──────────────────────────────────────────────────
function setStatus(msg, isErr=false){
  const el = document.getElementById("status");
  el.className = isErr ? "err" : "muted";
  el.textContent = msg || "";
}

async function analyze(){
  setStatus("מנתח…");
  showLoader();

  const file = document.getElementById("file").files?.[0];
  const logText = document.getElementById("log").value?.trim();

  try{
    let res;
    if(file){
      const fd = new FormData();
      fd.append("file", file);
      res = await fetch("/analyze-file", { method:"POST", body: fd });
    } else {
      if(!logText){ hideLoader(); setStatus("תדביק לוג או תעלה קובץ.", true); return; }
      res = await fetch("/analyze", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ log: logText })
      });
    }

    hideLoader();

    if(!res.ok){
      const t = await res.text();
      setStatus("שגיאה מהשרת: " + res.status, true);
      document.getElementById('results-section').style.display = 'block';
      document.getElementById("out").innerHTML =
        `<div class="card"><div class="err">שגיאה</div><pre style="color:#ffb4b4">${escapeHtml(t)}</pre></div>`;
      return;
    }

    const data = await res.json();
    render(data);
    setStatus("בוצע ✅");
  } catch(e){
    hideLoader();
    setStatus("שגיאת רשת/דפדפן", true);
  }
}

// ─── Export ───────────────────────────────────────────────────
function resultToMarkdown(r){
  if (!r) return '';
  const lines = ['# Log Analysis Report\n'];

  lines.push('## עובדות מאושרות ✅');
  (r.confirmed_facts||[]).forEach(f => lines.push('- ' + textFromMaybeObj(f)));

  lines.push('\n## הכשל הראשי 🎯');
  lines.push(r.primary_failure || '—');

  lines.push('\n## Root Cause 🧠');
  lines.push(r.root_cause || '—');

  lines.push('\n## השערות מדורגות 📌');
  (r.hypotheses_ranked||[]).forEach(h => lines.push(`${h.rank}. ${h.description} — ${h.justification||''}`));

  lines.push('\n## NEXT STEPS ➜');
  (r.next_steps||[]).forEach(s => lines.push('- ' + textFromMaybeObj(s)));

  lines.push('\n## סתירות 🧩');
  (r.contradictions||[]).forEach(c => lines.push('- ' + textFromMaybeObj(c)));

  return lines.join('\n');
}

function exportMarkdown(){
  if (!lastResult) return;
  const md = resultToMarkdown(lastResult);
  const blob = new Blob([md], {type:'text/markdown'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'log-analysis-' + Date.now() + '.md';
  a.click();
}

function exportPDF(){
  if (!lastResult) return;
  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation:'p', unit:'mm', format:'a4' });

    doc.setFont('helvetica','bold');
    doc.setFontSize(18);
    doc.setTextColor(0,180,220);
    doc.text('Log Analysis Report', 20, 22);

    doc.setFont('helvetica','normal');
    doc.setFontSize(9);

    const md = resultToMarkdown(lastResult);
    const lines = doc.splitTextToSize(md, 170);
    let y = 34;
    lines.forEach(line => {
      if (y > 280) { doc.addPage(); y = 20; }
      const low = line.toLowerCase();
      if (/error|fatal/.test(low)) doc.setTextColor(220,50,50);
      else if (/warn/.test(low)) doc.setTextColor(200,120,0);
      else if (/success|ok/.test(low)) doc.setTextColor(0,160,90);
      else if (/^#/.test(line.trim())) doc.setTextColor(0,180,220);
      else doc.setTextColor(50,50,50);
      doc.text(line, 20, y);
      y += 5;
    });

    doc.save('log-analysis-' + Date.now() + '.pdf');
  } catch(e) {
    alert('שגיאה ביצירת PDF. נסה ייצוא Markdown.');
  }
}

// ─── Clear ────────────────────────────────────────────────────
function clearAll(){
  document.getElementById("log").value = "";
  document.getElementById("file").value = "";
  document.getElementById("fileBadge").classList.remove('show');
  document.getElementById("out").innerHTML = "";
  document.getElementById("results-section").style.display = 'none';
  document.getElementById("summaryBadges").innerHTML = '';
  setStatus("");
  lastResult = null;
}
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(HTML)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    return analyze_log(req.log)


@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    return analyze_log(text)
