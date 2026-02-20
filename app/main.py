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
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Log Analyzer</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&family=Audiowide&display=swap" rel="stylesheet"/>
  <style>
    :root{
      --g:#00ff50; --g2:#00cc40; --g3:#004d18;
      --c:#00ffff; --c2:#004444;
      --bg:#020a04; --panel:rgba(0,255,80,.03);
      --border:rgba(0,255,80,.15); --border2:rgba(0,255,80,.08);
      --text:#c8ffd4; --muted:rgba(0,255,80,.4);
      --red:#ff4444; --orange:#ffaa00;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;min-height:100vh;overflow-x:hidden}

    /* arcs */
    .arc-wrap{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
    .arc{position:absolute;border-radius:50%;border:1px solid;bottom:-60%;left:50%;transform:translateX(-50%)}
    .arc1{width:140vw;height:140vw;border-color:rgba(0,255,80,.04)}
    .arc2{width:180vw;height:180vw;border-color:rgba(0,255,80,.025)}
    .arc3{width:220vw;height:220vw;border-color:rgba(0,255,80,.015)}
    .scanlines{position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,255,80,.008) 3px,rgba(0,255,80,.008) 4px);pointer-events:none;z-index:0}

    .wrap{max-width:1000px;margin:0 auto;padding:20px 24px;position:relative;z-index:1}

    /* ── HEADER ── */
    header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border:1px solid var(--border);background:var(--panel);margin-bottom:16px;position:relative}
    header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--g),transparent);opacity:.3}
    .hdr-left{display:flex;align-items:center;gap:16px}
    .hdr-icon{width:42px;height:42px;border:1px solid var(--g);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.2rem;position:relative}
    .hdr-icon::before{content:'';position:absolute;inset:-3px;border-radius:50%;border:1px solid rgba(0,255,80,.2);animation:spin-slow 6s linear infinite}
    @keyframes spin-slow{to{transform:rotate(360deg)}}
    .hdr-title{font-family:'Audiowide',monospace;font-size:1.3rem;color:var(--g);text-shadow:0 0 16px rgba(0,255,80,.5);letter-spacing:3px}
    .hdr-title span{color:var(--c);text-shadow:0 0 16px rgba(0,255,255,.5)}
    .hdr-sub{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--muted);letter-spacing:2px;margin-top:3px}
    .hdr-right{display:flex;gap:20px}
    .hdr-stat{text-align:center}
    .hdr-stat-val{font-family:'Share Tech Mono',monospace;font-size:.85rem;color:var(--g);text-shadow:0 0 8px rgba(0,255,80,.4)}
    .hdr-stat-key{font-family:'Share Tech Mono',monospace;font-size:.52rem;letter-spacing:2px;color:var(--muted);margin-top:2px}
    .hdr-online{display:flex;align-items:center;gap:6px;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--g);letter-spacing:2px}
    .hdr-online-dot{width:7px;height:7px;border-radius:50%;background:var(--g);box-shadow:0 0 8px var(--g);animation:pulse-dot 1.5s ease-in-out infinite}
    @keyframes pulse-dot{0%,100%{transform:scale(1)}50%{transform:scale(1.4)}}

    /* ── MAIN GRID ── */
    .main-grid{display:grid;grid-template-columns:180px 1fr;gap:12px;margin-bottom:12px}

    /* ── SIDEBAR ── */
    .sidebar{display:flex;flex-direction:column;gap:8px}
    .sb-section{border:1px solid var(--border);background:var(--panel);padding:12px}
    .sb-label{font-family:'Share Tech Mono',monospace;font-size:.55rem;letter-spacing:3px;color:var(--muted);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border2)}
    .sb-item{padding:8px 10px;border:1px solid transparent;cursor:pointer;transition:all .2s;margin-bottom:4px}
    .sb-item:hover{border-color:var(--border);background:rgba(0,255,80,.04)}
    .sb-item.on{border-color:rgba(0,255,80,.3);background:rgba(0,255,80,.06)}
    .sb-item-name{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:2px;color:rgba(0,255,80,.6);margin-bottom:3px}
    .sb-item-val{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--g)}
    .sb-bar{height:2px;background:rgba(0,255,80,.1);margin-top:5px;border-radius:1px;overflow:hidden}
    .sb-bar-fill{height:100%;background:var(--g);border-radius:1px;transition:width .6s ease}

    /* ── INPUT PANEL ── */
    .input-panel{border:1px solid var(--border);background:var(--panel)}
    .ip-top{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border2);background:rgba(0,255,80,.02)}
    .ip-label{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:3px;color:var(--muted);display:flex;align-items:center;gap:8px}
    .ip-label::before{content:'◈';color:var(--g);font-size:.7rem}
    .ip-formats{display:flex;gap:6px}
    .fmt-tag{font-family:'Share Tech Mono',monospace;font-size:.52rem;letter-spacing:1px;color:rgba(0,255,80,.4);border:1px solid rgba(0,255,80,.12);padding:2px 7px}
    .ip-body{display:grid;grid-template-columns:1fr 1fr;gap:0}
    .ip-col{padding:16px;position:relative}
    .ip-col+.ip-col{border-right:1px solid var(--border2)}
    .ip-col-label{font-family:'Share Tech Mono',monospace;font-size:.55rem;letter-spacing:3px;color:rgba(0,255,80,.35);margin-bottom:10px}
    .drop-zone{border:1px dashed rgba(0,255,80,.2);padding:24px 16px;text-align:center;cursor:pointer;transition:all .3s;background:rgba(0,255,80,.01);position:relative;min-height:160px;display:flex;flex-direction:column;align-items:center;justify-content:center}
    .drop-zone:hover,.drop-zone.dragover{border-color:rgba(0,255,80,.5);background:rgba(0,255,80,.05);box-shadow:inset 0 0 20px rgba(0,255,80,.04)}
    .drop-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
    .dz-icon{font-size:2rem;margin-bottom:10px;filter:drop-shadow(0 0 8px rgba(0,255,80,.5))}
    .dz-text{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:rgba(0,255,80,.6);letter-spacing:2px}
    .dz-sub{font-size:.62rem;color:rgba(0,255,80,.3);margin-top:5px;letter-spacing:1px}
    .file-badge{display:none;align-items:center;gap:8px;background:rgba(0,255,80,.06);border:1px solid rgba(0,255,80,.2);padding:8px 10px;margin-bottom:8px;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--g)}
    .file-badge.show{display:flex}
    .file-badge button{margin-right:auto;background:none;border:none;color:var(--red);cursor:pointer;font-size:.9rem}
    textarea{width:100%;height:160px;background:#000a03;border:1px solid rgba(0,255,80,.15);color:var(--g);font-family:'Share Tech Mono',monospace;font-size:.72rem;padding:12px;resize:vertical;outline:none;line-height:1.8;direction:ltr;transition:all .3s}
    textarea::placeholder{color:rgba(0,255,80,.2)}
    textarea:focus{border-color:rgba(0,255,80,.4);box-shadow:0 0 0 2px rgba(0,255,80,.06)}

    /* ── COMMAND BAR ── */
    .cmd-bar{display:flex;align-items:center;gap:10px;padding:12px 16px;border:1px solid var(--border);border-top:0;background:rgba(0,0,0,.3)}
    .cmd-prefix{font-family:'Share Tech Mono',monospace;font-size:.65rem;color:rgba(0,255,80,.4);letter-spacing:1px}
    .cmd-status{font-family:'Share Tech Mono',monospace;font-size:.65rem;color:rgba(0,255,80,.5);letter-spacing:1px;flex:1}
    .btn{border:0;cursor:pointer;font-family:'Orbitron',monospace;letter-spacing:2px;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
    .btn-clear{background:transparent;border:1px solid rgba(0,255,80,.2);color:rgba(0,255,80,.5);font-size:.62rem;padding:9px 14px}
    .btn-clear:hover{border-color:rgba(0,255,80,.4);color:var(--g)}
    .btn-analyze{background:var(--g);color:#000;font-size:.7rem;font-weight:700;padding:10px 24px;position:relative;overflow:hidden}
    .btn-analyze::before{content:'';position:absolute;inset:0;background:var(--c);transform:translateX(-101%);transition:transform .3s}
    .btn-analyze:hover::before{transform:translateX(0)}
    .btn-analyze:disabled{opacity:.4;cursor:not-allowed}
    .btn-analyze span{position:relative;z-index:1}
    .err-txt{color:var(--red);font-family:'Share Tech Mono',monospace;font-size:.65rem}

    /* ── LOADER ── */
    .loader{display:none;flex-direction:column;align-items:center;gap:16px;padding:50px}
    .loader.active{display:flex}
    .loader-ring{width:52px;height:52px;position:relative}
    .loader-ring::before{content:'';position:absolute;inset:0;border-radius:50%;border:2px solid rgba(0,255,80,.1)}
    .loader-ring::after{content:'';position:absolute;inset:0;border-radius:50%;border:2px solid transparent;border-top-color:var(--g);animation:spin .7s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .loader-txt{font-family:'Share Tech Mono',monospace;font-size:.72rem;color:var(--muted);letter-spacing:3px;animation:flicker 1.4s ease-in-out infinite}
    @keyframes flicker{0%,100%{opacity:.3}50%{opacity:1}}

    /* ── TIMEOUT BANNER ── */
    .timeout-banner{display:none;align-items:center;gap:14px;border:1px solid rgba(255,170,0,.3);background:rgba(255,170,0,.04);padding:14px 18px;margin-top:12px}
    .timeout-banner.show{display:flex}
    .tb-icon{font-size:1.5rem}
    .tb-body{flex:1}
    .tb-title{font-family:'Orbitron',monospace;font-size:.75rem;letter-spacing:2px;color:var(--orange);margin-bottom:3px}
    .tb-desc{font-family:'Share Tech Mono',monospace;font-size:.65rem;color:rgba(255,170,0,.5);line-height:1.6}
    .tb-tips{padding-inline-start:14px;margin-top:4px;color:rgba(255,170,0,.4);font-size:.62rem;font-family:'Share Tech Mono',monospace}
    .tb-tips li{margin:2px 0}
    .btn-retry{background:rgba(255,170,0,.1);border:1px solid rgba(255,170,0,.3);color:var(--orange);font-family:'Orbitron',monospace;font-size:.6rem;letter-spacing:2px;padding:8px 14px;cursor:pointer;transition:all .2s}
    .btn-retry:hover{background:rgba(255,170,0,.2)}

    /* ── RESULTS ── */
    #results-section{animation:fadeIn .4s ease}
    @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
    .results-hdr{display:flex;align-items:center;gap:10px;padding:10px 16px;border:1px solid var(--border);background:var(--panel);margin-bottom:10px}
    .results-hdr-label{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:3px;color:var(--muted);display:flex;align-items:center;gap:8px;flex:1}
    .results-hdr-label::before{content:'◈';color:var(--g)}
    .results-hdr-dot{width:6px;height:6px;border-radius:50%;background:var(--g);box-shadow:0 0 6px var(--g)}
    .badge{font-family:'Share Tech Mono',monospace;font-size:.6rem;padding:3px 9px;border-radius:2px;font-weight:700}
    .badge-err{background:rgba(255,68,68,.1);color:var(--red);border:1px solid rgba(255,68,68,.2)}
    .badge-warn{background:rgba(255,170,0,.1);color:var(--orange);border:1px solid rgba(255,170,0,.2)}
    .badge-ok{background:rgba(0,255,80,.08);color:var(--g);border:1px solid rgba(0,255,80,.15)}
    .btn-export{background:transparent;border:1px solid rgba(0,255,80,.2);color:rgba(0,255,80,.5);font-family:'Share Tech Mono',monospace;font-size:.58rem;letter-spacing:2px;padding:6px 12px;cursor:pointer;transition:all .2s}
    .btn-export:hover{border-color:rgba(0,255,80,.5);color:var(--g)}

    .results-grid{display:grid;grid-template-columns:1fr;gap:8px}

    /* severity card */
    .sev-card{display:flex;align-items:center;gap:16px;padding:14px 18px;border:1px solid var(--border);background:var(--panel)}
    .sev-icon{font-size:1.8rem}
    .sev-lbl{font-family:'Share Tech Mono',monospace;font-size:.55rem;letter-spacing:3px;color:var(--muted);margin-bottom:4px}
    .sev-val{font-family:'Orbitron',monospace;font-size:1.2rem;font-weight:700}
    .sev-bar-wrap{flex:1;height:6px;background:rgba(0,255,80,.08);border-radius:1px;overflow:hidden;margin-top:5px}
    .sev-bar{height:100%;border-radius:1px;transition:width .8s ease}
    .sev-desc{font-family:'Share Tech Mono',monospace;font-size:.62rem;color:var(--muted);margin-top:4px}
    .sev-low .sev-val{color:var(--g)}.sev-low .sev-bar{background:var(--g);width:33%}
    .sev-medium .sev-val{color:var(--orange)}.sev-medium .sev-bar{background:var(--orange);width:66%}
    .sev-high .sev-val{color:var(--red)}.sev-high .sev-bar{background:var(--red);width:100%;animation:pulse-bar 1.2s ease-in-out infinite}
    @keyframes pulse-bar{0%,100%{opacity:.6}50%{opacity:1}}

    /* result cards */
    .rcard{border:1px solid var(--border);background:var(--panel);padding:14px 16px}
    .rcard-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
    .rcard-title{font-family:'Orbitron',monospace;font-size:.75rem;letter-spacing:2px;color:var(--text)}
    .rtag{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:2px;padding:4px 10px;border-radius:1px;color:#000;font-weight:700}
    .rtag-g{background:var(--g)}.rtag-o{background:var(--orange)}.rtag-r{background:var(--red)}
    pre{white-space:pre-wrap;word-break:break-word;font-family:'Share Tech Mono',monospace;font-size:.72rem;line-height:1.8;color:var(--text)}
    ul{padding-inline-start:16px}
    li{margin:5px 0;font-family:'Share Tech Mono',monospace;font-size:.7rem;line-height:1.6}
    .muted{color:var(--muted)}

    /* highlight */
    .hl-err{color:var(--red);font-weight:700}
    .hl-warn{color:var(--orange)}
    .hl-ok{color:var(--g)}
    .hl-info{color:var(--c)}
    .hl-ts{color:rgba(0,255,80,.4);font-size:.68rem}
    .hl-num{color:#ffd740}
    .hl-path{color:#80cbc4}

    @media(max-width:700px){.main-grid{grid-template-columns:1fr}.ip-body{grid-template-columns:1fr}.sidebar{flex-direction:row;flex-wrap:wrap}.sb-section{flex:1;min-width:140px}}
  </style>
</head>
<body>
<div class="arc-wrap"><div class="arc arc1"></div><div class="arc arc2"></div><div class="arc arc3"></div></div>
<div class="scanlines"></div>

<div class="wrap">

  <!-- HEADER -->
  <header>
    <div class="hdr-left">
      <div class="hdr-icon">⚡</div>
      <div>
        <div class="hdr-title">LOG<span>_</span>ANALYZER</div>
        <div class="hdr-sub">DIAGNOSTIC SYSTEM · v2.0.0 · גרור קובץ לוג או הדבק טקסט</div>
      </div>
    </div>
    <div class="hdr-right">
      <div class="hdr-stat"><div class="hdr-stat-val" id="hdr-format">AUTO</div><div class="hdr-stat-key">FORMAT</div></div>
      <div class="hdr-stat"><div class="hdr-stat-val">&lt;1s</div><div class="hdr-stat-key">LATENCY</div></div>
      <div class="hdr-stat"><div class="hdr-stat-val">v2</div><div class="hdr-stat-key">ENGINE</div></div>
      <div class="hdr-online"><div class="hdr-online-dot"></div>ONLINE</div>
    </div>
  </header>

  <!-- MAIN GRID -->
  <div class="main-grid">

    <!-- SIDEBAR -->
    <div class="sidebar">
      <div class="sb-section">
        <div class="sb-label">◈ ENGINE CONFIG</div>
        <div class="sb-item on">
          <div class="sb-item-name">MODE</div>
          <div class="sb-item-val">AUTO-DETECT</div>
          <div class="sb-bar"><div class="sb-bar-fill" style="width:100%"></div></div>
        </div>
        <div class="sb-item on">
          <div class="sb-item-name">TIMEOUT PRIORITY</div>
          <div class="sb-item-val">■ FIRST</div>
          <div class="sb-bar"><div class="sb-bar-fill" style="width:100%"></div></div>
        </div>
        <div class="sb-item on">
          <div class="sb-item-name">EXCEPTIONS</div>
          <div class="sb-item-val">■ ENABLED</div>
          <div class="sb-bar"><div class="sb-bar-fill" style="width:80%"></div></div>
        </div>
        <div class="sb-item on">
          <div class="sb-item-name">TIMESTAMP</div>
          <div class="sb-item-val">■ EXTRACT</div>
          <div class="sb-bar"><div class="sb-bar-fill" style="width:70%"></div></div>
        </div>
        <div class="sb-item on">
          <div class="sb-item-name">EVENT ID</div>
          <div class="sb-item-val">■ EXTRACT</div>
          <div class="sb-bar"><div class="sb-bar-fill" style="width:70%"></div></div>
        </div>
        <div class="sb-item on">
          <div class="sb-item-name">SERVER NAME</div>
          <div class="sb-item-val">■ EXTRACT</div>
          <div class="sb-bar"><div class="sb-bar-fill" style="width:70%"></div></div>
        </div>
      </div>

      <div class="sb-section">
        <div class="sb-label">◈ FORMATS</div>
        <div class="sb-item on"><div class="sb-item-val">LOG4J XML</div></div>
        <div class="sb-item on"><div class="sb-item-val">PLAIN TEXT</div></div>
        <div class="sb-item on"><div class="sb-item-val">JSON LOGS</div></div>
        <div class="sb-item on"><div class="sb-item-val">IIS / W3C</div></div>
      </div>
    </div>

    <!-- INPUT PANEL -->
    <div>
      <div class="input-panel">
        <div class="ip-top">
          <div class="ip-label">INPUT TERMINAL</div>
          <div class="ip-formats">
            <div class="fmt-tag">.log</div>
            <div class="fmt-tag">.txt</div>
            <div class="fmt-tag">.json</div>
            <div class="fmt-tag">.csv</div>
          </div>
        </div>
        <div class="ip-body">
          <div class="ip-col">
            <div class="ip-col-label">▶ FILE UPLOAD</div>
            <div class="file-badge" id="fileBadge">
              <span>📄</span><span id="fileName"></span><span id="fileSize" style="opacity:.5"></span>
              <button id="removeFile">✕</button>
            </div>
            <div class="drop-zone" id="dropZone">
              <input type="file" id="file" accept=".log,.txt,.json,.csv">
              <div class="dz-icon">📂</div>
              <div class="dz-text">DRAG FILE OR CLICK</div>
              <div class="dz-sub">.log · .txt · .json · .csv</div>
            </div>
          </div>
          <div class="ip-col">
            <div class="ip-col-label">▶ PASTE RAW LOG</div>
            <textarea id="log" placeholder="&gt; PASTE LOG DATA HERE&#10;&gt; AWAITING INPUT..."></textarea>
          </div>
        </div>
      </div>

      <!-- CMD BAR -->
      <div class="cmd-bar">
        <span class="cmd-prefix">CMD &gt;</span>
        <span class="cmd-status" id="status">READY · PASTE OR UPLOAD TO BEGIN</span>
        <button class="btn btn-clear" onclick="clearAll()">🗑 CLEAR</button>
        <button class="btn btn-analyze" id="analyzeBtn" onclick="analyze()"><span>⚡ EXECUTE ANALYSIS</span></button>
      </div>
    </div>
  </div>

  <!-- TIMEOUT BANNER -->
  <div class="timeout-banner" id="timeoutBanner">
    <div class="tb-icon">⏱</div>
    <div class="tb-body">
      <div class="tb-title">REQUEST TIMEOUT</div>
      <div class="tb-desc">הניתוח לקח יותר מדי זמן — הלוג ארוך מדי או עומס על השרת.
        <ul class="tb-tips"><li>קצר את הלוג ל-50–200 שורות</li><li>המתן 30 שניות ונסה שוב</li></ul>
      </div>
    </div>
    <button class="btn-retry" onclick="analyze()">🔄 RETRY</button>
  </div>

  <!-- LOADER -->
  <div class="loader" id="loader">
    <div class="loader-ring"></div>
    <div class="loader-txt" id="loaderText">ANALYZING...</div>
  </div>

  <!-- RESULTS -->
  <div id="results-section" style="display:none">
    <div class="results-hdr">
      <div class="results-hdr-label"><div class="results-hdr-dot"></div>ANALYSIS RESULTS</div>
      <div id="summaryBadges"></div>
      <button class="btn-export" onclick="exportMarkdown()">📝 MD</button>
      <button class="btn-export" onclick="exportPDF()">📄 PDF</button>
    </div>
    <div class="results-grid" id="out"></div>
  </div>

</div>

<script>
var lastResult=null, TIMEOUT_MS=90000;

// Drag & Drop
var dropZone=document.getElementById('dropZone'), fileInput=document.getElementById('file');
['dragenter','dragover'].forEach(function(e){dropZone.addEventListener(e,function(ev){ev.preventDefault();dropZone.classList.add('dragover');});});
['dragleave','drop'].forEach(function(e){dropZone.addEventListener(e,function(ev){ev.preventDefault();dropZone.classList.remove('dragover');});});
dropZone.addEventListener('drop',function(ev){var f=ev.dataTransfer.files[0];if(f)loadFile(f);});
fileInput.addEventListener('change',function(){if(fileInput.files[0])loadFile(fileInput.files[0]);});
document.getElementById('removeFile').addEventListener('click',function(e){
  e.stopPropagation();fileInput.value='';
  document.getElementById('fileBadge').classList.remove('show');
  document.getElementById('log').value='';
});
function loadFile(file){
  var size=file.size>1024*1024?(file.size/1024/1024).toFixed(1)+' MB':(file.size/1024).toFixed(1)+' KB';
  document.getElementById('fileName').textContent=file.name;
  document.getElementById('fileSize').textContent='('+size+')';
  document.getElementById('fileBadge').classList.add('show');
  var ext=file.name.split('.').pop().toUpperCase();
  document.getElementById('hdr-format').textContent=ext||'AUTO';
  var reader=new FileReader();reader.onload=function(e){document.getElementById('log').value=e.target.result;};reader.readAsText(file);
}

// Loader
var loaderMsgs=['ANALYZING...','SCANNING PATTERNS...','DETECTING ERRORS...','BUILDING REPORT...'], li=0, lInt;
function showLoader(){
  document.getElementById('loader').classList.add('active');
  document.getElementById('results-section').style.display='none';
  document.getElementById('timeoutBanner').classList.remove('show');
  document.getElementById('analyzeBtn').disabled=true;
  li=0;lInt=setInterval(function(){document.getElementById('loaderText').textContent=loaderMsgs[li++%loaderMsgs.length];},900);
}
function hideLoader(){document.getElementById('loader').classList.remove('active');document.getElementById('analyzeBtn').disabled=false;clearInterval(lInt);}

// Helpers
function escHtml(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");}
function txt(x){
  if(x==null)return"";if(typeof x==="string")return x;
  if(typeof x==="object"){if("text"in x&&x.text!=null)return String(x.text);if("title"in x)return String(x.title);try{return JSON.stringify(x);}catch(e){return String(x);}}
  return String(x);
}
function sevTagFromSteps(s){
  var t=(s||[]).map(txt).join(" ").toLowerCase();
  if(t.includes("immediately")||t.includes("urgent"))return["דחוף","rtag-r"];
  if(t.includes("check")||t.includes("metrics"))return["בינוני","rtag-o"];
  return["לא דחוף","rtag-g"];
}
function hlText(text){
  return text.split('\n').map(function(line){
    if(!line.trim())return'';
    var low=line.toLowerCase(),cls='';
    if(/\b(error|fatal|exception|critical|timeout)\b/.test(low))cls='hl-err';
    else if(/\bwarn/.test(low))cls='hl-warn';
    else if(/\b(success|ok|done)\b/.test(low))cls='hl-ok';
    else if(/\binfo\b/.test(low))cls='hl-info';
    var out=escHtml(line);
    out=out.replace(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/g,function(m){return'<span class="hl-ts">'+m+'</span>';});
    out=out.replace(/(\/[\w.\-_/]+)/g,function(m){return'<span class="hl-path">'+m+'</span>';});
    out=out.replace(/\b(\d+)(ms|s|KB|MB|GB|%)?\b/g,function(m,n,u){return'<span class="hl-num">'+n+(u||'')+'</span>';});
    return cls?'<span class="'+cls+'">'+out+'</span>':out;
  }).join('\n');
}

// Severity card
function sevCard(score,label){
  var icons={1:'🟢',2:'🟠',3:'🔴'};
  var cls={1:'sev-low',2:'sev-medium',3:'sev-high'};
  var desc={1:'LOW SEVERITY · NO IMMEDIATE IMPACT',2:'MEDIUM SEVERITY · REQUIRES ATTENTION',3:'HIGH SEVERITY · IMMEDIATE ACTION REQUIRED'};
  var s=score||2,l=label||'Medium';
  return'<div class="sev-card '+cls[s]+'"><div class="sev-icon">'+icons[s]+'</div><div style="flex:1"><div class="sev-lbl">SEVERITY SCORE</div><div class="sev-val">'+l+' ('+s+'/3)</div><div class="sev-bar-wrap"><div class="sev-bar"></div></div><div class="sev-desc">'+desc[s]+'</div></div></div>';
}

// Summary badges
function buildBadges(result){
  var t=JSON.stringify(result).toLowerCase();
  var cnt=function(p){return p.reduce(function(a,r){return a+(t.match(r)||[]).length;},0);};
  var e=cnt([/error/g,/fatal/g,/exception/g]),w=cnt([/warn/g]),o=cnt([/success/g]);
  var h='';
  if(e)h+='<span class="badge badge-err">🔴 '+e+' ERR</span> ';
  if(w)h+='<span class="badge badge-warn">🟠 '+w+' WARN</span> ';
  if(o)h+='<span class="badge badge-ok">🟢 '+o+' OK</span>';
  document.getElementById('summaryBadges').innerHTML=h;
}

// Card
function card(title,content,tagLabel,tagCls){
  return'<div class="rcard"><div class="rcard-top"><div class="rcard-title">'+title+'</div><span class="rtag '+tagCls+'">'+tagLabel+'</span></div>'+content+'</div>';
}
function listHtml(items){
  if(!items||!items.length)return'<div class="muted">—</div>';
  return'<ul>'+items.map(function(x){
    if(x&&typeof x==="object"&&x.text!=null){var u=x.urgency?' <span class="muted">('+escHtml(x.urgency)+')</span>':"";return'<li>'+escHtml(x.text)+u+'</li>';}
    return'<li>'+escHtml(txt(x))+'</li>';
  }).join("")+'</ul>';
}

// Render
function render(result){
  lastResult=result;
  var out=document.getElementById("out");
  out.innerHTML="";
  buildBadges(result);
  out.innerHTML+=sevCard(result.severity_score,result.severity_label);
  var st=sevTagFromSteps(result.next_steps);
  var factsHtml=(result.confirmed_facts||[]).length
    ?'<pre>'+hlText((result.confirmed_facts||[]).map(txt).join('\n'))+'</pre>'
    :'<div class="muted">—</div>';
  out.innerHTML+=card("◈ עובדות מאושרות",factsHtml,"לא דחוף","rtag-g");
  out.innerHTML+=card("◈ הכשל הראשי",'<pre>'+hlText(result.primary_failure||"—")+'</pre>',"בינוני","rtag-o");
  out.innerHTML+=card("◈ Root Cause",'<pre>'+hlText(result.root_cause||"—")+'</pre>',"בינוני","rtag-o");
  var hyp=result.hypotheses_ranked||[];
  var hypH=hyp.length?'<ul>'+hyp.map(function(h){return'<li><b>#'+h.rank+'</b> '+escHtml(h.description)+' <span class="muted">— '+escHtml(h.justification||"")+'</span></li>';}).join("")+'</ul>':'<div class="muted">—</div>';
  out.innerHTML+=card("◈ השערות מדורגות",hypH,"בינוני","rtag-o");
  out.innerHTML+=card("◈ NEXT STEPS",listHtml(result.next_steps),st[0],st[1]);
  var conTag=(result.contradictions&&result.contradictions.length)?["דחוף","rtag-r"]:["לא דחוף","rtag-g"];
  out.innerHTML+=card("◈ סתירות / חשודות",listHtml(result.contradictions),conTag[0],conTag[1]);
  document.getElementById('results-section').style.display='block';
}

// Status
function setStatus(msg,isErr){
  var el=document.getElementById("status");
  el.className=isErr?"err-txt":"cmd-status";
  el.textContent=msg||"READY";
}

// Analyze
async function analyze(){
  setStatus("ANALYZING...");showLoader();
  var file=document.getElementById("file").files&&document.getElementById("file").files[0];
  var logText=document.getElementById("log").value&&document.getElementById("log").value.trim();
  var controller=new AbortController();
  var tTimer=setTimeout(function(){controller.abort();},TIMEOUT_MS);
  try{
    var res;
    if(file){
      var fd=new FormData();fd.append("file",file);
      res=await fetch("/analyze-file",{method:"POST",body:fd,signal:controller.signal});
    }else{
      if(!logText){hideLoader();clearTimeout(tTimer);setStatus("ERROR · NO INPUT",true);return;}
      res=await fetch("/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({log:logText}),signal:controller.signal});
    }
    clearTimeout(tTimer);hideLoader();
    if(!res.ok){
      var t=await res.text();
      if(res.status===504||res.status===408||t.toLowerCase().includes('timeout')){setStatus("TIMEOUT",false);document.getElementById('timeoutBanner').classList.add('show');}
      else{setStatus("SERVER ERROR: "+res.status,true);document.getElementById('results-section').style.display='block';document.getElementById("out").innerHTML='<div class="rcard"><div class="hl-err">ERROR '+res.status+'</div><pre style="color:#ff9999">'+escHtml(t)+'</pre></div>';}
      return;
    }
    var data=await res.json();render(data);setStatus("ANALYSIS COMPLETE ✓");
  }catch(e){
    clearTimeout(tTimer);hideLoader();
    if(e.name==='AbortError'){setStatus("TIMEOUT",false);document.getElementById('timeoutBanner').classList.add('show');}
    else{setStatus("NETWORK ERROR: "+(e.message||"CONNECTION FAILED"),true);}
  }
}

// Export
function toMd(r){
  if(!r)return'';
  var lines=['# Log Analysis Report','## Severity: '+(r.severity_label||'')+' ('+(r.severity_score||'')+'/3)',''];
  lines.push('## עובדות מאושרות');(r.confirmed_facts||[]).forEach(function(f){lines.push('- '+txt(f));});
  lines.push('','## הכשל הראשי');lines.push(r.primary_failure||'—');
  lines.push('','## Root Cause');lines.push(r.root_cause||'—');
  lines.push('','## השערות');(r.hypotheses_ranked||[]).forEach(function(h){lines.push(h.rank+'. '+h.description+' — '+(h.justification||''));});
  lines.push('','## Next Steps');(r.next_steps||[]).forEach(function(s){lines.push('- '+txt(s));});
  lines.push('','## סתירות');(r.contradictions||[]).forEach(function(c){lines.push('- '+txt(c));});
  return lines.join('\n');
}
function exportMarkdown(){
  if(!lastResult)return;
  var blob=new Blob([toMd(lastResult)],{type:'text/markdown'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='log-analysis-'+Date.now()+'.md';a.click();
}
function exportPDF(){
  if(!lastResult)return;
  try{
    var jsPDF=window.jspdf.jsPDF,doc=new jsPDF({orientation:'p',unit:'mm',format:'a4'});
    doc.setFont('helvetica','bold');doc.setFontSize(16);doc.setTextColor(0,200,80);doc.text('Log Analysis Report',20,22);
    doc.setFont('helvetica','normal');doc.setFontSize(8.5);
    var lines=doc.splitTextToSize(toMd(lastResult),170),y=34;
    lines.forEach(function(line){
      if(y>280){doc.addPage();y=20;}
      var low=line.toLowerCase();
      if(/error|fatal|timeout/.test(low))doc.setTextColor(220,50,50);
      else if(/warn/.test(low))doc.setTextColor(200,120,0);
      else if(/success|ok/.test(low))doc.setTextColor(0,160,70);
      else if(/^#/.test(line.trim()))doc.setTextColor(0,180,80);
      else doc.setTextColor(30,50,30);
      doc.text(line,20,y);y+=4.8;
    });
    doc.save('log-analysis-'+Date.now()+'.pdf');
  }catch(e){alert('שגיאה ב-PDF. נסה MD.');}
}

// Clear
function clearAll(){
  document.getElementById("log").value="";
  document.getElementById("file").value="";
  document.getElementById("fileBadge").classList.remove('show');
  document.getElementById("out").innerHTML="";
  document.getElementById("results-section").style.display='none';
  document.getElementById("timeoutBanner").classList.remove('show');
  document.getElementById("summaryBadges").innerHTML='';
  document.getElementById("hdr-format").textContent='AUTO';
  setStatus("READY · PASTE OR UPLOAD TO BEGIN");
  lastResult=null;
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
