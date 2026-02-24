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
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet"/>
  <style>
    :root{
      --c:#00ffff; --g:#00ff50;
      --bg:#000810; --panel:rgba(0,255,255,.03);
      --border-c:rgba(0,255,255,.18); --border-g:rgba(0,255,80,.18);
      --text:#d0f8ff; --muted:rgba(0,255,255,.4);
      --red:#ff4444; --orange:#ffaa00;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;min-height:100vh;overflow-x:hidden}

    .glow-l{position:fixed;top:0;left:-140px;width:480px;height:100vh;background:radial-gradient(ellipse at left,rgba(0,255,255,.07),transparent 70%);pointer-events:none;z-index:0}
    .glow-r{position:fixed;top:0;right:-140px;width:480px;height:100vh;background:radial-gradient(ellipse at right,rgba(0,255,80,.06),transparent 70%);pointer-events:none;z-index:0}
    .grid-lines{position:fixed;inset:0;background-image:linear-gradient(rgba(0,255,255,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,255,.02) 1px,transparent 1px);background-size:60px 60px;pointer-events:none;z-index:0}

    .wrap{max-width:980px;margin:0 auto;padding:24px;position:relative;z-index:1}

    /* ── HEADER ── */
    header{text-align:center;padding:32px 20px 24px;position:relative;margin-bottom:24px}
    .hdr-line-top{position:absolute;top:0;left:50%;transform:translateX(-50%);width:1px;height:32px;background:linear-gradient(180deg,transparent,var(--c))}
    header::after{content:'';position:absolute;bottom:0;left:50%;transform:translateX(-50%);width:200px;height:1px;background:linear-gradient(90deg,transparent,var(--c),transparent)}
    .hdr-eyebrow{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:6px;color:var(--muted);margin-bottom:12px}
    .hdr-title{font-family:'Orbitron',monospace;font-size:2.4rem;font-weight:900;letter-spacing:5px;line-height:1;position:relative;display:inline-block}
    .hdr-sub{font-family:'Share Tech Mono',monospace;font-size:.72rem;color:var(--muted);letter-spacing:2px;margin-top:12px}
    .hdr-status{display:inline-flex;align-items:center;gap:6px;margin-top:10px;font-family:'Share Tech Mono',monospace;font-size:.6rem;color:rgba(0,255,80,.6);letter-spacing:2px}
    .hdr-dot{width:6px;height:6px;border-radius:50%;background:var(--g);box-shadow:0 0 8px var(--g);animation:pulse-dot 1.5s ease-in-out infinite}
    @keyframes pulse-dot{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.5);opacity:.5}}

    /* ── LETTER ANIMATION ── */
    .hdr-title .letter{
      display:inline-block;
      transition:none;
      position:relative;
    }
    .hdr-title .cyan-l{color:var(--c);text-shadow:0 0 30px rgba(0,255,255,.7),0 0 60px rgba(0,255,255,.3)}
    .hdr-title .green-l{color:var(--g);text-shadow:0 0 30px rgba(0,255,80,.7),0 0 60px rgba(0,255,80,.3)}
    .hdr-title .space-l{display:inline-block;width:.4em}

    /* scatter state */
    .hdr-title.scattering .letter{
      animation:none;
    }
    /* reassemble state */
    .hdr-title.reassembling .letter{
      animation:none;
    }
    /* idle glow */
    .hdr-title.idle .cyan-l{color:var(--c);text-shadow:0 0 30px rgba(0,255,255,.7),0 0 60px rgba(0,255,255,.3)}
    .hdr-title.idle .green-l{color:var(--g);text-shadow:0 0 30px rgba(0,255,80,.7),0 0 60px rgba(0,255,80,.3)}

    /* ── INPUT CARD ── */
    .input-card{border:1px solid var(--border-c);background:rgba(0,255,255,.02);position:relative;margin-bottom:12px}
    .input-card::before{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:40%;height:1px;background:linear-gradient(90deg,transparent,var(--c),transparent)}
    .input-card::after{content:'';position:absolute;bottom:-1px;right:-1px;width:14px;height:14px;border-right:2px solid rgba(0,255,80,.4);border-bottom:2px solid rgba(0,255,80,.4)}
    .corner-tl{position:absolute;top:-1px;left:-1px;width:14px;height:14px;border-left:2px solid rgba(0,255,255,.4);border-top:2px solid rgba(0,255,255,.4);z-index:1}

    .ic-top{display:flex;align-items:center;justify-content:space-between;padding:10px 18px;border-bottom:1px solid rgba(0,255,255,.07);background:rgba(0,255,255,.015)}
    .ic-label{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:3px;color:var(--muted);display:flex;align-items:center;gap:8px}
    .ic-label::before{content:'◈';color:var(--c)}
    .fmt-tags{display:flex;gap:5px}
    .fmt{font-family:'Share Tech Mono',monospace;font-size:.52rem;color:rgba(0,255,255,.3);border:1px solid rgba(0,255,255,.1);padding:2px 7px;letter-spacing:1px}

    .ic-body{display:grid;grid-template-columns:1fr 1fr;position:relative}
    .split-line{position:absolute;top:8%;left:50%;transform:translateX(-50%);width:1px;height:84%;background:linear-gradient(180deg,transparent,rgba(0,255,255,.25) 30%,rgba(0,255,80,.25) 70%,transparent)}
    .ic-col{padding:20px}
    .ic-col-lbl{font-family:'Share Tech Mono',monospace;font-size:.56rem;letter-spacing:3px;color:rgba(0,255,255,.3);margin-bottom:12px;display:flex;align-items:center;gap:6px}
    .ic-col-lbl::before{content:'▶';font-size:.5rem;color:rgba(0,255,255,.4)}

    .drop-zone{border:1px solid rgba(0,255,255,.13);padding:28px 16px;text-align:center;cursor:pointer;transition:all .3s;background:rgba(0,255,255,.01);min-height:176px;display:flex;flex-direction:column;align-items:center;justify-content:center;position:relative}
    .drop-zone:hover,.drop-zone.dragover{border-color:rgba(0,255,255,.5);background:rgba(0,255,255,.05);box-shadow:inset 0 0 24px rgba(0,255,255,.04),0 0 24px rgba(0,255,255,.07)}
    .drop-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
    .dz-icon{font-size:2.4rem;margin-bottom:12px;filter:drop-shadow(0 0 12px rgba(0,255,255,.6))}
    .dz-text{font-family:'Share Tech Mono',monospace;font-size:.74rem;color:rgba(0,255,255,.65);letter-spacing:2px}
    .dz-sub{font-size:.63rem;color:rgba(0,255,255,.3);margin-top:6px;letter-spacing:1px}
    .file-badge{display:none;align-items:center;gap:8px;background:rgba(0,255,80,.06);border:1px solid rgba(0,255,80,.2);padding:7px 10px;margin-bottom:8px;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--g)}
    .file-badge.show{display:flex}
    .file-badge button{margin-right:auto;background:none;border:none;color:var(--red);cursor:pointer;font-size:1rem}

    textarea{width:100%;height:176px;background:#000d18;border:1px solid rgba(0,255,255,.1);color:var(--c);font-family:'Share Tech Mono',monospace;font-size:.76rem;padding:13px;resize:vertical;outline:none;line-height:1.9;direction:ltr;transition:all .3s}
    textarea::placeholder{color:rgba(0,255,255,.18)}
    textarea:focus{border-color:rgba(0,255,255,.4);box-shadow:0 0 0 2px rgba(0,255,255,.05),inset 0 0 20px rgba(0,255,255,.02)}

    .ic-footer{display:flex;align-items:center;justify-content:space-between;padding:11px 18px;border-top:1px solid rgba(0,255,255,.07);background:rgba(0,0,0,.35)}
    .ic-info{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:rgba(0,255,255,.28);letter-spacing:1px;line-height:1.8}
    .ic-info b{color:rgba(0,255,80,.5)}
    .btns{display:flex;gap:10px;align-items:center}
    .status-txt{font-family:'Share Tech Mono',monospace;font-size:.62rem;color:var(--muted);letter-spacing:1px}
    .err-txt{color:var(--red);font-family:'Share Tech Mono',monospace;font-size:.62rem}

    .btn-clear{background:transparent;border:1px solid rgba(0,255,255,.18);color:rgba(0,255,255,.4);font-family:'Share Tech Mono',monospace;font-size:.62rem;letter-spacing:2px;padding:9px 14px;cursor:pointer;transition:all .2s}
    .btn-clear:hover{border-color:rgba(0,255,255,.45);color:var(--c)}

    .btn-analyze{background:transparent;border:1px solid var(--c);color:var(--c);font-family:'Orbitron',monospace;font-size:.68rem;font-weight:700;letter-spacing:3px;padding:10px 26px;cursor:pointer;position:relative;overflow:hidden;transition:color .3s}
    .btn-analyze::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,var(--c),var(--g));transform:scaleX(0);transform-origin:right;transition:transform .3s}
    .btn-analyze:hover::before{transform:scaleX(1);transform-origin:left}
    .btn-analyze:hover{color:#000}
    .btn-analyze:disabled{opacity:.3;cursor:not-allowed}
    .btn-analyze span{position:relative;z-index:1}

    .timeout-banner{display:none;align-items:center;gap:14px;border:1px solid rgba(255,170,0,.25);background:rgba(255,170,0,.03);padding:14px 18px;margin-bottom:12px;position:relative}
    .timeout-banner::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(255,170,0,.4),transparent)}
    .timeout-banner.show{display:flex}
    .tb-body{flex:1}
    .tb-title{font-family:'Orbitron',monospace;font-size:.72rem;letter-spacing:2px;color:var(--orange);margin-bottom:4px}
    .tb-desc{font-family:'Share Tech Mono',monospace;font-size:.63rem;color:rgba(255,170,0,.45);line-height:1.7}
    .tb-tips{padding-inline-start:14px;margin-top:4px;color:rgba(255,170,0,.35);font-size:.6rem;font-family:'Share Tech Mono',monospace}
    .tb-tips li{margin:2px 0}
    .btn-retry{background:rgba(255,170,0,.07);border:1px solid rgba(255,170,0,.25);color:var(--orange);font-family:'Orbitron',monospace;font-size:.6rem;letter-spacing:2px;padding:9px 16px;cursor:pointer;transition:all .2s;white-space:nowrap}
    .btn-retry:hover{background:rgba(255,170,0,.15)}

    .loader{display:none;flex-direction:column;align-items:center;gap:18px;padding:54px}
    .loader.active{display:flex}
    .loader-rings{position:relative;width:52px;height:52px}
    .loader-rings::before{content:'';position:absolute;inset:0;border-radius:50%;border:2px solid rgba(0,255,255,.08)}
    .loader-rings::after{content:'';position:absolute;inset:0;border-radius:50%;border:2px solid transparent;border-top-color:var(--c);border-right-color:rgba(0,255,80,.4);animation:spin .8s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .loader-txt{font-family:'Share Tech Mono',monospace;font-size:.72rem;color:var(--muted);letter-spacing:3px;animation:flicker 1.4s ease-in-out infinite}
    @keyframes flicker{0%,100%{opacity:.2}50%{opacity:1}}

    #results-section{animation:fadeUp .4s ease}
    @keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}

    .results-hdr{display:flex;align-items:center;gap:10px;padding:10px 16px;border:1px solid var(--border-c);background:rgba(0,255,255,.02);margin-bottom:10px;position:relative}
    .results-hdr::before{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,255,.15),transparent)}
    .rh-label{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:3px;color:var(--muted);display:flex;align-items:center;gap:8px;flex:1}
    .rh-dot{width:6px;height:6px;border-radius:50%;background:var(--g);box-shadow:0 0 8px var(--g)}
    .badge{font-family:'Share Tech Mono',monospace;font-size:.6rem;padding:3px 9px;font-weight:700;border-radius:1px}
    .badge-err{background:rgba(255,68,68,.1);color:var(--red);border:1px solid rgba(255,68,68,.2)}
    .badge-warn{background:rgba(255,170,0,.1);color:var(--orange);border:1px solid rgba(255,170,0,.2)}
    .badge-ok{background:rgba(0,255,80,.07);color:var(--g);border:1px solid rgba(0,255,80,.15)}
    .btn-export{background:transparent;border:1px solid rgba(0,255,255,.13);color:rgba(0,255,255,.38);font-family:'Share Tech Mono',monospace;font-size:.57rem;letter-spacing:2px;padding:5px 12px;cursor:pointer;transition:all .2s}
    .btn-export:hover{border-color:rgba(0,255,255,.4);color:var(--c)}

    .results-grid{display:grid;gap:8px}

    .sev-card{display:flex;align-items:center;gap:16px;padding:16px 20px;border:1px solid var(--border-c);background:rgba(0,255,255,.02);position:relative}
    .sev-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,255,.2),transparent)}
    .sev-stripe{width:3px;height:52px;border-radius:2px;flex-shrink:0}
    .sev-low .sev-stripe{background:var(--g);box-shadow:0 0 10px var(--g)}
    .sev-medium .sev-stripe{background:var(--orange);box-shadow:0 0 10px var(--orange)}
    .sev-high .sev-stripe{background:var(--red);box-shadow:0 0 10px var(--red);animation:stripe-pulse 1.2s ease-in-out infinite}
    @keyframes stripe-pulse{0%,100%{opacity:.5}50%{opacity:1}}
    .sev-icon{font-size:1.8rem}
    .sev-lbl{font-family:'Share Tech Mono',monospace;font-size:.55rem;letter-spacing:3px;color:var(--muted);margin-bottom:4px}
    .sev-val{font-family:'Orbitron',monospace;font-size:1.2rem;font-weight:700}
    .sev-low .sev-val{color:var(--g);text-shadow:0 0 12px rgba(0,255,80,.5)}
    .sev-medium .sev-val{color:var(--orange);text-shadow:0 0 12px rgba(255,170,0,.5)}
    .sev-high .sev-val{color:var(--red);text-shadow:0 0 12px rgba(255,68,68,.5)}
    .sev-bar-wrap{flex:1;height:5px;background:rgba(0,255,255,.06);border-radius:1px;overflow:hidden;margin-top:6px}
    .sev-bar{height:100%;border-radius:1px;transition:width .8s ease}
    .sev-low .sev-bar{background:var(--g);width:33%}
    .sev-medium .sev-bar{background:var(--orange);width:66%}
    .sev-high .sev-bar{background:var(--red);width:100%}
    .sev-desc{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--muted);margin-top:4px}

    .rcard{border:1px solid var(--border-c);background:rgba(0,255,255,.018);padding:16px 18px;position:relative;transition:border-color .2s}
    .rcard:hover{border-color:rgba(0,255,255,.3)}
    .rcard::before{content:'';position:absolute;top:0;left:20px;right:20px;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,255,.12),transparent)}
    .rcard-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
    .rcard-title{font-family:'Orbitron',monospace;font-size:.88rem;letter-spacing:2px;color:var(--text)}
    .rtag{font-family:'Share Tech Mono',monospace;font-size:.6rem;letter-spacing:2px;padding:4px 10px;color:#000;font-weight:700;border-radius:1px}
    .rtag-g{background:var(--g)}.rtag-o{background:var(--orange)}.rtag-r{background:var(--red)}
    pre{white-space:pre-wrap;word-break:break-word;font-family:'Share Tech Mono',monospace;font-size:.88rem;line-height:1.9;color:var(--text)}
    ul{padding-inline-start:16px}
    li{margin:6px 0;font-family:'Share Tech Mono',monospace;font-size:.86rem;line-height:1.7}
    .muted{color:var(--muted)}

    .hl-err{color:var(--red);font-weight:700}
    .hl-warn{color:var(--orange)}
    .hl-ok{color:var(--g)}
    .hl-info{color:var(--c)}
    .hl-ts{color:rgba(0,255,255,.32);font-size:.75rem}
    .hl-num{color:#ffd740}
    .hl-path{color:#80cbc4}

    @media(max-width:680px){
      .ic-body{grid-template-columns:1fr}
      .split-line{display:none}
      .hdr-title{font-size:1.7rem}
    }
  </style>
</head>
<body>
<div class="glow-l"></div>
<div class="glow-r"></div>
<div class="grid-lines"></div>

<div class="wrap">

  <!-- HEADER -->
  <header>
    <div class="hdr-line-top"></div>
    <div class="hdr-eyebrow">DIAGNOSTIC INTERFACE · v2.0.0</div>
    <div class="hdr-title idle" id="hdrTitle"></div>
    <div class="hdr-sub">גרור קובץ לוג או הדבק טקסט — קבל ניתוח מלא תוך שניות</div>
    <div><div class="hdr-status"><div class="hdr-dot"></div>ENGINE ONLINE · SMART TRIM ACTIVE</div></div>
  </header>

  <!-- INPUT CARD -->
  <div class="input-card">
    <div class="corner-tl"></div>
    <div class="ic-top">
      <div class="ic-label">INPUT TERMINAL</div>
      <div class="fmt-tags">
        <div class="fmt">.log</div><div class="fmt">.txt</div><div class="fmt">.json</div><div class="fmt">.csv</div>
      </div>
    </div>
    <div class="ic-body">
      <div class="split-line"></div>
      <div class="ic-col">
        <div class="ic-col-lbl">FILE UPLOAD</div>
        <div class="file-badge" id="fileBadge">
          <span>📄</span><span id="fileName"></span><span id="fileSize" style="opacity:.5"></span>
          <button id="removeFile">✕</button>
        </div>
        <div class="drop-zone" id="dropZone">
          <input type="file" id="file" accept=".log,.txt,.json,.csv">
          <div class="dz-icon">📂</div>
          <div class="dz-text">גרור קובץ לכאן</div>
          <div class="dz-sub">.log · .txt · .json · .csv</div>
        </div>
      </div>
      <div class="ic-col">
        <div class="ic-col-lbl">PASTE RAW LOG</div>
        <textarea id="log" placeholder="> הדבק כאן את הלוג..."></textarea>
      </div>
    </div>
    <div class="ic-footer">
      <div class="ic-info">
        <div>■ TIMEOUT PRIORITY · <b>FIRST</b> &nbsp;|&nbsp; SMART TRIM · <b>ACTIVE</b></div>
        <div>■ סורק את כל הלוג — שגיאה בשורה 2500 תתפס</div>
      </div>
      <div class="btns">
        <span id="status" class="status-txt"></span>
        <button class="btn-clear" onclick="clearAll()">🗑 נקה</button>
        <button class="btn-analyze" id="analyzeBtn" onclick="analyze()"><span>⚡ נתח לוג</span></button>
      </div>
    </div>
  </div>

  <!-- TIMEOUT BANNER -->
  <div class="timeout-banner" id="timeoutBanner">
    <div style="font-size:1.5rem">⏱</div>
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
    <div class="loader-rings"></div>
    <div class="loader-txt" id="loaderText">ANALYZING...</div>
  </div>

  <!-- RESULTS -->
  <div id="results-section" style="display:none">
    <div class="results-hdr">
      <div class="rh-label"><div class="rh-dot"></div>ANALYSIS RESULTS</div>
      <div id="summaryBadges"></div>
      <button class="btn-export" onclick="exportMarkdown()">📝 MD</button>
      <button class="btn-export" onclick="exportPDF()">📄 PDF</button>
    </div>
    <div class="results-grid" id="out"></div>
  </div>

</div>

<script>
/* ══════════════════════════════════════════
   LETTER SCATTER / REASSEMBLE ANIMATION
   ══════════════════════════════════════════ */
var WORDS = [
  {text:'LOG',   cls:'cyan-l'},
  {text:' ',     cls:'space-l'},
  {text:'ANALYZER', cls:'green-l'}
];

var titleEl = document.getElementById('hdrTitle');
var letterEls = [];

// Build letter spans
(function buildTitle(){
  WORDS.forEach(function(w){
    if(w.cls === 'space-l'){
      var sp = document.createElement('span');
      sp.className = 'letter space-l';
      sp.innerHTML = '&nbsp;';
      titleEl.appendChild(sp);
      letterEls.push(sp);
    } else {
      w.text.split('').forEach(function(ch){
        var s = document.createElement('span');
        s.className = 'letter ' + w.cls;
        s.textContent = ch;
        titleEl.appendChild(s);
        letterEls.push(s);
      });
    }
  });
})();

var scatterInterval = null;
var isScattering = false;

function scatterLetters(){
  isScattering = true;
  titleEl.classList.remove('idle','reassembling');
  titleEl.classList.add('scattering');

  letterEls.forEach(function(el, i){
    var delay = Math.random() * 300;
    var tx = (Math.random() - 0.5) * 260;
    var ty = (Math.random() - 0.5) * 120;
    var rot = (Math.random() - 0.5) * 720;
    var scale = Math.random() * 0.4 + 0.1;

    setTimeout(function(){
      el.style.transition = 'transform 0.4s cubic-bezier(0.55,0,1,0.45), opacity 0.4s ease';
      el.style.transform = 'translate('+tx+'px,'+ty+'px) rotate('+rot+'deg) scale('+scale+')';
      el.style.opacity = '0.08';
    }, delay);
  });

  // Keep re-shuffling while analyzing
  scatterInterval = setInterval(function(){
    if(!isScattering) return;
    var idx = Math.floor(Math.random() * letterEls.length);
    var el = letterEls[idx];
    var tx = (Math.random() - 0.5) * 260;
    var ty = (Math.random() - 0.5) * 120;
    var rot = (Math.random() - 0.5) * 720;
    var scale = Math.random() * 0.5 + 0.1;
    el.style.transition = 'transform 0.6s ease, opacity 0.6s ease';
    el.style.transform = 'translate('+tx+'px,'+ty+'px) rotate('+rot+'deg) scale('+scale+')';
    el.style.opacity = String(Math.random() * 0.25 + 0.05);
  }, 180);
}

function reassembleLetters(onDone){
  isScattering = false;
  clearInterval(scatterInterval);
  titleEl.classList.remove('scattering');
  titleEl.classList.add('reassembling');

  letterEls.forEach(function(el, i){
    var delay = i * 38 + Math.random() * 40;
    setTimeout(function(){
      el.style.transition = 'transform 0.55s cubic-bezier(0.175,0.885,0.32,1.275), opacity 0.45s ease';
      el.style.transform = 'translate(0,0) rotate(0deg) scale(1)';
      el.style.opacity = '1';
    }, delay);
  });

  var totalTime = letterEls.length * 38 + 300;
  setTimeout(function(){
    titleEl.classList.remove('reassembling');
    titleEl.classList.add('idle');
    if(onDone) onDone();
  }, totalTime);
}

/* ══════════════════════════════════════════
   EXISTING APP LOGIC
   ══════════════════════════════════════════ */
var lastResult=null, TIMEOUT_MS=90000;

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
  var reader=new FileReader();reader.onload=function(e){document.getElementById('log').value=e.target.result;};reader.readAsText(file);
}

var loaderMsgs=['ANALYZING...','SCANNING PATTERNS...','DETECTING ERRORS...','BUILDING REPORT...'],li=0,lInt;
function showLoader(){
  document.getElementById('loader').classList.add('active');
  document.getElementById('results-section').style.display='none';
  document.getElementById('timeoutBanner').classList.remove('show');
  document.getElementById('analyzeBtn').disabled=true;
  li=0;lInt=setInterval(function(){document.getElementById('loaderText').textContent=loaderMsgs[li++%loaderMsgs.length];},900);
  scatterLetters();
}
function hideLoader(){
  document.getElementById('loader').classList.remove('active');
  document.getElementById('analyzeBtn').disabled=false;
  clearInterval(lInt);
  reassembleLetters();
}

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

function sevCard(score,label){
  var icons={1:'🟢',2:'🟠',3:'🔴'};
  var cls={1:'sev-low',2:'sev-medium',3:'sev-high'};
  var desc={1:'LOW SEVERITY · NO IMMEDIATE IMPACT',2:'MEDIUM SEVERITY · REQUIRES ATTENTION',3:'HIGH SEVERITY · IMMEDIATE ACTION REQUIRED'};
  var s=score||2,l=label||'Medium';
  return'<div class="sev-card '+cls[s]+'"><div class="sev-stripe"></div><div class="sev-icon">'+icons[s]+'</div><div style="flex:1"><div class="sev-lbl">SEVERITY SCORE</div><div class="sev-val">'+l+' ('+s+'/3)</div><div class="sev-bar-wrap"><div class="sev-bar"></div></div><div class="sev-desc">'+desc[s]+'</div></div></div>';
}

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
  out.innerHTML+=card("עובדות מאושרות ✅",factsHtml,"לא דחוף","rtag-g");
  out.innerHTML+=card("הכשל הראשי 🎯",'<pre>'+hlText(result.primary_failure||"—")+'</pre>',"בינוני","rtag-o");
  out.innerHTML+=card("Root Cause 🧠",'<pre>'+hlText(result.root_cause||"—")+'</pre>',"בינוני","rtag-o");
  var hyp=result.hypotheses_ranked||[];
  var hypH=hyp.length?'<ul>'+hyp.map(function(h){return'<li><b>#'+h.rank+'</b> '+escHtml(h.description)+' <span class="muted">— '+escHtml(h.justification||"")+'</span></li>';}).join("")+'</ul>':'<div class="muted">—</div>';
  out.innerHTML+=card("השערות מדורגות 📌",hypH,"בינוני","rtag-o");
  out.innerHTML+=card("NEXT STEPS ➜",listHtml(result.next_steps),st[0],st[1]);
  var conTag=(result.contradictions&&result.contradictions.length)?["דחוף","rtag-r"]:["לא דחוף","rtag-g"];
  out.innerHTML+=card("סתירות / נקודות חשודות 🧩",listHtml(result.contradictions),conTag[0],conTag[1]);
  document.getElementById('results-section').style.display='block';
}

function setStatus(msg,isErr){
  var el=document.getElementById("status");
  el.className=isErr?"err-txt":"status-txt";
  el.textContent=msg||"";
}

async function analyze(){
  setStatus("מנתח…");showLoader();
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
      if(!logText){hideLoader();clearTimeout(tTimer);setStatus("תדביק לוג או תעלה קובץ.",true);return;}
      res=await fetch("/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({log:logText}),signal:controller.signal});
    }
    clearTimeout(tTimer);hideLoader();
    if(!res.ok){
      var t=await res.text();
      if(res.status===504||res.status===408||t.toLowerCase().includes('timeout')){setStatus("",false);document.getElementById('timeoutBanner').classList.add('show');}
      else{setStatus("שגיאה: "+res.status,true);document.getElementById('results-section').style.display='block';document.getElementById("out").innerHTML='<div class="rcard"><div class="hl-err">ERROR '+res.status+'</div><pre style="color:#ff9999">'+escHtml(t)+'</pre></div>';}
      return;
    }
    var data=await res.json();render(data);setStatus("בוצע ✅");
  }catch(e){
    clearTimeout(tTimer);hideLoader();
    if(e.name==='AbortError'){setStatus("",false);document.getElementById('timeoutBanner').classList.add('show');}
    else{setStatus("שגיאת רשת: "+(e.message||""),true);}
  }
}

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
    doc.setFont('helvetica','bold');doc.setFontSize(16);doc.setTextColor(0,200,220);doc.text('Log Analysis Report',20,22);
    doc.setFont('helvetica','normal');doc.setFontSize(8.5);
    var lines=doc.splitTextToSize(toMd(lastResult),170),y=34;
    lines.forEach(function(line){
      if(y>280){doc.addPage();y=20;}
      var low=line.toLowerCase();
      if(/error|fatal|timeout/.test(low))doc.setTextColor(220,50,50);
      else if(/warn/.test(low))doc.setTextColor(200,120,0);
      else if(/success|ok/.test(low))doc.setTextColor(0,180,80);
      else if(/^#/.test(line.trim()))doc.setTextColor(0,180,220);
      else doc.setTextColor(20,40,50);
      doc.text(line,20,y);y+=4.8;
    });
    doc.save('log-analysis-'+Date.now()+'.pdf');
  }catch(e){alert('שגיאה ב-PDF.');}
}

function clearAll(){
  document.getElementById("log").value="";
  document.getElementById("file").value="";
  document.getElementById("fileBadge").classList.remove('show');
  document.getElementById("out").innerHTML="";
  document.getElementById("results-section").style.display='none';
  document.getElementById("timeoutBanner").classList.remove('show');
  document.getElementById("summaryBadges").innerHTML='';
  setStatus("");lastResult=null;
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
