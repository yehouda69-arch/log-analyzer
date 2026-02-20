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
    body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
    .wrap{max-width:920px;margin:0 auto;padding:28px;position:relative;z-index:1}
    header{text-align:center;margin-bottom:36px}
    .logo-wrap{display:inline-flex;align-items:center;gap:14px;margin-bottom:8px}
    h1{margin:0;font-size:2.6rem;font-weight:900;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-1px}
    .mag{position:relative;width:58px;height:58px;flex-shrink:0}
    .mag-circle{position:absolute;top:0;left:0;width:44px;height:44px;border-radius:50%;border:3.5px solid var(--accent);box-shadow:0 0 16px rgba(0,212,255,.5),inset 0 0 10px rgba(0,212,255,.08);overflow:hidden;background:#050d1a;z-index:2}
    #matrixCanvas{width:100%;height:100%;display:block;border-radius:50%}
    .mag-handle{position:absolute;bottom:2px;right:2px;width:22px;height:5px;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:3px;transform:rotate(45deg);transform-origin:left center;box-shadow:0 0 8px rgba(0,212,255,.4);z-index:1}
    .sub{color:var(--muted);font-size:.95rem}
    .card{background:rgba(15,26,46,.85);border:1px solid var(--border);border-radius:18px;padding:16px;backdrop-filter:blur(4px)}
    .severity-card{display:flex;align-items:center;gap:16px;padding:16px 20px;border-radius:18px;margin-bottom:14px;border:1px solid var(--border);background:rgba(15,26,46,.85);}
    .sev-icon{font-size:2rem}
    .sev-label{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:4px}
    .sev-value{font-size:1.5rem;font-weight:900}
    .sev-bar-wrap{flex:1;height:8px;background:rgba(255,255,255,.08);border-radius:99px;overflow:hidden;margin-top:6px}
    .sev-bar{height:100%;border-radius:99px;transition:width .6s ease}
    .sev-low .sev-value{color:var(--green)}.sev-low .sev-bar{background:var(--green);width:33%}
    .sev-medium .sev-value{color:var(--orange)}.sev-medium .sev-bar{background:var(--orange);width:66%}
    .sev-high .sev-value{color:var(--red)}.sev-high .sev-bar{background:var(--red);width:100%;animation:pulse-bar 1.2s ease-in-out infinite}
    @keyframes pulse-bar{0%,100%{opacity:.7}50%{opacity:1}}
    .drop-zone{border:2px dashed var(--border);border-radius:12px;padding:26px;text-align:center;cursor:pointer;transition:all .3s;position:relative;background:rgba(0,212,255,.02);margin-bottom:4px}
    .drop-zone:hover,.drop-zone.dragover{border-color:var(--accent);background:rgba(0,212,255,.07)}
    .drop-zone.dragover{transform:scale(1.01)}
    .drop-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
    .drop-icon{font-size:1.8rem;margin-bottom:6px}
    .drop-label{color:var(--muted);font-size:.88rem}
    .drop-label strong{color:var(--accent)}
    .file-badge{display:none;align-items:center;gap:8px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:8px 12px;margin-bottom:10px;font-size:.82rem;color:var(--green);font-family:monospace}
    .file-badge.show{display:flex}
    .file-badge button{margin-right:auto;background:none;border:none;color:var(--red);cursor:pointer;font-size:1rem;padding:0 4px}
    .divider{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:.8rem;margin:10px 0}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
    textarea{width:100%;min-height:200px;border:1px solid var(--border);background:#071023;color:var(--text);border-radius:14px;padding:14px;resize:vertical;outline:none;font-family:monospace;font-size:.82rem;line-height:1.7;direction:ltr}
    textarea::placeholder{color:var(--muted)}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .btn{border:0;border-radius:14px;padding:10px 18px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:6px;font-size:.88rem;transition:all .2s}
    .btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 4px 18px rgba(0,212,255,.25)}
    .btn-primary:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 28px rgba(0,212,255,.4)}
    .btn-primary:disabled{opacity:.5;cursor:not-allowed;transform:none}
    .btn-ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
    .btn-ghost:hover{border-color:var(--muted)}
    .btn-export{background:rgba(124,77,255,.12);color:#b39ddb;border:1px solid rgba(124,77,255,.25)}
    .btn-export:hover{background:rgba(124,77,255,.22)}
    .loader{display:none;flex-direction:column;align-items:center;gap:16px;padding:50px 20px}
    .loader.active{display:flex}
    .spinner{width:48px;height:48px;position:relative}
    .spinner::before{content:'';position:absolute;inset:0;border-radius:50%;border:3px solid rgba(0,212,255,.1)}
    .spinner::after{content:'';position:absolute;inset:0;border-radius:50%;border:3px solid transparent;border-top-color:var(--accent);animation:spin .85s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .loader-text{color:var(--muted);font-size:.85rem;font-family:monospace;animation:pulse 1.4s ease-in-out infinite}
    @keyframes pulse{0%,100%{opacity:.3}50%{opacity:1}}
    .timeout-banner{display:none;align-items:center;gap:12px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:12px;padding:14px 18px;margin-top:14px}
    .timeout-banner.show{display:flex}
    .timeout-body{flex:1}
    .timeout-title{font-weight:700;color:var(--orange);margin-bottom:3px;font-size:.95rem}
    .timeout-desc{color:var(--muted);font-size:.82rem;line-height:1.5}
    .timeout-tips{margin:6px 0 0 0;padding-inline-start:16px;color:var(--muted);font-size:.8rem}
    .timeout-tips li{margin:3px 0}
    .btn-retry{background:rgba(245,158,11,.15);color:var(--orange);border:1px solid rgba(245,158,11,.3);border-radius:10px;padding:7px 14px;font-weight:700;cursor:pointer;font-size:.82rem;white-space:nowrap}
    .btn-retry:hover{background:rgba(245,158,11,.25)}
    .results-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 14px;background:rgba(7,16,35,.8);border-radius:12px;margin-bottom:12px;border:1px solid var(--border)}
    .results-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);flex:1;display:flex;align-items:center;gap:6px}
    .results-title .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}
    .badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:.75rem;font-family:monospace;font-weight:700}
    .badge-error{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.2)}
    .badge-warn{background:rgba(245,158,11,.1);color:var(--orange);border:1px solid rgba(245,158,11,.2)}
    .badge-ok{background:rgba(34,197,94,.08);color:var(--green);border:1px solid rgba(34,197,94,.15)}
    .grid{display:grid;grid-template-columns:1fr;gap:14px}
    .title-row{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .tag{font-weight:900;padding:6px 10px;border-radius:999px;color:#0b1220}
    .tag.green{background:var(--green)}.tag.orange{background:var(--orange)}.tag.red{background:var(--red)}
    ul{margin:0;padding-inline-start:18px}
    li{margin:6px 0}
    .muted{color:var(--muted)}
    .err{color:var(--red);font-weight:800}
    pre{white-space:pre-wrap;word-break:break-word;margin:0}
    .hl-error{color:var(--red);font-weight:700}.hl-warn{color:var(--orange);font-weight:600}
    .hl-ok{color:var(--green)}.hl-info{color:var(--accent)}.hl-debug{color:var(--muted)}
    .hl-ts{color:#78909c;font-size:.78rem}.hl-ip{color:#b39ddb}.hl-num{color:#ffd740}.hl-path{color:#80cbc4}
    .section-hdr{display:block;margin:14px 0 6px;padding:5px 10px;background:rgba(0,212,255,.08);border-right:3px solid var(--accent);border-radius:4px;color:var(--accent);font-weight:700;font-size:.82rem;text-transform:uppercase;letter-spacing:.5px}
    #results-section{animation:slideIn .4s ease}
    @keyframes slideIn{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
    @media(max-width:600px){h1{font-size:1.9rem}.row{flex-direction:column;align-items:stretch}}
  </style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo-wrap">
      <h1>Log Analyzer</h1>
      <div class="mag">
        <div class="mag-circle"><canvas id="matrixCanvas"></canvas></div>
        <div class="mag-handle"></div>
      </div>
    </div>
    <div class="sub">גרור קובץ לוג או הדבק טקסט — קבל ניתוח מלא תוך שניות</div>
  </header>

  <div class="card">
    <div class="drop-zone" id="dropZone">
      <input type="file" id="file" accept=".log,.txt,.json,.csv">
      <div class="drop-icon">📂</div>
      <div class="drop-label"><strong>גרור קובץ לכאן</strong> או לחץ לבחירה</div>
      <div class="drop-label" style="font-size:.73rem;margin-top:3px;opacity:.7">.log · .txt · .json · .csv</div>
    </div>
    <div class="file-badge" id="fileBadge">
      <span>📄</span><span id="fileName"></span><span id="fileSize" style="opacity:.6"></span>
      <button id="removeFile">✕</button>
    </div>
    <div class="divider">או הדבק טקסט</div>
    <textarea id="log" placeholder="הדבק כאן את הלוג..."></textarea>
    <div style="height:12px"></div>
    <div class="row">
      <button class="btn btn-primary" id="analyzeBtn" onclick="analyze()">⚡ נתח לוג</button>
      <button class="btn btn-ghost" onclick="clearAll()">🗑 נקה</button>
      <span id="status" class="muted"></span>
    </div>
  </div>

  <div class="timeout-banner" id="timeoutBanner">
    <div style="font-size:1.4rem">⏱️</div>
    <div class="timeout-body">
      <div class="timeout-title">פג זמן הבקשה (Timeout)</div>
      <div class="timeout-desc">הניתוח לקח יותר מדי זמן — הלוג ארוך מדי או עומס על השרת.</div>
      <ul class="timeout-tips">
        <li>קצר את הלוג ל-50–200 שורות</li>
        <li>המתן 30 שניות ונסה שוב</li>
      </ul>
    </div>
    <button class="btn-retry" onclick="analyze()">🔄 נסה שוב</button>
  </div>

  <div class="loader" id="loader">
    <div class="spinner"></div>
    <div class="loader-text" id="loaderText">מנתח לוגים...</div>
  </div>

  <div id="results-section" style="display:none">
    <div class="results-bar">
      <div class="results-title"><span class="dot"></span>תוצאות ניתוח</div>
      <div id="summaryBadges"></div>
      <button class="btn btn-export" onclick="exportMarkdown()">📝 Markdown</button>
      <button class="btn btn-export" onclick="exportPDF()">📄 PDF</button>
    </div>
    <div id="out" class="grid"></div>
  </div>
</div>

<script>
(function(){
  var canvas=document.getElementById('matrixCanvas'),ctx=canvas.getContext('2d'),SIZE=88;
  canvas.width=canvas.height=SIZE;
  var chars='01エラーERROR警WARN0xFF48454C50ABDE',fontSize=7,cols=Math.floor(SIZE/fontSize);
  var drops=Array(cols).fill(0).map(function(){return Math.random()*-15;});
  var colors=['#00d4ff','#00ffcc','#7c4dff','#b39ddb','#00e5ff'];
  setInterval(function(){
    ctx.fillStyle='rgba(5,13,26,0.18)';ctx.fillRect(0,0,SIZE,SIZE);
    ctx.font='bold '+fontSize+'px monospace';
    for(var i=0;i<drops.length;i++){
      var ch=chars[Math.floor(Math.random()*chars.length)];
      if(Math.random()>.88){ctx.fillStyle='#fff';ctx.shadowColor='#00d4ff';ctx.shadowBlur=6;}
      else{ctx.fillStyle=colors[Math.floor(Math.random()*colors.length)];ctx.shadowBlur=0;}
      ctx.fillText(ch,i*fontSize,drops[i]*fontSize);
      if(drops[i]*fontSize>SIZE&&Math.random()>.975)drops[i]=0;
      drops[i]+=0.35+Math.random()*0.3;
    }
  },40);
})();

var lastResult=null,TIMEOUT_MS=90000;

var dropZone=document.getElementById('dropZone'),fileInput=document.getElementById('file');
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

var loaderMsgs=['מנתח לוגים...','מזהה שגיאות...','בודק דפוסים...','מסכם תוצאות...'],loaderInterval;
function showLoader(){
  document.getElementById('loader').classList.add('active');
  document.getElementById('results-section').style.display='none';
  document.getElementById('timeoutBanner').classList.remove('show');
  document.getElementById('analyzeBtn').disabled=true;
  var i=0;loaderInterval=setInterval(function(){document.getElementById('loaderText').textContent=loaderMsgs[i++%loaderMsgs.length];},900);
}
function hideLoader(){document.getElementById('loader').classList.remove('active');document.getElementById('analyzeBtn').disabled=false;clearInterval(loaderInterval);}

function escapeHtml(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");}
function textFromMaybeObj(x){
  if(x==null)return"";if(typeof x==="string")return x;
  if(typeof x==="object"){if("text"in x&&x.text!=null)return String(x.text);if("title"in x&&x.title!=null)return String(x.title);try{return JSON.stringify(x);}catch(e){return String(x);}}
  return String(x);
}
function severityTagFromSteps(s){
  var t=(s||[]).map(textFromMaybeObj).join(" ").toLowerCase();
  if(t.includes("immediately")||t.includes("urgent")||t.includes("rotate")||t.includes("breach"))return["דחוף","red"];
  if(t.includes("check")||t.includes("inspect")||t.includes("validate")||t.includes("metrics"))return["בינוני","orange"];
  return["לא דחוף","green"];
}

function highlightText(text){
  return text.split('\n').map(function(line){
    if(!line.trim())return'';
    if(/^#{1,3}\s/.test(line))return'<span class="section-hdr">'+escapeHtml(line.replace(/^#{1,3}\s/,''))+'</span>';
    var low=line.toLowerCase(),cls='';
    if(/\b(error|fatal|exception|critical|timeout)\b/.test(low))cls='hl-error';
    else if(/\bwarn/.test(low))cls='hl-warn';
    else if(/\b(success|ok|passed|done)\b/.test(low))cls='hl-ok';
    else if(/\binfo\b/.test(low))cls='hl-info';
    else if(/\bdebug\b/.test(low))cls='hl-debug';
    var out=escapeHtml(line);
    out=out.replace(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/g,function(m){return'<span class="hl-ts">'+m+'</span>';});
    out=out.replace(/\b(\d{1,3}\.){3}\d{1,3}\b/g,function(m){return'<span class="hl-ip">'+m+'</span>';});
    out=out.replace(/(\/[\w.\-_/]+)/g,function(m){return'<span class="hl-path">'+m+'</span>';});
    out=out.replace(/\b(\d+)(ms|s|KB|MB|GB|%)?\b/g,function(m,n,u){return'<span class="hl-num">'+n+(u||'')+'</span>';});
    return cls?'<span class="'+cls+'">'+out+'</span>':out;
  }).join('\n');
}

function renderSeverityCard(score,label){
  var icons={1:'🟢',2:'🟠',3:'🔴'};
  var cls={1:'sev-low',2:'sev-medium',3:'sev-high'};
  var desc={1:'חומרה נמוכה — אין השפעה מיידית',2:'חומרה בינונית — דורש בדיקה',3:'חומרה גבוהה — טיפול מיידי נדרש!'};
  var s=score||2,l=label||'Medium';
  return '<div class="severity-card '+cls[s]+'"><div class="sev-icon">'+icons[s]+'</div><div style="flex:1"><div class="sev-label">Severity Score</div><div class="sev-value">'+l+' ('+s+'/3)</div><div class="sev-bar-wrap"><div class="sev-bar"></div></div><div style="font-size:.78rem;color:var(--muted);margin-top:4px">'+desc[s]+'</div></div></div>';
}

function buildSummaryBadges(result){
  var text=JSON.stringify(result).toLowerCase();
  var count=function(p){return p.reduce(function(a,r){return a+(text.match(r)||[]).length;},0);};
  var errors=count([/error/g,/fatal/g,/exception/g]);
  var warns=count([/warn/g]);
  var ok=count([/success/g]);
  var html='';
  if(errors)html+='<span class="badge badge-error">🔴 '+errors+' שגיאות</span> ';
  if(warns)html+='<span class="badge badge-warn">🟠 '+warns+' אזהרות</span> ';
  if(ok)html+='<span class="badge badge-ok">🟢 '+ok+' הצלחות</span>';
  document.getElementById('summaryBadges').innerHTML=html;
}

function card(title,contentHtml,tag){
  var label=tag[0],color=tag[1];
  return'<div class="card"><div class="title-row"><div style="font-size:18px;font-weight:900">'+title+'</div><span class="tag '+color+'">'+label+'</span></div><div style="height:10px"></div>'+contentHtml+'</div>';
}
function list(items){
  if(!items||!items.length)return'<div class="muted">—</div>';
  var html=items.map(function(x){
    if(x&&typeof x==="object"&&x.text!=null){var u=x.urgency?' <span class="muted">('+escapeHtml(x.urgency)+')</span>':"";return'<li>'+escapeHtml(x.text)+u+'</li>';}
    return'<li>'+escapeHtml(textFromMaybeObj(x))+'</li>';
  }).join("");
  return'<ul>'+html+'</ul>';
}

function render(result){
  lastResult=result;
  var out=document.getElementById("out");
  out.innerHTML="";
  buildSummaryBadges(result);
  out.innerHTML+=renderSeverityCard(result.severity_score,result.severity_label);
  var nextStepsTag=severityTagFromSteps(result.next_steps);
  var factsHtml=(result.confirmed_facts||[]).length
    ?'<pre style="font-family:monospace;font-size:.82rem;line-height:1.8">'+highlightText((result.confirmed_facts||[]).map(textFromMaybeObj).join('\n'))+'</pre>'
    :'<div class="muted">—</div>';
  out.innerHTML+=card("עובדות מאושרות ✅",factsHtml,["לא דחוף","green"]);
  out.innerHTML+=card("הכשל הראשי 🎯",'<pre style="font-family:monospace;font-size:.85rem;line-height:1.7">'+highlightText(result.primary_failure||"—")+'</pre>',["בינוני","orange"]);
  out.innerHTML+=card("Root Cause 🧠",'<pre style="font-family:monospace;font-size:.85rem;line-height:1.7">'+highlightText(result.root_cause||"—")+'</pre>',["בינוני","orange"]);
  var hyp=result.hypotheses_ranked||[];
  var hypHtml=hyp.length?'<ul>'+hyp.map(function(h){return'<li><b>#'+h.rank+'</b> '+escapeHtml(h.description)+' <span class="muted">— '+escapeHtml(h.justification||"")+'</span></li>';}).join("")+'</ul>':'<div class="muted">—</div>';
  out.innerHTML+=card("השערות מדורגות 📌",hypHtml,["בינוני","orange"]);
  out.innerHTML+=card("NEXT STEPS ➜",list(result.next_steps),nextStepsTag);
  var conTag=(result.contradictions&&result.contradictions.length)?["דחוף","red"]:["לא דחוף","green"];
  out.innerHTML+=card("סתירות / נקודות חשודות 🧩",list(result.contradictions),conTag);
  document.getElementById('results-section').style.display='block';
}

function setStatus(msg,isErr){var el=document.getElementById("status");el.className=isErr?"err":"muted";el.textContent=msg||"";}
function showTimeoutBanner(){document.getElementById('timeoutBanner').classList.add('show');}

async function analyze(){
  setStatus("מנתח…");showLoader();
  var file=document.getElementById("file").files&&document.getElementById("file").files[0];
  var logText=document.getElementById("log").value&&document.getElementById("log").value.trim();
  var controller=new AbortController();
  var timeoutTimer=setTimeout(function(){controller.abort();},TIMEOUT_MS);
  try{
    var res;
    if(file){
      var fd=new FormData();fd.append("file",file);
      res=await fetch("/analyze-file",{method:"POST",body:fd,signal:controller.signal});
    }else{
      if(!logText){hideLoader();clearTimeout(timeoutTimer);setStatus("תדביק לוג או תעלה קובץ.",true);return;}
      res=await fetch("/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({log:logText}),signal:controller.signal});
    }
    clearTimeout(timeoutTimer);hideLoader();
    if(!res.ok){
      var t=await res.text();
      if(res.status===504||res.status===408||t.toLowerCase().includes('timeout')){setStatus("",false);showTimeoutBanner();}
      else{setStatus("שגיאה מהשרת: "+res.status,true);document.getElementById('results-section').style.display='block';document.getElementById("out").innerHTML='<div class="card"><div class="err">שגיאה</div><pre style="color:#ffb4b4">'+escapeHtml(t)+'</pre></div>';}
      return;
    }
    var data=await res.json();render(data);setStatus("בוצע ✅");
  }catch(e){
    clearTimeout(timeoutTimer);hideLoader();
    if(e.name==='AbortError'){setStatus("",false);showTimeoutBanner();}
    else{setStatus("שגיאת רשת: "+(e.message||"בעיית חיבור"),true);}
  }
}

function resultToMarkdown(r){
  if(!r)return'';
  var lines=['# Log Analysis Report\n','## Severity: '+(r.severity_label||'')+'  ('+(r.severity_score||'')+'  /3)\n'];
  lines.push('## עובדות מאושרות ✅');(r.confirmed_facts||[]).forEach(function(f){lines.push('- '+textFromMaybeObj(f));});
  lines.push('\n## הכשל הראשי 🎯');lines.push(r.primary_failure||'—');
  lines.push('\n## Root Cause 🧠');lines.push(r.root_cause||'—');
  lines.push('\n## השערות 📌');(r.hypotheses_ranked||[]).forEach(function(h){lines.push(h.rank+'. '+h.description+' — '+(h.justification||''));});
  lines.push('\n## NEXT STEPS ➜');(r.next_steps||[]).forEach(function(s){lines.push('- '+textFromMaybeObj(s));});
  lines.push('\n## סתירות 🧩');(r.contradictions||[]).forEach(function(c){lines.push('- '+textFromMaybeObj(c));});
  return lines.join('\n');
}
function exportMarkdown(){
  if(!lastResult)return;
  var blob=new Blob([resultToMarkdown(lastResult)],{type:'text/markdown'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='log-analysis-'+Date.now()+'.md';a.click();
}
function exportPDF(){
  if(!lastResult)return;
  try{
    var jsPDF=window.jspdf.jsPDF,doc=new jsPDF({orientation:'p',unit:'mm',format:'a4'});
    doc.setFont('helvetica','bold');doc.setFontSize(18);doc.setTextColor(0,180,220);doc.text('Log Analysis Report',20,22);
    doc.setFont('helvetica','normal');doc.setFontSize(9);
    var lines=doc.splitTextToSize(resultToMarkdown(lastResult),170),y=34;
    lines.forEach(function(line){
      if(y>280){doc.addPage();y=20;}
      var low=line.toLowerCase();
      if(/error|fatal|timeout/.test(low))doc.setTextColor(220,50,50);
      else if(/warn/.test(low))doc.setTextColor(200,120,0);
      else if(/success|ok/.test(low))doc.setTextColor(0,160,90);
      else if(/^#/.test(line.trim()))doc.setTextColor(0,180,220);
      else doc.setTextColor(50,50,50);
      doc.text(line,20,y);y+=5;
    });
    doc.save('log-analysis-'+Date.now()+'.pdf');
  }catch(e){alert('שגיאה ביצירת PDF. נסה ייצוא Markdown.');}
}

function clearAll(){
  document.getElementById("log").value="";document.getElementById("file").value="";
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
