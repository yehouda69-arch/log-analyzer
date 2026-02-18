from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List

from app.llm import analyze_log  # נשאר כמו שהיה אצלך

app = FastAPI(title="Log Analyzer")

class AnalyzeRequest(BaseModel):
    log: str

@app.get("/", response_class=HTMLResponse)
def home():
    # דף HTML מינימלי שמאפשר להעלות/להדביק לוג ולנתח
    return HTMLResponse("""
<!doctype html>
<html lang="he" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Log Analyzer</title>
  <style>
    :root{
      --bg:#0b1220; --card:#0f1a2e; --text:#e8eefc; --muted:#9fb0d0;
      --border:#233454; --green:#22c55e; --orange:#f59e0b; --red:#ef4444;
    }
    body{margin:0;font-family:system-ui,Segoe UI,Arial;background:linear-gradient(180deg,#070b14, #0b1220);color:var(--text)}
    .wrap{max-width:920px;margin:0 auto;padding:28px}
    h1{margin:0 0 10px;font-size:40px;letter-spacing:.2px}
    .sub{color:var(--muted);margin-bottom:18px}
    .grid{display:grid;grid-template-columns:1fr;gap:14px}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    textarea{width:100%;min-height:220px;border:1px solid var(--border);background:#071023;color:var(--text);
      border-radius:14px;padding:14px;resize:vertical;outline:none}
    .card{background:rgba(15,26,46,.72);border:1px solid var(--border);border-radius:18px;padding:16px}
    .btn{border:0;border-radius:14px;padding:12px 16px;font-weight:700;cursor:pointer}
    .btn-primary{background:#2b6ef2;color:white}
    .btn-ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
    .pill{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;border:1px solid var(--border);color:var(--muted)}
    .k{font-size:13px;color:var(--muted);margin-bottom:8px}
    .title{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .tag{font-weight:800;padding:6px 10px;border-radius:999px;color:#0b1220}
    .tag.green{background:var(--green)}
    .tag.orange{background:var(--orange)}
    .tag.red{background:var(--red)}
    ul{margin:0;padding-inline-start:18px}
    li{margin:6px 0;color:var(--text)}
    .muted{color:var(--muted)}
    .err{color:var(--red);font-weight:700}
    .footer{margin-top:18px;color:var(--muted);font-size:13px}
    input[type=file]{color:var(--muted)}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Log Analyzer</h1>
    <div class="sub">הדבק לוג או העלה קובץ. התוצאה תופיע ככרטיסים ברורים (לא JSON).</div>

    <div class="card">
      <div class="row">
        <span class="pill">📎 העלאת קובץ .log/.txt</span>
        <input id="file" type="file" accept=".log,.txt" />
        <button class="btn btn-ghost" onclick="clearAll()">נקה</button>
      </div>
      <div style="height:10px"></div>
      <div class="k">או הדבק כאן לוג:</div>
      <textarea id="log" placeholder="הדבק כאן את הלוג..."></textarea>
      <div style="height:12px"></div>
      <div class="row">
        <button class="btn btn-primary" onclick="analyze()">Analyze</button>
        <span id="status" class="muted"></span>
      </div>
    </div>

    <div id="out" class="grid" style="margin-top:14px"></div>

    <div class="footer">
      טיפ: אם השירות “נרדם” ב-Render Free, הבקשה הראשונה יכולה לקחת זמן.
    </div>
  </div>

<script>
  function severityTag(text){
    const t = (text || "").toLowerCase();
    // חוקים פשוטים לדוגמה. אפשר לשפר אחר כך:
    if (t.includes("401") || t.includes("unauthorized") || t.includes("503") || t.includes("outage") || t.includes("fatal"))
      return ["דחוף", "red"];
    if (t.includes("timeout") || t.includes("degraded") || t.includes("pool") || t.includes("circuit"))
      return ["בינוני", "orange"];
    return ["לא דחוף", "green"];
  }

  function card(title, contentHtml, tag){
    const [label, color] = tag || ["", "green"];
    return `
      <div class="card">
        <div class="title">
          <div style="font-size:18px;font-weight:900">${title}</div>
          <span class="tag ${color}">${label}</span>
        </div>
        <div style="height:10px"></div>
        ${contentHtml}
      </div>
    `;
  }

  function list(items){
    if(!items || !items.length) return '<div class="muted">—</div>';
    return `<ul>${items.map(x => `<li>${escapeHtml(String(x))}</li>`).join("")}</ul>`;
  }

  function escapeHtml(s){
    return s.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");
  }

  function render(result){
    const out = document.getElementById("out");
    out.innerHTML = "";

    const tag1 = severityTag(result.primary_failure);
    out.innerHTML += card("עובדות מאושרות ✅", list(result.confirmed_facts), ["לא דחוף","green"]);
    out.innerHTML += card("הכשל הראשי 🎯", `<div>${escapeHtml(result.primary_failure || "—")}</div>`, tag1);
    out.innerHTML += card("Root Cause 🧠", `<div>${escapeHtml(result.root_cause || "—")}</div>`, tag1);

    // hypotheses_ranked
    let hyp = result.hypotheses_ranked || [];
    let hypHtml = hyp.length
      ? `<ul>${hyp.map(h => `<li><b>#${h.rank}</b> ${escapeHtml(h.description)} <span class="muted">— ${escapeHtml(h.justification || "")}</span></li>`).join("")}</ul>`
      : `<div class="muted">—</div>`;
    out.innerHTML += card("השערות מדורגות 📌", hypHtml, ["בינוני","orange"]);

    // next steps
    const tagSteps = ["לא דחוף","green"];
    out.innerHTML += card("NEXT STEPS ➜", list(result.next_steps), tagSteps);

    // contradictions
    const tagCon = (result.contradictions && result.contradictions.length) ? ["דחוף","red"] : ["לא דחוף","green"];
    out.innerHTML += card("סתירות / נקודות חשודות 🧩", list(result.contradictions), tagCon);
  }

  function setStatus(msg, isErr=false){
    const el = document.getElementById("status");
    el.className = isErr ? "err" : "muted";
    el.textContent = msg || "";
  }

  async function analyze(){
    setStatus("מנתח…");
    const file = document.getElementById("file").files?.[0];
    const logText = document.getElementById("log").value?.trim();

    try{
      let res;
      if(file){
        const fd = new FormData();
        fd.append("file", file);
        res = await fetch("/analyze-file", { method:"POST", body: fd });
      } else {
        if(!logText){
          setStatus("תדביק לוג או תעלה קובץ.", true);
          return;
        }
        res = await fetch("/analyze", {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          body: JSON.stringify({ log: logText })
        });
      }

      if(!res.ok){
        const t = await res.text();
        setStatus("שגיאה מהשרת: " + res.status, true);
        document.getElementById("out").innerHTML =
          `<div class="card"><div class="err">שגיאה</div><pre style="white-space:pre-wrap;color:#ffb4b4">${escapeHtml(t)}</pre></div>`;
        return;
      }

      const data = await res.json();
      render(data);
      setStatus("בוצע ✅");
    } catch(e){
      setStatus("שגיאת רשת/דפדפן", true);
    }
  }

  function clearAll(){
    document.getElementById("log").value = "";
    document.getElementById("file").value = "";
    document.getElementById("out").innerHTML = "";
    setStatus("");
  }
</script>
</body>
</html>
""")

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    return analyze_log(req.log)

@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    return analyze_log(text)
