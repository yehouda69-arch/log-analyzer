from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.llm import analyze_log

app = FastAPI(title="Log Analyzer", version="1.0.0")


class AnalyzeRequest(BaseModel):
    log: str


HTML = r"""
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
      --blue:#2b6ef2;
    }
    body{margin:0;font-family:system-ui,Segoe UI,Arial;background:linear-gradient(180deg,#070b14, #0b1220);color:var(--text)}
    .wrap{max-width:920px;margin:0 auto;padding:28px}
    h1{margin:0 0 10px;font-size:40px}
    .sub{color:var(--muted);margin-bottom:18px}
    .grid{display:grid;grid-template-columns:1fr;gap:14px}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    textarea{width:100%;min-height:220px;border:1px solid var(--border);background:#071023;color:var(--text);
      border-radius:14px;padding:14px;resize:vertical;outline:none}
    .card{background:rgba(15,26,46,.72);border:1px solid var(--border);border-radius:18px;padding:16px}
    .btn{border:0;border-radius:14px;padding:12px 16px;font-weight:700;cursor:pointer}
    .btn-primary{background:var(--blue);color:white}
    .btn-ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
    .pill{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;border:1px solid var(--border);color:var(--muted)}
    .k{font-size:13px;color:var(--muted);margin-bottom:8px}
    .title{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .tag{font-weight:900;padding:6px 10px;border-radius:999px;color:#0b1220}
    .tag.green{background:var(--green)}
    .tag.orange{background:var(--orange)}
    .tag.red{background:var(--red)}
    ul{margin:0;padding-inline-start:18px}
    li{margin:6px 0}
    .muted{color:var(--muted)}
    .err{color:var(--red);font-weight:800}
    input[type=file]{color:var(--muted)}
    pre{white-space:pre-wrap;word-break:break-word;margin:0}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Log Analyzer</h1>
    <div class="sub">מדביקים לוג או מעלים קובץ → Analyze → מקבלים תוצאה “יפה” (לא JSON).</div>

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
  </div>

<script>
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
    if (text.includes("immediately") || text.includes("urgent") || text.includes("rotate") || text.includes("breach")) return ["דחוף","red"];
    if (text.includes("check") || text.includes("inspect") || text.includes("validate") || text.includes("metrics")) return ["בינוני","orange"];
    return ["לא דחוף","green"];
  }

  function card(title, contentHtml, tag){
    const [label, color] = tag || ["לא דחוף","green"];
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
    const out = document.getElementById("out");
    out.innerHTML = "";

    const nextStepsTag = severityTagFromSteps(result.next_steps);

    out.innerHTML += card("עובדות מאושרות ✅", list(result.confirmed_facts), ["לא דחוף","green"]);
    out.innerHTML += card("הכשל הראשי 🎯", `<div>${escapeHtml(result.primary_failure || "—")}</div>`, ["בינוני","orange"]);
    out.innerHTML += card("Root Cause 🧠", `<div>${escapeHtml(result.root_cause || "—")}</div>`, ["בינוני","orange"]);

    const hyp = result.hypotheses_ranked || [];
    const hypHtml = hyp.length
      ? `<ul>${hyp.map(h => `<li><b>#${h.rank}</b> ${escapeHtml(h.description)} <span class="muted">— ${escapeHtml(h.justification || "")}</span></li>`).join("")}</ul>`
      : `<div class="muted">—</div>`;
    out.innerHTML += card("השערות מדורגות 📌", hypHtml, ["בינוני","orange"]);

    // NEXT STEPS – עם צבע לפי דחיפות
    out.innerHTML += card("NEXT STEPS ➜", list(result.next_steps), nextStepsTag);

    const conTag = (result.contradictions && result.contradictions.length) ? ["דחוף","red"] : ["לא דחוף","green"];
    out.innerHTML += card("סתירות / נקודות חשודות 🧩", list(result.contradictions), conTag);
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
          `<div class="card"><div class="err">שגיאה</div><pre style="color:#ffb4b4">${escapeHtml(t)}</pre></div>`;
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
