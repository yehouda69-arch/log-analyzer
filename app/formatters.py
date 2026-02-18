from app.schemas import LogAnalysisResponse


def _urgency_badge(u: str) -> str:
    # low=green, medium=orange, high=red
    return {
        "low": "badge low",
        "medium": "badge med",
        "high": "badge high",
    }.get(u, "badge med")


def to_html(result: LogAnalysisResponse, title: str = "Log Analysis") -> str:
    def li(items):
        return "".join(f"<li>{x}</li>" for x in items) if items else "<li><i>None</i></li>"

    hypos = "".join(
        f"<li><b>{h.rank}. {h.description}</b><br/><small>{h.justification}</small></li>"
        for h in result.hypotheses_ranked
    ) or "<li><i>None</i></li>"

    steps = "".join(
        f"""
        <div class="step">
          <span class="{_urgency_badge(s.urgency)}">{s.urgency.upper()}</span>
          <div class="steptext">{s.text}</div>
        </div>
        """
        for s in result.next_steps
    ) or "<div class='muted'>None</div>"

    sev_class = {1: "sev low", 2: "sev med", 3: "sev high"}.get(result.severity_score, "sev med")

    return f"""<!doctype html>
<html lang="he">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      background: radial-gradient(1200px 800px at 20% 10%, #1b2a4a 0%, #0b1220 45%, #070b14 100%);
      color: #eaf0ff;
      direction: rtl;
    }}
    .wrap {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px 18px 60px;
    }}
    .topbar {{
      display:flex; justify-content:space-between; align-items:center;
      gap: 12px; flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    h1 {{
      margin: 0;
      font-size: 34px;
      letter-spacing: 0.2px;
    }}
    .pill {{
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.10);
      display:flex; align-items:center; gap:10px;
    }}
    .sev {{
      padding: 6px 10px;
      border-radius: 999px;
      font-weight: 700;
      border: 1px solid rgba(255,255,255,0.16);
    }}
    .sev.low {{ background: rgba(34,197,94,0.15); color:#bbf7d0; }}
    .sev.med {{ background: rgba(249,115,22,0.15); color:#fed7aa; }}
    .sev.high {{ background: rgba(239,68,68,0.15); color:#fecaca; }}

    .grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}

    .card {{
      background: rgba(17,26,46,0.78);
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: 16px;
      padding: 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
      overflow: hidden;
    }}
    .card h2 {{
      margin: 0 0 10px;
      font-size: 18px;
      display:flex; align-items:center; gap:10px;
    }}
    .muted {{ color:#b8c3dd; }}
    ul {{ margin: 8px 0 0 18px; }}
    small {{ color:#b8c3dd; }}

    .mono {{
      font-family: Consolas, monospace;
      background: rgba(0,0,0,0.25);
      border: 1px solid rgba(255,255,255,0.08);
      padding: 10px 12px;
      border-radius: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
    }}

    .steps {{
      display:flex;
      flex-direction: column;
      gap: 10px;
    }}
    .step {{
      display:flex;
      align-items:flex-start;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(0,0,0,0.18);
    }}
    .steptext {{ line-height: 1.35; }}

    .badge {{
      font-size: 12px;
      font-weight: 800;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.18);
      min-width: 72px;
      text-align: center;
    }}
    .badge.low {{ background: rgba(34,197,94,0.18); color:#bbf7d0; }}
    .badge.med {{ background: rgba(249,115,22,0.18); color:#fed7aa; }}
    .badge.high {{ background: rgba(239,68,68,0.18); color:#fecaca; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <h1>Log Analyzer</h1>
      <div class="pill">
        <div class="{sev_class}">SEVERITY: {result.severity_label} ({result.severity_score})</div>
        <div class="muted">דוח מסודר (ללא JSON)</div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2>✅ עובדות מאושרות</h2>
        <ul>{li(result.confirmed_facts)}</ul>
      </div>

      <div class="card">
        <h2>🎯 הכשל הראשי</h2>
        <div class="mono">{result.primary_failure}</div>
      </div>

      <div class="card">
        <h2>🧠 Root Cause</h2>
        <div class="mono">{result.root_cause}</div>
      </div>

      <div class="card">
        <h2>🧩 מה לא ניתן להסיק מהלוג</h2>
        <ul>{li(result.unknowns)}</ul>
      </div>

      <div class="card">
        <h2>🧪 היפותזות מדורגות</h2>
        <ul>{hypos}</ul>
      </div>

      <div class="card">
        <h2>➡ Next Steps (צבוע לפי דחיפות)</h2>
        <div class="steps">{steps}</div>
      </div>

      <div class="card" style="grid-column: 1 / -1;">
        <h2>⚠ סתירות / נקודות לבדיקה</h2>
        <ul>{li(result.contradictions)}</ul>
      </div>
    </div>
  </div>
</body>
</html>"""
