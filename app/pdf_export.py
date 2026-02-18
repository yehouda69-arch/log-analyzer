from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from app.schemas import LogAnalysisResponse


def to_pdf_bytes(result: LogAnalysisResponse) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    y = height - 40

    def line(text: str, size=11, gap=16):
        nonlocal y
        c.setFont("Helvetica", size)
        c.drawString(40, y, (text or "")[:120])
        y -= gap
        if y < 60:
            c.showPage()
            y = height - 40

    line("Log Analysis Report", 16, 22)
    line(f"Severity: {result.severity_label} ({result.severity_score})", 12, 18)
    line("")

    line("Confirmed Facts:", 12, 18)
    for f in result.confirmed_facts:
        line(f"- {f}")

    line("")
    line(f"Primary Failure: {result.primary_failure}", 12, 18)
    line(f"Root Cause: {result.root_cause}")

    line("")
    line("Unknowns:", 12, 18)
    for u in result.unknowns:
        line(f"- {u}")

    line("")
    line("Ranked Hypotheses:", 12, 18)
    for h in result.hypotheses_ranked:
        line(f"{h.rank}. {h.description}", 11, 16)
        line(f"   {h.justification}", 10, 14)

    line("")
    line("Next Steps:", 12, 18)
    for s in result.next_steps:
        line(f"- [{s.urgency.upper()}] {s.text}")

    line("")
    line("Contradictions:", 12, 18)
    if result.contradictions:
        for cx in result.contradictions:
            line(f"- {cx}")
    else:
        line("- None")

    c.save()
    return buf.getvalue()
