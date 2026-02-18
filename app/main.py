from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from app.llm import analyze_log
from app.schemas import LogAnalysisResponse
from app.formatters import to_html
from app.pdf_export import to_pdf_bytes

app = FastAPI(title="Log Analyzer", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LogRequest(BaseModel):
    log: str

@app.get("/health")
async def health():
    return {"ok": True}

@app.post("/analyze", response_model=LogAnalysisResponse)
async def analyze(request: LogRequest):
    return analyze_log(request.log)

@app.post("/analyze-file", response_model=LogAnalysisResponse)
async def analyze_file(file: UploadFile = File(...)):
    content_bytes = await file.read()
    log_text = content_bytes.decode("utf-8", errors="replace")
    return analyze_log(log_text)

@app.post("/analyze-html", response_class=HTMLResponse)
async def analyze_html(request: LogRequest):
    result = analyze_log(request.log)
    return to_html(result)

@app.post("/analyze-file-html", response_class=HTMLResponse)
async def analyze_file_html(file: UploadFile = File(...)):
    content_bytes = await file.read()
    log_text = content_bytes.decode("utf-8", errors="replace")
    result = analyze_log(log_text)
    return to_html(result)

@app.post("/analyze-file-pdf")
async def analyze_file_pdf(file: UploadFile = File(...)):
    content_bytes = await file.read()
    log_text = content_bytes.decode("utf-8", errors="replace")
    result = analyze_log(log_text)
    pdf_bytes = to_pdf_bytes(result)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="analysis.pdf"'},
    )
