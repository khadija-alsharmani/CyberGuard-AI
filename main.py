from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from contextlib import asynccontextmanager
import uvicorn

import rules
import database

@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    yield

app = FastAPI(title="CyberGuard AI", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

class URLScanRequest(BaseModel):
    url: str

class MessageScanRequest(BaseModel):
    message: str

@app.get("/")
def read_root():
    return FileResponse("static/index.html")

@app.post("/scan/url")
def scan_url(data: URLScanRequest):
    result = rules.evaluate_url_risk(data.url)
    database.save_scan_result("URL", data.url, result)
    return {
        "status": "success",
        "input_type": "URL",
        "scanned_input": data.url,
        "risk_score": result["score"],
        "risk_level": result["level"],
        "indicators": result["indicators"],
        "recommendation": result["recommendation"],
        "ai_explanation": result.get("ai_explanation", "")
    }

@app.post("/scan/message")
def scan_message(data: MessageScanRequest):
    result = rules.evaluate_message_risk(data.message)
    database.save_scan_result("Message", data.message, result)
    return {
        "status": "success",
        "input_type": "Message",
        "scanned_input": data.message,
        "risk_score": result["score"],
        "risk_level": result["level"],
        "indicators": result["indicators"],
        "recommendation": result["recommendation"],
        "ai_explanation": result.get("ai_explanation", "")
    }

@app.get("/scans/stats")
def get_stats():
    return database.get_scan_stats()

@app.get("/scans/recent")
def get_recent_scans():
    return database.get_recent_scans(10)

@app.get("/scans/detail/{scan_id}")
def get_scan_detail(scan_id: int):
    res = database.get_scan_by_id(scan_id)
    if not res:
        return {"error": "Not found"}
    return res

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

