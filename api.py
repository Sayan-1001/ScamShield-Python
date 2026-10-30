"""FastAPI Backend for Chrome Extension and Android Client."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scamshield.explainable_engine import ScamShieldEngine
from scamshield.url_analyzer import analyze_single_url

app = FastAPI(title="ScamShield API")

# Enable CORS so Chrome Extension can query localhost without blocks
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ScamShieldEngine()

class URLCheckRequest(BaseModel):
    url: str

class TextCheckRequest(BaseModel):
    sender: str = ""
    text: str

@app.post("/check-url")
def check_url(payload: URLCheckRequest):
    analysis = analyze_single_url(payload.url)
    is_scam = analysis["risk_points"] >= 30
    return {
        "url": payload.url,
        "is_scam": is_scam,
        "risk_score": analysis["risk_points"],
        "warning_signs": analysis["warning_signs"]
    }

@app.post("/check-text")
def check_text(payload: TextCheckRequest):
    result = engine.analyze(payload.text)
    is_scam = result["risk_score"] >= 50
    return {
        "is_scam": is_scam,
        "risk_score": result["risk_score"],
        "threat_level": result["risk_level"],
        "reasons": [t["explanation"] for t in result["triggers"]],
        "recommendations": result["recommendations"]
    }
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)