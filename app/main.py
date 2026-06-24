from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from app.security.deterministic import DeterministicEngine

app = FastAPI(title="Sentinel AI Gateway")

# Instantiate the engine globally (saving latency)
security_engine = DeterministicEngine()

# JSON input
class InspectRequest(BaseModel):
    prompt: str = Field(..., example="My AWS key is aws_secret_key='AKIAIOSFODNN7EXAMPLE'")

#JSON output
class InspectResponse(BaseModel):
    sanitized_prompt: str
    risk_score: float
    violations: List[Dict[str, Any]]
    action: str

@app.post("/v1/inspect", response_model=InspectResponse)
async def inspect_prompt(payload: InspectRequest):
    try:
        sanitized, findings, risk = security_engine.scan_and_redact(payload.prompt)
        
        action = "ALLOW"
        if risk >= 40.0:
            action = "BLOCK"
        elif risk > 0:
            action = "REDACT"
            
        return InspectResponse(
            sanitized_prompt=sanitized,
            risk_score=risk,
            violations=findings,
            action=action
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "Layer 1 Active"}