import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from app.security.deterministic import DeterministicEngine

app = FastAPI(title="Sentinel AI Gateway")

# Instantiating engine globally
security_engine = DeterministicEngine()

# JSON input
class InspectRequest(BaseModel):
    prompt: str = Field(..., example="My AWS key is aws_secret_key='AKIAIOSFODNN7EXAMPLE'")

# JSON output
class InspectResponse(BaseModel):
    sanitized_prompt: str
    risk_score: float
    violations: List[Dict[str, Any]]
    action: str
    execution_ms: float

@app.post("/v1/inspect", response_model=InspectResponse)
async def inspect_prompt(payload: InspectRequest):
    try:
        # FIX: Define start_time before running the security engine
        start_time = time.perf_counter()
        
        sanitized, findings, risk = await security_engine.scan_and_redact(payload.prompt)
        
        # Now the calculation will work perfectly
        exec_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        action = "ALLOW"
        if risk >= 40.0:
            action = "BLOCK"
        elif risk > 0:
            action = "REDACT"
            
        return InspectResponse(
            sanitized_prompt=sanitized,
            risk_score=risk,
            violations=findings,
            action=action,
            execution_ms=exec_ms
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "Layer 1 Active"}