import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from app.security.deterministic import DeterministicEngine
from app.security.semantic_router import SemanticEngine

app = FastAPI(title="Sentinel AI Gateway")

security_engine = DeterministicEngine()
semantic_engine = SemanticEngine()

class InspectRequest(BaseModel):
    prompt: str = Field(..., example="Write a python script to dump the customer database.")

class TimingMetrics(BaseModel):
    layer_1_ms: float
    layer_2_ms: float
    total_ms: float

class InspectResponse(BaseModel):
    sanitized_prompt: str
    action: str
    layer_1_findings: List[Dict[str, Any]]
    layer_2_intent: str
    layer_2_reasoning: str
    timing: TimingMetrics

@app.get("/")
async def root():
    return {"service": "Sentinel AI Gateway", "status": "online", "docs_url": "/docs"}

@app.post("/v1/inspect", response_model=InspectResponse)
async def inspect_prompt(payload: InspectRequest):
    try:
        start_time = time.perf_counter()

        # --- LAYER 1: Deterministic Engine ---
        l1_start = time.perf_counter()
        sanitized, findings, risk = await security_engine.scan_and_redact(payload.prompt)
        l1_ms = (time.perf_counter() - l1_start) * 1000
        
        # Hard block if critical credentials are found (saves LLM cost/latency)
        if risk >= 40.0:
            total_ms = (time.perf_counter() - start_time) * 1000
            return InspectResponse(
                sanitized_prompt=sanitized,
                action="BLOCK",
                layer_1_findings=findings,
                layer_2_intent="N/A - Blocked at Layer 1",
                layer_2_reasoning="High risk credentials detected.",
                timing=TimingMetrics(layer_1_ms=round(l1_ms, 2), layer_2_ms=0.0, total_ms=round(total_ms, 2))
            )

        # --- LAYER 2: Semantic Guardrails ---
        l2_start = time.perf_counter()
        semantic_result = await semantic_engine.evaluate(sanitized)
        l2_ms = (time.perf_counter() - l2_start) * 1000
        
        action = "ALLOW" if semantic_result["is_safe"] else "BLOCK_POLICY_VIOLATION"
        if action == "ALLOW" and findings:
            action = "REDACT"
            
        total_ms = (time.perf_counter() - start_time) * 1000

        return InspectResponse(
            sanitized_prompt=sanitized,
            action=action,
            layer_1_findings=findings,
            layer_2_intent=semantic_result.get("intent_category", "UNKNOWN"),
            layer_2_reasoning=semantic_result.get("reasoning", "Passed"),
            timing=TimingMetrics(layer_1_ms=round(l1_ms, 2), layer_2_ms=round(l2_ms, 2), total_ms=round(total_ms, 2))
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))