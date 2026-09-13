import time
import uuid
from collections import deque
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage
from app.security.deterministic import DeterministicEngine
from app.security.semantic_router import SemanticEngine

app = FastAPI(
    title="Sentinel AI Gateway",
    description="Enterprise AI Trust Gateway & Security Reverse Proxy",
    version="1.0.0"
)

# Core Engines
security_engine = DeterministicEngine()
semantic_engine = SemanticEngine()

# Downstream Generation LLM (Fast, lightweight execution for allowed/redacted prompts)
downstream_llm = ChatGroq(
    model="openai/gpt-oss-120b",
    temperature=0.7
)

# In-Memory Telemetry Ring Buffer (Holds last 100 requests for the SOC Dashboard)
TELEMETRY_LOGS = deque(maxlen=100)

# ---------------------------------------------------------
# UNIFIED SCHEMAS
# ---------------------------------------------------------
class ChatRequest(BaseModel):
    prompt: str = Field(..., example="Explain how neural networks work.")

class TimingBreakdown(BaseModel):
    layer_1_ms: float
    layer_2_ms: float
    downstream_ms: float
    total_ms: float

class SecurityDecision(BaseModel):
    request_id: str
    decision: str                  # ALLOW, REDACT, BLOCK
    risk_level: str                # LOW, MEDIUM, HIGH, CRITICAL
    intent: str
    policy_id: Optional[str] = None
    reason: str
    sanitized_prompt: str
    timing: TimingBreakdown

class ChatResponse(BaseModel):
    request_id: str
    security_decision: SecurityDecision
    llm_response: Optional[str] = None


async def run_pipeline(prompt: str) -> SecurityDecision:
    """Executes the Tiered Defense pipeline and constructs the SecurityDecision object."""
    req_id = f"req_{uuid.uuid4().hex[:8]}"
    start_total = time.perf_counter()

    # --- LAYER 1: Presidio & Custom Regex ---
    l1_start = time.perf_counter()
    sanitized, findings, risk = await security_engine.scan_and_redact(prompt)
    l1_ms = (time.perf_counter() - l1_start) * 1000

    # Layer 1 Hard Block (Zero-Trust PII / Secrets)
    if risk >= 40.0:
        total_ms = (time.perf_counter() - start_total) * 1000
        decision = SecurityDecision(
            request_id=req_id,
            decision="BLOCK",
            risk_level="CRITICAL" if risk >= 40.0 else "HIGH",
            intent="DATA_EXTRACTION",
            policy_id="POL-DATA-001",
            reason=f"Blocked at Layer 1: Detected {len(findings)} sensitive entity/credential match(es).",
            sanitized_prompt=sanitized,
            timing=TimingBreakdown(
                layer_1_ms=round(l1_ms, 2),
                layer_2_ms=0.0,
                downstream_ms=0.0,
                total_ms=round(total_ms, 2)
            )
        )
        TELEMETRY_LOGS.append(decision.model_dump())
        return decision

    # --- LAYER 2: Semantic Router & Policy RAG ---
    l2_start = time.perf_counter()
    l2_result = await semantic_engine.evaluate(sanitized)
    l2_ms = (time.perf_counter() - l2_start) * 1000

    is_safe = l2_result.get("is_safe", True)
    intent = l2_result.get("intent_category", "BENIGN")
    reasoning = l2_result.get("reasoning", "Passed evaluation.")

    # Extract Policy ID if present in reasoning string
    policy_id = None
    if "POL-" in reasoning:
        start_idx = reasoning.find("POL-")
        policy_id = reasoning[start_idx:start_idx + 11].split()[0].strip(".,:;\"'")

    # --- ARCHITECTURAL SAFETY FLOOR ---
    # Overrule the Judge if the Classifier caught a hard prompt injection keyword
    if intent == "PROMPT_INJECTION" and any(
        keyword in sanitized.lower() 
        for keyword in ["ignore previous", "disregard", "system override", "jailbreak", "clear prior"]
    ):
        is_safe = False
        reasoning = "Security Gateway Override: Direct prompt injection directive detected."
        policy_id = "POL-INJ-002"

    if not is_safe:
        final_decision = "BLOCK"
        risk_level = "HIGH" if intent == "PROMPT_INJECTION" else "CRITICAL"
    elif findings:
        final_decision = "REDACT"
        risk_level = "MEDIUM"
    else:
        final_decision = "ALLOW"
        risk_level = "LOW"

    total_ms = (time.perf_counter() - start_total) * 1000
    decision = SecurityDecision(
        request_id=req_id,
        decision=final_decision,
        risk_level=risk_level,
        intent=intent,
        policy_id=policy_id,
        reason=reasoning,
        sanitized_prompt=sanitized,
        timing=TimingBreakdown(
            layer_1_ms=round(l1_ms, 2),
            layer_2_ms=round(l2_ms, 2),
            downstream_ms=0.0,
            total_ms=round(total_ms, 2)
        )
    )
    TELEMETRY_LOGS.append(decision.model_dump())
    return decision


# ---------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------
@app.post("/v1/inspect", response_model=SecurityDecision)
async def inspect_endpoint(payload: ChatRequest):
    """Auditing endpoint: Evaluates prompt safety without invoking downstream LLMs."""
    return await run_pipeline(payload.prompt)


@app.post("/v1/chat", response_model=ChatResponse)
async def chat_proxy_endpoint(payload: ChatRequest):
    """Full Reverse Proxy: Inspects prompt, applies redaction/blocks, and proxies to LLM."""
    decision = await run_pipeline(payload.prompt)

    # If blocked, drop the connection immediately
    if decision.decision == "BLOCK":
        return ChatResponse(
            request_id=decision.request_id,
            security_decision=decision,
            llm_response="[SECURITY GATEWAY ERROR]: Your request was blocked due to an enterprise policy violation."
        )

    # If ALLOW or REDACT, dispatch the sanitized prompt downstream
    downstream_start = time.perf_counter()
    response = await downstream_llm.ainvoke([HumanMessage(content=decision.sanitized_prompt)])
    downstream_ms = (time.perf_counter() - downstream_start) * 1000

    # Update latency metrics to include generation time
    decision.timing.downstream_ms = round(downstream_ms, 2)
    decision.timing.total_ms = round(decision.timing.total_ms + downstream_ms, 2)

    return ChatResponse(
        request_id=decision.request_id,
        security_decision=decision,
        llm_response=response.content
    )


@app.get("/v1/telemetry", response_model=List[Dict[str, Any]])
async def get_telemetry():
    """Returns the historical buffer of recent requests to populate the Streamlit SOC UI."""
    return list(TELEMETRY_LOGS)

@app.get("/health", tags=["System"])
async def health_check():
    """Ultra-low latency probe for liveness checks."""
    return {"status": "healthy", "service": "sentinel-gateway"}