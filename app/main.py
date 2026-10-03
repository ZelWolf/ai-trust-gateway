import os
import time
import uuid
from collections import deque
from typing import List, Dict, Any, Optional
from chromadb import db
from fastapi import FastAPI, HTTPException, status, Security, Request, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from app.database import get_db, AuditLog
from pydantic import BaseModel, Field
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage
from app.security.deterministic import DeterministicEngine
from app.security.semantic_router import SemanticEngine
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

app = FastAPI(
    title="Sentinel AI Gateway",
    description="Enterprise AI Trust Gateway & Security Reverse Proxy",
    version="1.0.0"
)
# Load API keys from environment variable or default to a set of test keys
RAW_KEYS = os.getenv("SENTINEL_API_KEYS", "sk-sentinel-dev-12345,sk-sentinel-test-98765")
VALID_API_KEYS = {k.strip() for k in RAW_KEYS.split(",") if k.strip()}

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Validates incoming client credentials against authorized registry."""
    if not api_key or api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing or invalid X-API-Key header. Access denied by Sentinel Gateway."
        )
    return api_key

def get_client_identifier(request: Request) -> str:
    """Keys rate limits by API Key if present, falling back to client IP to prevent NAT bottlenecks."""
    return request.headers.get("X-API-Key") or get_remote_address(request)

limiter = Limiter(key_func=get_client_identifier)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Core Engines
security_engine = DeterministicEngine()
semantic_engine = SemanticEngine()

# Downstream Generation LLM 
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

def save_audit_log(db: Session, decision: SecurityDecision):
    """Persists a pipeline security decision into the SQLite audit log."""
    db_log = AuditLog(
        request_id=decision.request_id,
        decision=decision.decision,
        risk_level=decision.risk_level,
        intent=decision.intent,
        policy_id=decision.policy_id,
        reason=decision.reason,
        l1_ms=decision.timing.layer_1_ms,
        l2_ms=decision.timing.layer_2_ms,
        total_ms=decision.timing.total_ms
    )
    db.add(db_log)
    db.commit()

async def run_pipeline(prompt: str, db: Session) -> SecurityDecision:
    """Executes the Tiered Defense pipeline and constructs the SecurityDecision object."""
    req_id = f"req_{uuid.uuid4().hex[:8]}"
    start_total = time.perf_counter()

    # --- LAYER 1: Presidio & Custom Regex ---
    l1_start = time.perf_counter()
    sanitized, findings, risk = await security_engine.scan_and_redact(prompt)
    l1_ms = (time.perf_counter() - l1_start) * 1000

    # Critical Infrastructure & Secret Identifiers
    CREDENTIAL_ENTITIES = {
        "AWS_ACCESS_KEY",
        "OPENAI_API_KEY",
        "JWT_TOKEN",
        "RSA_PRIVATE_KEY"
    }
    has_credentials = any(item.get("entity") in CREDENTIAL_ENTITIES for item in findings)

    # Layer 1 Hard Block (Zero-Trust on Credentials / API Keys strictly)
    if has_credentials:
        total_ms = (time.perf_counter() - start_total) * 1000
        decision = SecurityDecision(
            request_id=req_id,
            decision="BLOCK",
            risk_level="CRITICAL",
            intent="CREDENTIAL_EXPOSURE",
            policy_id="POL-SEC-001",
            reason="Blocked at Layer 1: Infrastructure secret or credential leak detected in payload.",
            sanitized_prompt=sanitized,
            timing=TimingBreakdown(
                layer_1_ms=round(l1_ms, 2),
                layer_2_ms=0.0,
                downstream_ms=0.0,
                total_ms=round(total_ms, 2)
            )
        )
        save_audit_log(db, decision)
        return decision
        db_log = AuditLog(
        request_id=decision.request_id,
        decision=decision.decision,
        risk_level=decision.risk_level,
        intent=decision.intent,
        policy_id=decision.policy_id,
        reason=decision.reason,
        l1_ms=decision.timing.layer_1_ms,
        l2_ms=decision.timing.layer_2_ms,
        total_ms=decision.timing.total_ms
    )
        db.add(db_log)
        db.commit()
        return decision

    # --- LAYER 2: Semantic Router & Policy RAG ---
    # Standard PII proceeds with the sanitized prompt for contextual analysis
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
        has_high_value_pii = any(
            item.get("entity") in {"CREDIT_CARD", "US_SSN", "AADHAAR_NUMBER", "PAN_NUMBER"} 
            for item in findings
        )
        risk_level = "HIGH" if has_high_value_pii else "MEDIUM"
        if not policy_id:
            reasoning = f"Sanitized {len(findings)} sensitive PII entity/match(es). Payload cleared for downstream execution."
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
    save_audit_log(db, decision)
    return decision
    return decision


# ---------------------------------------------------------
# SECURE API ROUTES
# ---------------------------------------------------------
@app.post("/v1/inspect", response_model=SecurityDecision)
@limiter.limit("10/minute") # Rate limit
async def inspect_endpoint(
    request: Request, 
    payload: ChatRequest,
    api_key: str = Security(verify_api_key), # Authentication
    db: Session = Depends(get_db) 
):
    """Auditing endpoint: Evaluates prompt safety without invoking downstream LLMs."""
    return await run_pipeline(payload.prompt,db)


@app.post("/v1/chat", response_model=ChatResponse)
@limiter.limit("5/minute") # Strict 5 requests per minute limit
async def chat_proxy_endpoint(
    request: Request, 
    payload: ChatRequest,
    api_key: str = Security(verify_api_key), # Authentication
    db: Session = Depends(get_db) 
):
    """Full Reverse Proxy: Inspects prompt, applies redaction/blocks, and proxies to LLM."""
    decision = await run_pipeline(payload.prompt,db)

    # If blocked, return a security block response WITHOUT dropping the connection
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
async def get_telemetry(
    api_key: str = Security(verify_api_key),  
    db: Session = Depends(get_db)
): 
    """Fetches the last 100 audit records directly from the SQLite database."""
    # Query the database, ordered by newest first
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    #  Reconstruct the JSON shape that the Streamlit dashboard expects
    return [
        {
            "request_id": log.request_id,
            "timestamp": log.timestamp.isoformat(),
            "decision": log.decision,
            "risk_level": log.risk_level,
            "intent": log.intent,
            "policy_id": log.policy_id,
            "reason": log.reason,
            "timing": {
                "layer_1_ms": log.l1_ms,
                "layer_2_ms": log.l2_ms,
                "total_ms": log.total_ms
            }
        }
        for log in logs
    ]
@app.get("/health", tags=["System"])
async def health_check():
    """Ultra-low latency probe for liveness checks. (Publicly accessible)"""
    return {"status": "healthy", "service": "sentinel-gateway"}