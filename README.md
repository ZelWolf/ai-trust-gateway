# Sentinel AI Gateway

A production-oriented security gateway for LLM applications.

Sentinel intercepts LLM requests and applies a dual-layer security
pipeline before allowing them to reach the target model.

## Current Status

🚧 Work in Progress

### Security Pipeline

Request
   ↓
Deterministic Security Layer
   ↓
Semantic Guardrail Layer
   ↓
ALLOW / BLOCK
   ↓
Target LLM

## Current Stack

- Python
- FastAPI
- Microsoft Presidio
- Regex-based secret detection
- Sentence Transformers
- ChromaDB
- LangChain
- LangGraph
- Groq / Gemma 2

## Current Capabilities

- PII detection and redaction
- API key / secret detection
- Risk scoring
- Semantic intent classification
- Policy retrieval using RAG
- LLM-based policy evaluation
- FastAPI REST API
- OpenAPI documentation

## Roadmap

- [ ] Target LLM integration
- [ ] Structured LLM outputs
- [ ] Authentication
- [ ] Rate limiting
- [ ] Automated security tests
- [ ] Docker
- [ ] CI/CD with GitHub Actions
- [ ] Observability
- [ ] Production deployment
