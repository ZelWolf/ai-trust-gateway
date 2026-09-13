<div align="center">

# 🛡️ Sentinel AI Gateway
### Enterprise LLM Security Reverse Proxy & Observability Suite

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-005571?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Production Ready](https://img.shields.io/badge/Status-Active%20Development-success)]()

*A high-performance, dual-layer security middleware designed to intercept, inspect, redact, and evaluate LLM payloads in real-time before they reach downstream generative models.*

</div>

---

## 🏗️ System Architecture

Sentinel operates as an asynchronous reverse proxy, enforcing strict zero-trust boundaries between clients and foundation models without introducing unacceptable latency penalties.

```text
Client Request
      │
      ▼
┌───────────────┐
│ FastAPI Proxy │
└───────┬───────┘
        │
        ▼
┌──────────────────────────────────────────────┐
│ LAYER 1: Deterministic Engine (Sub-25ms)     │
│ ├── Microsoft Presidio (PII / Identifiers)   │
│ └── Custom Regex (AWS Keys, JWT, PAN, etc.)  │
└───────┬──────────────────────────────────────┘
        │
        ├─► [CRITICAL RISK / MATCH] ──► HARD BLOCK (Zero Token Waste)
        │
        ▼
┌──────────────────────────────────────────────┐
│ LAYER 2: Semantic Guardrail & Policy RAG     │
│ ├── LangGraph Intent Classifier              │
│ └── ChromaDB + FastEmbed Compliance Store    │
└───────┬──────────────────────────────────────┘
        │
        ├─► [POLICY VIOLATION] ────────► HARD BLOCK / AUDIT LOG
        │
        ▼
┌───────────────┐
│ Sanitized I/O │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Downstream LLM│
└───────────────┘

```
# 🚀 Key Features

- **Dual-Tiered Defense Pipeline:** Combines lightning-fast deterministic CPU matching (Layer 1) with context-aware semantic reasoning and vector-based policy retrieval (Layer 2).
- **Zero-Token Short-Circuiting:** Malicious prompts, credential leaks, and prompt injections are hard-stopped at the proxy level, preventing wasted compute tokens and API costs on downstream LLMs.
- **Intelligent PII Redacting & Masking:** Automatically strips or replaces sensitive personal identifiers, credentials, and custom enterprise secrets before forwarding sanitized prompts.
- **Interactive SOC Observability Dashboard:** Built with Streamlit to monitor live traffic, track decision latencies, inspect pipeline blocks, and export structured JSON audit records.
- **Security Benchmark Arena:** A built-in parallel evaluation suite comparing Sentinel's custom pipeline against specialized industry safety models (such as Meta Llama Prompt Guard and OpenAI Safety Guard) in real-time.

## 📊 Benchmark Arena: Speed vs. Context Trade-off

| Security Engine | Architecture | Latency (Avg) | Contextual Reason Generation | PII Redaction Support |
|-------------------|--------------|--------------|------------------------------|---------------------|
| Sentinel Gateway  | Deterministic + Policy RAG | ~600–1200 ms | Yes (Cites specific company policy IDs) | Yes (Regex + Presidio) |
| Meta Prompt Guard 86M Classification Model | ~300 ms | No (Returns raw probability float) | No |
| Safety GPT OSS 20B Reasoning Classifier | ~1500 ms | Yes (Binary Safe/Unsafe check) | No |

## 🛠️ Tech Stack

- **Core Gateway:** FastAPI, Pydantic v2, Uvicorn (Async IO)
- **Observability UI:** Streamlit, Pandas, Custom CSS
- **Deterministic Guardrails:** Microsoft Presidio Analyzer/Anonymizer, Custom RegEx Engine
- **Semantic Guardrails:** LangGraph, ChromaDB, FastEmbedInference & Benchmarking: Groq API SDK, LangChain Core

## ⚙️ Installation & Quickstart

### 1. Clone the Repository
```bash
git clone [https://github.com/ZelWolf/ai-trust-gateway.git](https://github.com/ZelWolf/ai-trust-gateway.git)
cd ai-trust-gateway
```

### 2. Set Up Virtual Environment
```bash
def python3 -m venv .venv
def source .venv/bin/activate
```

### 3. Install Dependencies
```bash
dpip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory and add your API credentials:
```plaintext
groq_api_key=your_groq_api_key_here
ANONYMIZED_TELEMETRY=False
POLICY_SCORE_THRESHOLD=0.16
```

### 5. Run the Application
#### Terminal 1: Start the FastAPI Gateway Backend 
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
``` 
#### Terminal 2: Launch the Streamlit SOC Dashboard 
```bash 
streamlit run app/ui/dashboard.py 
```
## 📂 Project Structure

```text
ai-trust-gateway/
├── app/
│   ├── main.py                     # FastAPI application entrypoint & proxy routes
│   ├── security/
│   │   ├── deterministic.py        # Layer 1: Presidio & Custom Regex engine
│   │   └── semantic_router.py      # Layer 2: LangGraph & ChromaDB RAG
│   └── ui/
       └── dashboard.py            # Streamlit SOC observability dashboard
├── tests/                          # Automated evaluation test suites
├── requirements.txt                # Project dependencies
└── README.md
```

📝 License Distributed under the MIT License. See LICENSE for more information.
