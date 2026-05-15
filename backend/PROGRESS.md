# Autonomous Red-Team Engine — Build Progress

> **Project**: Multi-Agent Autonomy Hackathon (PS3 Track)
> **Last Updated**: 2026-05-15

---

## Architecture Overview

An autonomous penetration testing and remediation pipeline built on a **Colored Petri Net (CPN)** execution model. The system receives deployment webhooks, scans for vulnerabilities, generates and executes exploit payloads in a sandboxed environment, verifies exploitation, and autonomously patches the vulnerable code — all with full OpenTelemetry observability via the Omium SDK.

```
Webhook → FastAPI → Celery → CPN Engine → [Recon → Exploit → Verify → Patch] → Git Commit
                                  ↕
                          SQLite Checkpoint
                          (crash recovery)
```

---

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Orchestration Engine | Custom Python CPN (no framework) | Full mathematical control over state transitions; no framework lock-in |
| State Persistence | SQLite (WAL) + Redis Streams hybrid | SQLite for durable checkpoints; Redis for async fan-out/fan-in |
| State Synchronizer | Dedicated single-threaded daemon | Guarantees atomic, sequential SQLite updates — no write-locks |
| Sandbox | AST-Validated Subprocess (not Docker) | Docker has network issues on dev machine; AST filtering + stripped env provides fail-closed safety |
| Inter-Agent Communication | Strict Pydantic v2 JSON schemas | Eliminates context poisoning; no free-form text between agents |
| Observability | Omium SDK (OTLP gRPC) | Traces exported to `ingest.monium.yandex.cloud:443` with W3C Trace Context propagation across Celery |
| Target App | Vulnerable Flask server (Path Traversal) | Simple, predictable demo; judges focus on architecture, not app complexity |

---

## File Structure

```
omium/
├── app/
│   ├── __init__.py              # Package init
│   ├── config.py                # Central configuration (env vars, API keys)
│   ├── db.py                    # SQLite WAL checkpointing + execution log
│   ├── schemas.py               # 7 Pydantic data contracts
│   ├── telemetry.py             # Omium/OTLP exporter + W3C propagation
│   ├── celery_app.py            # Celery broker (Redis-backed)
│   ├── main.py                  # FastAPI webhook ingress
│   ├── sandbox.py               # AST-validated subprocess sandbox
│   ├── graph.py                 # Colored Petri Net execution engine
│   ├── tasks.py                 # Celery tasks (FastAPI → CPN bridge)
│   ├── state_synchronizer.py    # Redis Stream → SQLite merge daemon
│   └── agents/
│       ├── __init__.py
│       ├── recon.py             # Agent 1: Reconnaissance (LLM-powered)
│       ├── exploiter.py         # Agent 2: Exploit Generation (LLM + sandbox)
│       ├── verifier.py          # Verifier: Deterministic (NO LLM)
│       └── patcher.py           # Agent 3: Patch + Git Commit (LLM-powered)
├── target_app/
│   └── server.py                # Intentionally vulnerable Flask app
├── tests/
│   └── test_sandbox.py          # TDD tests for sandbox (7/7 passing)
├── requirements.txt             # All Python dependencies
└── PROGRESS.md                  # This file
```

---

## Build Progress

### Phase 1: Project Setup — COMPLETE
- [x] Python virtual environment initialized
- [x] `requirements.txt` created and all deps installed
- [x] Omium API key configured: `omium_poJ52g3sSBV6Cijv9kAi-HmAsqZiPptZNaSpLfofb-E`

### Phase 2: Core Infrastructure — COMPLETE
- [x] `app/config.py` — Central config with env vars, sensible defaults
- [x] `app/db.py` — SQLite WAL-mode with checkpoint CRUD + execution logging
- [x] `app/schemas.py` — 7 strict Pydantic contracts:
  - `WebhookPayload` (ingress validation)
  - `ReconOutput` (attack surface catalog)
  - `ExploitOutput` (payload + sandbox stdout)
  - `PatchOutput` (diff + PR metadata)
  - `VerificationResult` (deterministic proof)
  - `MasterState` (CPN coloured token)
  - `VulnerableEndpoint` + `HttpMethod` (sub-schemas)
- [x] `app/telemetry.py` — OTLP gRPC exporter to Yandex Cloud + W3C trace propagation
- [x] `app/celery_app.py` — Redis broker, late ACK, prefetch=1
- [x] `app/main.py` — FastAPI POST /webhook → Pydantic validation → Celery dispatch → 202
- [x] `app/state_synchronizer.py` — Single-threaded Redis Stream consumer

### Phase 3: Target Environment — COMPLETE
- [x] `target_app/server.py` — Flask app with intentional Path Traversal at `/files/<path>`
- [x] Secret flag file: `FLAG{r3d_t34m_4ut0n0my_pr00f}`
- [x] Git repository initialized with initial commit

### Phase 4: Agent Logic & Orchestration — COMPLETE
- [x] `app/sandbox.py` — AST filtering + stripped env + hard timeout + signature hash circuit breaker
- [x] `app/agents/recon.py` — HTTP probing + LLM analysis → `ReconOutput`
- [x] `app/agents/exploiter.py` — LLM payload generation + sandbox execution → `ExploitOutput`
- [x] `app/agents/verifier.py` — Deterministic stdout validation (no LLM) → `VerificationResult`
- [x] `app/agents/patcher.py` — LLM fix generation + Git branch/commit → `PatchOutput`
- [x] `app/graph.py` — Full CPN engine: 10 places, 5 transitions, retry circuit breakers
- [x] `app/tasks.py` — Celery task with trace context restoration

### Phase 5: Integration & Testing — COMPLETE
- [x] Sandbox TDD tests: **7/7 passing**
  - Safe code acceptance
  - Dangerous import blocking (shutil)
  - Dangerous call blocking (os.remove)
  - Syntax error fast-fail
  - Safe payload execution
  - Timeout enforcement (infinite loops)
  - subprocess.run blocking
- [x] End-to-end pipeline test successfully executed
- [x] Omium trace verification completed

---

## CPN Graph Topology

```
[ingress] → T1 → [recon_ready] → T2 → [exploit_ready] → T3 → [exploit_done]
                        ↓                      ↑                      ↓
                   (no vulns)             (retry < 3)              T4 (verify)
                        ↓                      ↑                      ↓
                   [end_safe]            [exploit_ready]  ←── (fail) ──┘
                                                                      ↓
                                                               (verified)
                                                                      ↓
                                                              [patch_ready] → T5 → [patch_done]
                                                                                        ↓
                                                                                   TERMINAL
```

**Terminal places**: `patch_done`, `end_safe`, `end_error`

---

## Fail-Closed Safety Mechanisms

| Mechanism | Implementation | File |
|---|---|---|
| AST Import Filtering | Blocks shutil, ctypes, subprocess, etc. | `app/sandbox.py` |
| AST Call Filtering | Blocks os.remove, os.system, eval, exec | `app/sandbox.py` |
| Stripped Environment | `env={}` in subprocess.run | `app/sandbox.py` |
| Hard Timeout | `timeout=5s` on subprocess | `app/sandbox.py` |
| Signature Hash Dedup | SHA-256 hash of payload; blocks after 3 identical failures | `app/sandbox.py` |
| CPN Max Steps | 20-step absolute limit prevents infinite graph traversal | `app/graph.py` |
| Retry Circuit Breaker | Max 3 retries at verification before halting | `app/graph.py` |
| Pydantic Validation | Strict JSON schema enforcement on all agent I/O | `app/schemas.py` |
| SQLite Checkpointing | State saved after every CPN transition | `app/graph.py` |

---

## How to Run

### Prerequisites
- Python 3.11+
- Redis server running on localhost:6379
- OpenAI API key set as `OPENAI_API_KEY` env var

### Start the Target App
```bash
python target_app/server.py
# Starts on http://localhost:9999
```

### Start the Celery Worker
```bash
celery -A app.celery_app worker --loglevel=info
```

### Start the State Synchronizer
```bash
python -m app.state_synchronizer
```

### Start the FastAPI Ingress
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Fire a Test Webhook
```bash
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:9999", "deployment_id": "test-001"}'
```

Expected response: `{"status": "accepted", "trace_id": "...", "task_id": "..."}`

---

## Next Steps
The system is now fully complete, tested, and operational.
1. **Prepare Demo:** You can run the webhook simulation to demonstrate the autonomous detection, exploitation, verification, and patching of the vulnerability.
2. **Submit to Hackathon:** The architecture meets all constraints (CPN, SQLite/Redis hybrid, AST Sandbox, Fail-Closed design). Record the demo video and submit!
