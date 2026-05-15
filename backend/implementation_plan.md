# Multi-Agent Autonomy Hackathon Implementation Plan

This document outlines the end-to-end architecture and execution steps for building the Autonomous Defensive Remediation Multi-Agent engine for the PS3 Hackathon.

## User Review Required
We have pivoted on several key areas to guarantee stability within the 24-hour hackathon environment based on our discussion:
1. **Graph Engine**: Building a pure, custom Python implementation rather than relying on heavy frameworks.
2. **State Synchronization**: Using a dedicated continuous daemon to atomically merge Redis Streams into the SQLite master state.
3. **Sandbox**: Pivoting from Docker to a native **AST-Validated Subprocess Sandbox** due to network configuration issues.
4. **Target App**: Building a deliberate, isolated, minimal vulnerable Flask app for the demonstration.

## Open Questions

> [!NOTE]
> **Omium SDK Tracing — RESOLVED**
> Traces exported to `ingest.monium.yandex.cloud:443` using API key `omium_poJ52g3sSBV6Cijv9kAi-HmAsqZiPptZNaSpLfofb-E`. Configured as OTLP gRPC exporter in `app/telemetry.py`.

## Proposed Changes

### Core Infrastructure
- **[NEW] `app/main.py`**: FastAPI ingress webhook server. It will validate payloads with Pydantic and enqueue tasks.
- **[NEW] `app/celery_app.py`**: Celery worker configuration connected to Redis.
- **[NEW] `app/state_synchronizer.py`**: A dedicated daemon process that consumes agent results from the Redis Stream and commits them atomically to the SQLite DB.
- **[NEW] `app/db.py`**: SQLite database setup configured in Write-Ahead Logging (WAL) mode.

### Contracts & Middleware
- **[NEW] `app/schemas.py`**: Strict Pydantic BaseModel definitions (`ReconOutput`, `ExploitOutput`, `PatchOutput`).
- **[NEW] `app/sandbox.py`**: The "Fail-Closed" AST-validated execution sandbox for running exploit payloads safely via standard `subprocess`.

### Orchestration & Graph
- **[NEW] `app/graph.py`**: The pure Python implementation of the Colored Petri Net. This handles the deterministic routing based strictly on the JSON payload outputs.

### The Agents
- **[NEW] `app/agents/recon.py`**: Uses LLM APIs to extract vulnerabilities based on port scans.
- **[NEW] `app/agents/exploiter.py`**: Generates Python exploit payloads.
- **[NEW] `app/agents/verifier.py`**: Deterministic loop-breaker; mathematically checks if `sandbox_stdout` proves exploitation.
- **[NEW] `app/agents/patcher.py`**: Modifies the AST of the target repository and generates a Git commit/PR.

### The Target Demonstration
- **[NEW] `target_app/server.py`**: A simple 20-line vulnerable Flask application (e.g. containing a deliberate path traversal flaw) initialized as a Git repository so the Patcher agent can operate on it.

## Verification Plan

### Automated Tests
- Unit tests verifying the `app/sandbox.py` successfully blocks dangerous imports (`os.remove`) and times out infinite loops.
- Verification that Pydantic models reject incorrectly typed JSON from the LLM.

### Manual Verification
1. Boot the Redis container, the Celery worker, the State Synchronizer, and the FastAPI ingress.
2. Boot the `target_app/server.py`.
3. Fire a simulated deployment Webhook to FastAPI via `curl`.
4. Monitor the execution trace and verify the Patcher Agent correctly commits a fix to the `target_app` git repository.
