"""
Strict Pydantic v2 data contracts for deterministic inter-agent handoffs.

Every agent input/output is typed here. LLMs are forced to return
structured JSON matching these schemas — no free-form text passes
between agents.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ── Webhook Ingress ──────────────────────────────────────────────────────────

class WebhookPayload(BaseModel):
    """Incoming deployment webhook validated at the FastAPI edge."""
    target_url: str = Field(..., description="URL of the deployed staging service")
    deployment_id: str = Field(..., description="Unique deployment identifier")
    repo_url: Optional[str] = Field(None, description="Git clone URL of the target repo")
    auth_signature: Optional[str] = Field(None, description="HMAC signature for payload integrity")
    # Web-app pipeline additions (populated by pipeline.py, not from external webhooks)
    repo_name: Optional[str] = Field(None, description="'owner/repo' short name, e.g. 'DevOpsDreamer/ANVIL'")
    github_token: Optional[str] = Field(None, description="OAuth token used for cloning and PR creation")
    base_branch: str = Field("main", description="Branch to scan and base the fix PR against")


# ── Agent 1: Reconnaissance ──────────────────────────────────────────────────

class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class VulnerableEndpoint(BaseModel):
    path: str = Field(..., description="URL path of the vulnerable endpoint")
    method: HttpMethod = Field(..., description="HTTP method to trigger the vulnerability")
    injection_vector: str = Field(..., description="Description of the injection vector")


class ReconOutput(BaseModel):
    """Strict output contract for the Reconnaissance agent."""
    target_url: str = Field(..., description="Base URL of the scanned target")
    detected_framework: str = Field(..., description="Detected web framework or server")
    vulnerable_endpoints: List[VulnerableEndpoint] = Field(
        ..., description="Catalogued attack surface without raw HTTP responses"
    )


# ── Agent 2: Exploitation ────────────────────────────────────────────────────

class ExploitOutput(BaseModel):
    """Strict output contract for the Exploiter agent."""
    vulnerability_confirmed: bool = Field(
        ..., description="Whether the vulnerability was actively confirmed"
    )
    exploit_payload_used: str = Field(
        ..., description="Exact Python exploit code that was executed"
    )
    sandbox_stdout: str = Field(
        ..., description="Raw stdout captured from the sandbox execution"
    )
    exploit_evidence: Optional[str] = Field(
        None, description="Evidence of successful exploitation extracted from stdout (e.g. leaked secrets, file contents, env vars)"
    )


# ── Agent 3: Patching ────────────────────────────────────────────────────────

class PatchOutput(BaseModel):
    """Strict output contract for the Patcher agent."""
    file_modified: str = Field(..., description="Relative path to the patched file")
    unified_diff: str = Field(..., description="Unified diff of the applied fix")
    pull_request_title: str = Field(..., description="Title for the generated PR/commit")
    pull_request_body: str = Field(
        ..., description="Body describing the vulnerability and the fix"
    )
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Model confidence in the patch correctness"
    )
    pr_url: Optional[str] = Field(
        None, description="URL of the created GitHub Pull Request"
    )


# ── Verifier ─────────────────────────────────────────────────────────────────

class VerificationResult(BaseModel):
    """Output of the deterministic Verifier node."""
    verified: bool = Field(
        ..., description="True only if the sandbox stdout cryptographically proves exploitation"
    )
    reason: str = Field(..., description="Human-readable justification")
    expected_pattern: Optional[str] = Field(
        None, description="The pattern or hash the Verifier was checking for"
    )
    actual_value: Optional[str] = Field(
        None, description="The actual value found in stdout"
    )


# ── Master State (CPN Token) ────────────────────────────────────────────────

class MasterState(BaseModel):
    """The coloured token that flows through the Petri net."""
    trace_id: str
    task_id: str
    current_node: str = "ingress"
    retry_count: int = 0
    webhook: Optional[WebhookPayload] = None
    recon: Optional[ReconOutput] = None
    exploit: Optional[ExploitOutput] = None
    verification: Optional[VerificationResult] = None
    patch: Optional[PatchOutput] = None
    error: Optional[str] = None
    completed: bool = False
    # Web-app additions
    repo_url: Optional[str] = None
    repo_dir: Optional[str] = None
    github_token: Optional[str] = None
    base_branch: str = "main"


# ── Web App Schemas ──────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request body for POST /api/scan."""
    repo_url: str = Field(..., description="GitHub repo URL, e.g. https://github.com/user/repo")
    base_branch: str = Field("main", description="Branch to scan and base the fix PR against")


class ScanStage(str, Enum):
    """Pipeline stages for SSE progress updates."""
    QUEUED = "queued"
    CLONING = "cloning"
    RECON = "recon"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    PATCH = "patch"
    PUSHING = "pushing"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanEvent(BaseModel):
    """A single SSE event pushed to the frontend."""
    scan_id: str
    stage: ScanStage
    status: str = Field(..., description="'running' | 'done' | 'error'")
    message: str = ""
    detail: Optional[str] = None
    pr_url: Optional[str] = None
    vuln_count: Optional[int] = None
    progress_pct: int = Field(0, ge=0, le=100)


class ScanResult(BaseModel):
    """Full scan result returned by GET /api/scan/{scan_id}."""
    scan_id: str
    repo_url: str
    status: str
    stage: ScanStage
    vulnerabilities: List[VulnerableEndpoint] = []
    pr_url: Optional[str] = None
    error: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    recon: Optional[ReconOutput] = None
    exploit: Optional[ExploitOutput] = None
    verification: Optional[VerificationResult] = None
    patch: Optional[PatchOutput] = None

