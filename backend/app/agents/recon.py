"""
Reconnaissance Agent — scans the target application and catalogs
the attack surface into a strict ReconOutput schema.

Supports two modes:
  1. SOURCE CODE ANALYSIS (web app mode) — reads cloned repo files
     and uses GPT-4o to identify vulnerabilities in the code.
  2. HTTP PROBING (legacy mode) — probes a running target via HTTP
     requests and identifies vulnerabilities from responses.
"""

from __future__ import annotations

import json
import logging
from typing import List, Optional

try:
    import omium as _omium_mod
except Exception:
    _omium_mod = None


def _noop_trace(*a, **kw):
    def _d(fn): return fn
    return _d


class _OmiumShim:
    trace = staticmethod(_noop_trace)


omium = _omium_mod if _omium_mod is not None else _OmiumShim()
import requests
from openai import OpenAI

from app.config import LLM_MODEL, LLM_TEMPERATURE, OPENAI_API_KEY
from app.schemas import ReconOutput
from app.telemetry import trace_operation

logger = logging.getLogger(__name__)

_client: Optional[OpenAI] = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=OPENAI_API_KEY)
    return _client


# ── Mode 1: Source Code Analysis ─────────────────────────────────────────────

@omium.trace("recon_agent", span_type="agent")
def run_recon_source(repo_dir: str, repo_url: str) -> ReconOutput:
    """
    Scan cloned source code for vulnerabilities.
    Reads files from disk and sends them to GPT-4o for analysis.
    """
    from app.github_service import read_repo_files

    with trace_operation(
        "recon_agent_source",
        attributes={"agent.name": "recon", "agent.mode": "source_code", "agent.repo_url": repo_url},
    ) as span:
        # Step 1: read source files
        files = read_repo_files(repo_dir)
        span.set_attribute("recon.file_count", len(files))

        if not files:
            logger.warning("No scannable files found in %s", repo_dir)
            return ReconOutput(
                target_url=repo_url,
                detected_framework="Unknown",
                vulnerable_endpoints=[],
            )

        # Step 2: build a compact code digest for the LLM
        # Truncate individual files to keep total prompt size reasonable
        code_digest_parts = []
        total_chars = 0
        max_total = 80_000  # ~20K tokens budget for code

        for f in files:
            content = f["content"]
            if total_chars + len(content) > max_total:
                remaining = max_total - total_chars
                if remaining > 500:
                    content = content[:remaining] + "\n... (truncated)"
                else:
                    break
            code_digest_parts.append(f"### {f['path']}\n```\n{content}\n```")
            total_chars += len(content)

        code_digest = "\n\n".join(code_digest_parts)

        # Step 3: LLM-assisted vulnerability analysis
        client = _get_client()

        example_json = json.dumps({
            "target_url": repo_url,
            "detected_framework": "Flask/Express/Django/etc",
            "vulnerable_endpoints": [
                {
                    "path": "src/routes/files.py:45",
                    "method": "GET",
                    "injection_vector": "Path traversal via unsanitized user input in os.path.join"
                }
            ]
        }, indent=2)

        system_prompt = (
            "You are an expert security code reviewer. Analyze the source code below "
            "and identify ALL security vulnerabilities.\n\n"
            "You MUST return valid JSON with EXACTLY this structure:\n"
            f"```json\n{example_json}\n```\n\n"
            "Rules:\n"
            "- target_url: the repository URL (string)\n"
            "- detected_framework: the main framework used in the project (string)\n"
            "- vulnerable_endpoints: array of objects, each with:\n"
            "  - path: file path and line number where the vulnerability exists (e.g. 'server.py:23')\n"
            "  - method: HTTP method associated (GET/POST/etc), or GET if not applicable\n"
            "  - injection_vector: detailed description of the vulnerability and how it can be exploited\n"
            "- Focus on: path traversal, SQL injection, XSS, command injection, SSRF, "
            "insecure deserialization, hardcoded secrets, auth bypass, IDOR\n"
            "- Include ALL vulnerabilities found, ranked by severity\n"
            "- Be specific about the exact line/function and the attack vector\n"
            "- If no vulnerabilities found, return empty vulnerable_endpoints array\n"
        )

        response = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Repository: {repo_url}\n\nSource code:\n{code_digest}"},
            ],
        )

        raw_json = response.choices[0].message.content
        logger.info("LLM recon response: %s", raw_json[:500])
        span.set_attribute("llm.prompt_tokens", response.usage.prompt_tokens)
        span.set_attribute("llm.completion_tokens", response.usage.completion_tokens)
        span.set_attribute("agent.decision_rationale", raw_json[:500])

        # Step 4: validate through Pydantic contract
        try:
            result = ReconOutput.model_validate_json(raw_json)
        except Exception as exc:
            logger.warning("LLM output failed validation (%s), returning empty", exc)
            result = ReconOutput(
                target_url=repo_url,
                detected_framework="Unknown",
                vulnerable_endpoints=[],
            )

        logger.info("Source recon found %d vulnerable endpoints", len(result.vulnerable_endpoints))
        return result


# ── Mode 2: HTTP Probing (legacy) ────────────────────────────────────────────

def _probe_target(target_url: str) -> str:
    """
    Perform basic HTTP probing of the target to gather raw data
    for the LLM to reason about. Returns a compact summary string.
    """
    findings: list[str] = []
    base = target_url.rstrip("/")

    # Probe common paths including path traversal attempts via /files/
    probe_paths = [
        "/",
        "/health",
        "/admin",
        "/files/readme.txt",
        "/files/../secrets/flag.txt",
        "/files/..%2Fsecrets%2Fflag.txt",
        "/files/....//secrets/flag.txt",
    ]

    for path in probe_paths:
        try:
            url = f"{base}{path}"
            resp = requests.get(url, timeout=5, allow_redirects=False)
            header_info = {
                "server": resp.headers.get("Server", "unknown"),
                "content-type": resp.headers.get("Content-Type", "unknown"),
            }

            body_preview = resp.text[:200] if resp.status_code == 200 else ""
            findings.append(
                f"GET {path} -> {resp.status_code} | "
                f"headers={json.dumps(header_info)} | "
                f"body_length={len(resp.text)} | "
                f"body_preview={body_preview!r}"
            )

            # Detect sensitive data leaks in response
            _sensitive_indicators = [
                "root:x:0", "DB_PASSWORD", "SECRET_KEY", "API_KEY",
                "-----BEGIN", "password", "AWS_ACCESS", "PRIVATE KEY",
            ]
            for indicator in _sensitive_indicators:
                if indicator in resp.text:
                    findings.append(
                        f"  [!] SENSITIVE DATA LEAK at {path}: "
                        f"response contains '{indicator}'"
                    )
                    break
        except requests.RequestException as exc:
            findings.append(f"GET {path} -> ERROR: {exc}")

    return "\n".join(findings)


def run_recon(target_url: str) -> ReconOutput:
    """
    Execute reconnaissance against *target_url* using HTTP probing
    and return a typed ReconOutput with the catalogued attack surface.
    """
    with trace_operation(
        "recon_agent",
        attributes={"agent.name": "recon", "agent.mode": "http_probe", "agent.target_url": target_url},
    ) as span:
        # Step 1: deterministic probe
        probe_data = _probe_target(target_url)
        logger.info("Recon probe complete:\n%s", probe_data)
        span.set_attribute("recon.probe_lines", probe_data.count("\n") + 1)

        # Step 2: LLM-assisted analysis with structured output
        client = _get_client()

        # Provide a concrete JSON example to anchor the LLM's output
        example_json = json.dumps({
            "target_url": "http://example.com",
            "detected_framework": "Flask/Werkzeug",
            "vulnerable_endpoints": [
                {
                    "path": "/files/../secrets/flag.txt",
                    "method": "GET",
                    "injection_vector": "Path traversal via ../ sequences in filename parameter"
                }
            ]
        }, indent=2)

        system_prompt = (
            "You are a security reconnaissance agent. Analyze the HTTP probe "
            "results below and identify ALL vulnerable endpoints.\n\n"
            "You MUST return valid JSON with EXACTLY this structure:\n"
            f"```json\n{example_json}\n```\n\n"
            "Rules:\n"
            "- target_url: the base URL of the target (string)\n"
            "- detected_framework: the server/framework from headers (string)\n"
            "- vulnerable_endpoints: array of objects, each with path, method, injection_vector\n"
            "- method must be one of: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS\n"
            "- Focus on path traversal, injection, SSRF vulnerabilities\n"
            "- If a probe returned secret/flag content, that endpoint IS vulnerable\n"
            "- Do NOT return an empty object. Always include all three required fields.\n"
        )

        response = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Target: {target_url}\n\nProbe results:\n{probe_data}"},
            ],
        )

        raw_json = response.choices[0].message.content
        logger.info("LLM recon response: %s", raw_json[:500])
        span.set_attribute("llm.prompt_tokens", response.usage.prompt_tokens)
        span.set_attribute("llm.completion_tokens", response.usage.completion_tokens)
        span.set_attribute("agent.decision_rationale", raw_json[:500])

        # Step 3: validate through Pydantic contract
        try:
            result = ReconOutput.model_validate_json(raw_json)
        except Exception as exc:
            # Fallback: if LLM output is malformed, construct from probe data
            logger.warning("LLM output failed validation (%s), using probe fallback", exc)
            result = _fallback_recon(target_url, probe_data)

        logger.info("Recon found %d vulnerable endpoints", len(result.vulnerable_endpoints))
        return result


def _fallback_recon(target_url: str, probe_data: str) -> ReconOutput:
    """
    Deterministic fallback if the LLM returns garbage.
    Parses probe_data directly for sensitive data leak indicators.
    """
    from app.schemas import VulnerableEndpoint, HttpMethod
    import re

    endpoints = []
    # Look for our deterministic leak markers in the probe output
    leak_matches = re.findall(
        r"\[!\] SENSITIVE DATA LEAK at (.+?): response contains '(.+?)'",
        probe_data,
    )
    for path, indicator in leak_matches:
        endpoints.append(
            VulnerableEndpoint(
                path=path.strip(),
                method=HttpMethod.GET,
                injection_vector=f"Sensitive data exposure: response contains '{indicator}' — possible path traversal or misconfigured endpoint",
            )
        )

    return ReconOutput(
        target_url=target_url,
        detected_framework="Unknown",
        vulnerable_endpoints=endpoints,
    )
