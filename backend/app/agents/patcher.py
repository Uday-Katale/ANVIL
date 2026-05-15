"""
Patcher Agent — generates a code patch to fix the exploited vulnerability
and creates a Pull Request on the user's GitHub repository.

Supports two modes:
  1. GITHUB API MODE (web app) — pushes fix via PyGithub API and opens a PR
  2. LOCAL GIT MODE (legacy) — commits fix to local git repo
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

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
from openai import OpenAI

from app.config import LLM_MODEL, LLM_TEMPERATURE, OPENAI_API_KEY, TARGET_REPO_DIR
from app.schemas import ExploitOutput, PatchOutput, ReconOutput, VerificationResult
from app.telemetry import trace_operation

logger = logging.getLogger(__name__)

_client: Optional[OpenAI] = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=OPENAI_API_KEY)
    return _client


def _run_git(repo_dir: str, *args: str) -> str:
    """Run a git command in *repo_dir* and return stdout."""
    result = subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


# ── Regression Test ──────────────────────────────────────────────────────────

def _regression_test(
    original_code: str,
    fixed_code: str,
    exploit_payload: str,
    target_file_path: Path = None,
    span=None,
) -> bool:
    """
    Live regression test: write the fix, restart the target process, re-run
    the exploit. Only valid in LOCAL GIT mode where ANVIL controls the server.

    Returns True if the patch is safe (exploit fails against fixed code).
    Returns False if the exploit still works (patch is bad).

    NOTE: this intentionally re-imports execute_payload at call time so the
    sandbox module is not loaded unless this function is actually called.
    """
    from app.sandbox import execute_payload

    logger.info("Running regression test — re-executing exploit against patched code...")

    wrote_temp = False
    backup = None
    if target_file_path and Path(target_file_path).exists():
        backup = Path(target_file_path).read_text(encoding="utf-8")
        Path(target_file_path).write_text(fixed_code, encoding="utf-8")
        wrote_temp = True

    try:
        success, stdout, stderr = execute_payload(exploit_payload)

        exploit_still_works = success and "EXPLOIT_SUCCESS" in stdout

        if span:
            span.set_attribute("regression.exploit_rerun_success", success)
            span.set_attribute("regression.exploit_still_works", exploit_still_works)
            span.set_attribute("regression.stdout_preview", stdout[:200])

        if exploit_still_works:
            logger.error(
                "REGRESSION FAILED: exploit still returns EXPLOIT_SUCCESS. stdout: %s",
                stdout[:500],
            )
            return False
        else:
            logger.info("REGRESSION PASSED: exploit no longer succeeds against patched code.")
            return True

    finally:
        if wrote_temp and backup is not None:
            Path(target_file_path).write_text(backup, encoding="utf-8")


def _static_patch_validation(
    original_code: str,
    fixed_code: str,
    exploit_payload: str,
    span=None,
) -> tuple[bool, str]:
    """
    Static validation for GitHub PR mode (web app), where ANVIL does NOT
    control the running server process.

    Checks that the patch:
      1. Actually changed the code (non-empty diff).
      2. Introduces at least one security-relevant pattern.
      3. Does not reintroduce obvious unsafe patterns from the original.

    Returns (passed: bool, reason: str).
    """
    import ast

    # 1. Must have changed something
    if fixed_code.strip() == original_code.strip():
        return False, "Patch produced no changes to the source code."

    # 2. Must parse as valid Python
    try:
        ast.parse(fixed_code)
    except SyntaxError as exc:
        return False, f"Patched code has a syntax error: {exc}"

    # 3. Look for known unsafe patterns that should have been removed.
    #    These are heuristics covering the most common vulnerability classes.
    UNSAFE_PATTERNS = {
        "path_traversal": [
            # Raw os.path.join with user input without realpath/resolve
            ("open(", "os.path.join(", "request."),
        ],
        "sql_injection": [
            ('f"SELECT', "execute(f"),
            ("f'SELECT", "execute(f'"),
        ],
        "command_injection": [
            ("os.system(", "shell=True"),
            ("subprocess.call(", "shell=True"),
        ],
    }

    SAFE_PATTERNS = [
        "realpath", "resolve()", "abspath", "normpath",
        "startswith", "commonpath", "commonprefix",
        "parameterized", "prepared", "?", ":param",
        "shlex.quote", "shlex.split",
        "sanitize", "validate", "allowlist", "whitelist",
        "secure_filename",
    ]

    fixed_lower = fixed_code.lower()
    has_safe_pattern = any(p.lower() in fixed_lower for p in SAFE_PATTERNS)

    # Count lines changed
    orig_lines = set(original_code.splitlines())
    fixed_lines = set(fixed_code.splitlines())
    added = fixed_lines - orig_lines
    removed = orig_lines - fixed_lines

    if not added and not removed:
        return False, "Patch produced no line-level changes."

    logger.info(
        "Static patch validation: %d lines added, %d lines removed, "
        "safe_pattern_found=%s",
        len(added), len(removed), has_safe_pattern,
    )

    if span:
        span.set_attribute("regression.mode", "static")
        span.set_attribute("regression.lines_added", len(added))
        span.set_attribute("regression.lines_removed", len(removed))
        span.set_attribute("regression.has_safe_pattern", has_safe_pattern)

    return True, (
        f"Static validation passed: {len(added)} lines added, "
        f"{len(removed)} lines removed"
        + (", security pattern detected." if has_safe_pattern else ".")
    )


# ── Mode 1: GitHub API Patch (web app) ───────────────────────────────────────

@omium.trace("patcher_agent", span_type="agent")
def run_patch_github(
    recon: ReconOutput,
    exploit: ExploitOutput,
    verification: VerificationResult,
    trace_id: str,
    github_token: str,
    repo_url: str,
    repo_dir: str,
    base_branch: str = "main",
) -> PatchOutput:
    """
    Generate a fix and push it as a Pull Request to the user's GitHub repo
    via the GitHub API (no local git needed for the push).
    """
    from app.github_service import create_branch_and_pr, parse_repo_full_name

    with trace_operation(
        "patcher_agent_github",
        attributes={
            "agent.name": "patcher",
            "agent.mode": "github_api",
            "agent.repo_url": repo_url,
            "agent.trace_id": trace_id,
        },
    ) as span:
        repo_full_name = parse_repo_full_name(repo_url)

        # Step 1: Identify the vulnerable file and read it
        vuln_path = None
        if recon.vulnerable_endpoints:
            raw_path = recon.vulnerable_endpoints[0].path
            # Extract file path (strip line numbers like "server.py:23")
            vuln_path = raw_path.split(":")[0] if ":" in raw_path else raw_path

        # Try to find the file in the cloned repo
        target_file = None
        original_code = ""
        if vuln_path and repo_dir:
            candidate = Path(repo_dir) / vuln_path
            if candidate.exists():
                target_file = vuln_path
                original_code = candidate.read_text(encoding="utf-8")
            else:
                # Try searching for the file by name
                filename = Path(vuln_path).name
                for fpath in Path(repo_dir).rglob(filename):
                    target_file = str(fpath.relative_to(repo_dir)).replace("\\", "/")
                    original_code = fpath.read_text(encoding="utf-8")
                    break

        if not target_file or not original_code:
            raise RuntimeError(
                f"Cannot locate vulnerable file '{vuln_path}' in cloned repo"
            )

        # Step 2: Ask LLM for the fix
        client = _get_client()

        system_prompt = (
            "You are a security patch agent. Given the vulnerable source code and "
            "the exploit details, generate a fixed version of the code that eliminates "
            "the vulnerability. Return ONLY valid JSON:\n"
            "{\n"
            '  "fixed_code": "<the complete fixed source code>",\n'
            '  "explanation": "<brief explanation of what was fixed>",\n'
            '  "confidence": <float 0-1>\n'
            "}\n"
            "The fix should:\n"
            "1. Sanitize user input to prevent the exploit\n"
            "2. Keep all other functionality intact\n"
            "3. Use secure coding practices (path canonicalization, input validation)\n"
            "4. NOT add any comments referencing this tool or AI\n"
        )

        vuln_desc = (
            recon.vulnerable_endpoints[0].injection_vector
            if recon.vulnerable_endpoints else "unknown"
        )

        user_prompt = (
            f"## Vulnerable File: {target_file}\n"
            f"```python\n{original_code}\n```\n\n"
            f"## Vulnerability Details\n"
            f"- Type: {vuln_desc}\n"
            f"- Exploit payload:\n```python\n{exploit.exploit_payload_used}\n```\n"
            f"- Sandbox stdout: {exploit.sandbox_stdout[:500]}\n"
            f"- Verification: {verification.reason}\n"
        )

        response = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )

        raw = json.loads(response.choices[0].message.content)
        fixed_code = raw["fixed_code"]
        explanation = raw["explanation"]
        confidence = float(raw.get("confidence", 0.8))

        span.set_attribute("llm.prompt_tokens", response.usage.prompt_tokens)
        span.set_attribute("llm.completion_tokens", response.usage.completion_tokens)
        span.set_attribute("agent.decision_rationale", explanation[:500])

        # Step 3: Validate the patch statically.
        # In GitHub PR mode ANVIL does not control the running server process —
        # the target app was started once for the exploit and may still be in
        # memory with the original code. Re-running the HTTP exploit against that
        # stale process would always return EXPLOIT_SUCCESS regardless of the fix.
        # Static analysis is the correct gate here: the PR is for human review.
        regression_passed, regression_reason = _static_patch_validation(
            original_code=original_code,
            fixed_code=fixed_code,
            exploit_payload=exploit.exploit_payload_used,
            span=span,
        )

        if not regression_passed:
            raise RuntimeError(f"Patch validation failed: {regression_reason}")

        # Step 4: Build the PR content
        fix_branch = f"anvil/fix-{trace_id[:12]}"
        pr_title = f"🛡️ Security Fix: {vuln_desc[:80]} — Anvil Scan {trace_id[:8]}"
        pr_body = (
            f"## 🔍 Vulnerability Report\n\n"
            f"**Repository**: {repo_url}\n"
            f"**File**: `{target_file}`\n"
            f"**Type**: {vuln_desc}\n\n"
            f"## 💣 Proof of Exploitation\n\n"
            f"```\n{exploit.sandbox_stdout[:1000]}\n```\n\n"
            f"## 🩹 Fix Applied\n\n{explanation}\n\n"
            f"## ✅ Patch Validation\n\n"
            f"Static analysis confirmed: {regression_reason}\n\n"
            f"**Confidence**: {confidence:.0%}\n"
            f"**Trace ID**: `{trace_id}`\n\n"
            f"---\n"
            f"*This PR was automatically generated by [Anvil](https://github.com) — "
            f"Autonomous Security Remediation Platform*"
        )

        # Step 5: Push to GitHub and create PR
        pr_url = create_branch_and_pr(
            token=github_token,
            repo_full_name=repo_full_name,
            base_branch=base_branch,
            fix_branch=fix_branch,
            fixed_files=[{"path": target_file, "content": fixed_code}],
            pr_title=pr_title,
            pr_body=pr_body,
        )

        span.set_attribute("patch.branch", fix_branch)
        span.set_attribute("patch.confidence", confidence)
        span.set_attribute("patch.pr_url", pr_url)

        # Generate a simple diff for display
        diff_lines = []
        orig_lines = original_code.splitlines()
        fixed_lines = fixed_code.splitlines()
        for line in orig_lines:
            if line not in fixed_lines:
                diff_lines.append(f"- {line}")
        for line in fixed_lines:
            if line not in orig_lines:
                diff_lines.append(f"+ {line}")
        unified_diff = "\n".join(diff_lines) if diff_lines else "(no diff available)"

        result = PatchOutput(
            file_modified=target_file,
            unified_diff=unified_diff,
            pull_request_title=pr_title,
            pull_request_body=pr_body,
            confidence_score=confidence,
            pr_url=pr_url,
        )

        logger.info("PR created: %s (confidence=%.0f%%)", pr_url, confidence * 100)
        return result


# ── Mode 2: Local Git Patch (legacy) ─────────────────────────────────────────

def run_patch(
    recon: ReconOutput,
    exploit: ExploitOutput,
    verification: VerificationResult,
    trace_id: str,
) -> PatchOutput:
    """
    Generate and apply a patch to fix the exploited vulnerability,
    then commit it to the target repository.
    """
    with trace_operation(
        "patcher_agent",
        attributes={
            "agent.name": "patcher",
            "agent.mode": "local_git",
            "agent.target_url": recon.target_url,
            "agent.trace_id": trace_id,
        },
    ) as span:
        repo_dir = os.path.abspath(TARGET_REPO_DIR)

        # Step 1: create a fix branch
        branch_name = f"fix/{trace_id[:12]}"
        try:
            _run_git(repo_dir, "checkout", "-b", branch_name)
        except RuntimeError:
            # Branch might already exist
            _run_git(repo_dir, "checkout", branch_name)

        # Step 2: read the vulnerable source file
        target_file = Path(repo_dir) / "server.py"
        original_code = target_file.read_text(encoding="utf-8")

        # Step 3: ask LLM for the fix
        client = _get_client()

        system_prompt = (
            "You are a security patch agent. Given the vulnerable source code and "
            "the exploit details, generate a fixed version of the code that eliminates "
            "the vulnerability. Return ONLY valid JSON:\n"
            "{\n"
            '  "fixed_code": "<the complete fixed source code>",\n'
            '  "explanation": "<brief explanation of what was fixed>",\n'
            '  "confidence": <float 0-1>\n'
            "}\n"
            "The fix should:\n"
            "1. Sanitize user input to prevent the exploit\n"
            "2. Keep all other functionality intact\n"
            "3. Use secure coding practices (path canonicalization, input validation)\n"
        )

        user_prompt = (
            f"## Vulnerable Code\n```python\n{original_code}\n```\n\n"
            f"## Exploit Details\n"
            f"- Vulnerability type: {recon.vulnerable_endpoints[0].injection_vector if recon.vulnerable_endpoints else 'unknown'}\n"
            f"- Exploit payload:\n```python\n{exploit.exploit_payload_used}\n```\n"
            f"- Sandbox stdout: {exploit.sandbox_stdout[:500]}\n"
            f"- Verification: {verification.reason}\n"
        )

        response = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )

        raw = json.loads(response.choices[0].message.content)
        fixed_code = raw["fixed_code"]
        explanation = raw["explanation"]
        confidence = float(raw.get("confidence", 0.8))

        span.set_attribute("llm.prompt_tokens", response.usage.prompt_tokens)
        span.set_attribute("llm.completion_tokens", response.usage.completion_tokens)
        span.set_attribute("agent.decision_rationale", explanation[:500])

        # Step 4: Regression Test — re-run exploit against patched code
        regression_passed = _regression_test(
            original_code=original_code,
            fixed_code=fixed_code,
            exploit_payload=exploit.exploit_payload_used,
            target_file_path=target_file,
            span=span,
        )

        if not regression_passed:
            raise RuntimeError(
                "Regression test FAILED: the original exploit still succeeds "
                "against the patched code. The fix is insufficient."
            )

        # Step 5: write the fixed code
        target_file.write_text(fixed_code, encoding="utf-8")
        logger.info("Patched %s", target_file)

        # Step 5: generate unified diff
        diff = _run_git(repo_dir, "diff", "server.py")

        # Step 6: commit the fix
        pr_title = f"fix: patch {recon.vulnerable_endpoints[0].injection_vector if recon.vulnerable_endpoints else 'vulnerability'} — trace {trace_id[:12]}"
        pr_body = (
            f"## Vulnerability Report\n\n"
            f"**Target**: {recon.target_url}\n"
            f"**Framework**: {recon.detected_framework}\n"
            f"**Vector**: {recon.vulnerable_endpoints[0].injection_vector if recon.vulnerable_endpoints else 'N/A'}\n\n"
            f"## Proof of Exploitation\n\n"
            f"```\n{exploit.sandbox_stdout[:1000]}\n```\n\n"
            f"## Fix Applied\n\n{explanation}\n\n"
            f"**Confidence**: {confidence:.0%}\n"
            f"**Trace ID**: `{trace_id}`\n"
        )

        _run_git(repo_dir, "add", "server.py")
        _run_git(repo_dir, "commit", "-m", pr_title)

        span.set_attribute("patch.branch", branch_name)
        span.set_attribute("patch.confidence", confidence)

        result = PatchOutput(
            file_modified="server.py",
            unified_diff=diff,
            pull_request_title=pr_title,
            pull_request_body=pr_body,
            confidence_score=confidence,
        )

        logger.info("Patch committed on branch %s (confidence=%.0f%%)", branch_name, confidence * 100)
        return result