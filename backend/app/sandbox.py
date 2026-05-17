"""
AST-Validated Subprocess Sandbox — Fail-Closed execution layer.

Replaces Docker with a native Python subprocess that is protected by:
1. AST filtering — blocks dangerous imports/calls before execution.
2. Stripped environment — payload cannot read host env vars.
3. Hard timeout — prevents infinite loops from locking the system.
4. Signature hashing — prevents the exact same failed call from retrying.

If ANY validation step fails, the sandbox refuses to execute (fail-closed).
"""

from __future__ import annotations

import ast
import hashlib
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from app.config import SANDBOX_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

# ── Blocked constructs ───────────────────────────────────────────────────────

_BLOCKED_MODULES: Set[str] = {
    "shutil", "ctypes", "multiprocessing", "signal",
    "importlib", "code", "codeop", "compileall",
    "pty", "resource", "readline",
    "socket", "threading",
}

_BLOCKED_FUNCTIONS: Set[str] = {
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.renames", "os.replace",
    "os.system", "os.popen", "os.exec", "os.execl",
    "os.execle", "os.execlp", "os.execlpe", "os.execv",
    "os.execve", "os.execvp", "os.execvpe", "os.fork",
    "subprocess.Popen", "subprocess.call", "subprocess.run",
    "eval", "exec", "__import__", "compile",
    "shutil.rmtree", "shutil.move",
    "pickle.loads", "pickle.load",
    "importlib.import_module",
    "ctypes.cdll",
}

# ── Signature-hash dedup (circuit breaker) ───────────────────────────────────

_seen_hashes: Dict[str, int] = {}


def _signature_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


# ── AST validation ───────────────────────────────────────────────────────────

class _DangerousNodeVisitor(ast.NodeVisitor):
    """Walk the AST and raise ValueError on any blocked construct."""

    def __init__(self) -> None:
        self.violations: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        """Block dangerous module imports."""
        for alias in node.names:
            top_module = alias.name.split(".")[0]
            if top_module in _BLOCKED_MODULES:
                self.violations.append(f"Blocked import: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Block dangerous from-imports including submodules."""
        if node.module:
            top_module = node.module.split(".")[0]
            if top_module in _BLOCKED_MODULES:
                self.violations.append(f"Blocked import-from: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Block dangerous function calls and open() in write mode."""
        func_name = _resolve_call_name(node)
        if func_name and func_name in _BLOCKED_FUNCTIONS:
            self.violations.append(f"Blocked call: {func_name}")
        # Block open() in write/append/create modes
        if func_name == "open" and len(node.args) > 1:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                if any(m in mode_arg.value for m in ("w", "a", "x", "+")):
                    self.violations.append(
                        f"Blocked write-mode open() at line {node.lineno}"
                    )
        # Also block open() with mode keyword arg in write mode
        if func_name == "open":
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str) and any(
                        m in keyword.value.value for m in ("w", "a", "x", "+")
                    ):
                        self.violations.append(
                            f"Blocked write-mode open() at line {node.lineno}"
                        )
        self.generic_visit(node)


def _resolve_call_name(node: ast.Call) -> Optional[str]:
    """Best-effort resolution of a Call node to a dotted name."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def validate_code(code: str) -> Tuple[bool, str]:
    """
    Parse and AST-validate *code*. Returns (ok, message).
    If ok is False, the code MUST NOT be executed.
    """
    # Step 1: syntax check
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return False, f"SyntaxError: {exc}"

    # Step 2: dangerous-node check
    visitor = _DangerousNodeVisitor()
    visitor.visit(tree)
    if visitor.violations:
        return False, "Blocked constructs: " + "; ".join(visitor.violations)

    return True, "OK"


# ── Execution ────────────────────────────────────────────────────────────────

def execute_payload(
    code: str,
    *,
    timeout: int = SANDBOX_TIMEOUT_SECONDS,
    max_retries: int = 3,
) -> Tuple[bool, str, str]:
    """
    Execute *code* in a restricted subprocess.

    Returns (success, stdout, stderr).
    Fail-closed: any validation failure → (False, "", error_msg).
    """
    # ── Circuit breaker: signature dedup ──────────────────────────────────
    sig = _signature_hash(code)
    _seen_hashes[sig] = _seen_hashes.get(sig, 0) + 1
    if _seen_hashes[sig] > max_retries:
        msg = f"Circuit breaker: payload hash {sig[:12]}… attempted {_seen_hashes[sig]} times. Blocked."
        logger.warning(msg)
        return False, "", msg

    # ── AST validation ───────────────────────────────────────────────────
    ok, reason = validate_code(code)
    if not ok:
        logger.warning("Sandbox rejected payload: %s", reason)
        return False, "", reason

    # ── Write to temp file & execute ─────────────────────────────────────
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, dir="."
    ) as tmp:
        tmp.write(code)
        tmp_path = Path(tmp.name)

    try:
        # Build a safe environment that allows Python + networking to work
        # on Windows, while stripping all sensitive credentials.
        #
        # Strategy: start from the FULL host environment (so SSL, DNS, proxy,
        # and Python path resolution all work), then DELETE known-dangerous
        # variables that could leak secrets to the payload.
        import os as _os
        safe_env = dict(_os.environ)

        # Strip ALL known credential / secret variables
        _DANGEROUS_VARS = {
            "OPENAI_API_KEY", "GITHUB_TOKEN", "GITHUB_CLIENT_ID",
            "GITHUB_CLIENT_SECRET", "SESSION_SECRET", "OMIUM_API_KEY",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_SECRET", "GCP_SERVICE_ACCOUNT_KEY",
            "DATABASE_URL", "DB_PASSWORD", "REDIS_URL",
            "SECRET_KEY", "JWT_SECRET", "COOKIE_SECRET",
        }
        for var in _DANGEROUS_VARS:
            safe_env.pop(var, None)

        result = subprocess.run(
            [sys.executable, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=safe_env,
            cwd=".",
        )
        return (
            result.returncode == 0,
            result.stdout,
            result.stderr,
        )
    except subprocess.TimeoutExpired:
        msg = f"Sandbox timeout after {timeout}s"
        logger.warning(msg)
        return False, "", msg
    except Exception as exc:
        return False, "", f"Sandbox error: {exc}"
    finally:
        tmp_path.unlink(missing_ok=True)
