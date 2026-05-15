"""
TDD Tests for the AST-Validated Subprocess Sandbox.

Following the /tdd skill: vertical slices, one test at a time,
testing behavior through the public interface.

Run with: pytest tests/ -v
"""

import pytest

from app.sandbox import validate_code, execute_payload


# ── AST Validation Tests ─────────────────────────────────────────────────────


class TestASTValidation:
    """Tests for the AST-based code validation layer."""

    def test_safe_code_accepted(self):
        """Safe code should pass AST validation."""
        ok, msg = validate_code('print("hello world")')
        assert ok, f"Safe code rejected: {msg}"

    def test_dangerous_import_blocked(self):
        """Importing blocked modules like shutil should be rejected."""
        ok, msg = validate_code('import shutil\nshutil.rmtree("/")')
        assert not ok, "Dangerous import was allowed!"
        assert "shutil" in msg

    def test_os_remove_blocked(self):
        """Calling os.remove should be rejected."""
        ok, msg = validate_code('import os\nos.remove("file.txt")')
        assert not ok, "os.remove was allowed!"

    def test_subprocess_blocked(self):
        """Calling subprocess.run should be rejected."""
        ok, msg = validate_code('import subprocess\nsubprocess.run(["ls"])')
        assert not ok, "subprocess.run was allowed!"

    def test_syntax_error_caught(self):
        """Syntax errors should fail validation fast."""
        ok, msg = validate_code("def foo(")
        assert not ok, "Syntax error was allowed!"
        assert "SyntaxError" in msg

    def test_eval_blocked(self):
        """Direct eval() calls should be rejected."""
        ok, msg = validate_code('eval("1+1")')
        assert not ok, "eval was allowed!"

    def test_exec_blocked(self):
        """Direct exec() calls should be rejected."""
        ok, msg = validate_code('exec("print(1)")')
        assert not ok, "exec was allowed!"

    def test_ctypes_blocked(self):
        """Importing ctypes should be rejected."""
        ok, msg = validate_code("import ctypes")
        assert not ok, "ctypes import was allowed!"

    def test_safe_requests_allowed(self):
        """The requests library should be allowed (needed for exploits)."""
        ok, msg = validate_code('import requests\nrequests.get("http://example.com")')
        assert ok, f"Safe requests code rejected: {msg}"


# ── Sandbox Execution Tests ──────────────────────────────────────────────────


class TestSandboxExecution:
    """Tests for the sandboxed subprocess execution."""

    def test_safe_execution(self):
        """A safe payload should execute and return stdout."""
        success, stdout, stderr = execute_payload('print("EXPLOIT_SUCCESS")')
        assert success, f"Execution failed: {stderr}"
        assert "EXPLOIT_SUCCESS" in stdout

    def test_timeout_enforcement(self):
        """Infinite loops should be killed by the timeout."""
        code = "while True: pass"
        success, stdout, stderr = execute_payload(code, timeout=2)
        assert not success, "Infinite loop was not killed!"
        assert "timeout" in stderr.lower()

    def test_dangerous_code_never_runs(self):
        """Code that fails AST validation should never execute."""
        success, stdout, stderr = execute_payload('import shutil\nshutil.rmtree("/")')
        assert not success, "Dangerous code was executed!"
        assert "Blocked" in stderr

    def test_circuit_breaker(self):
        """The same failing payload hash should be blocked after max retries."""
        unique_code = 'raise Exception("circuit_breaker_test_unique_payload_xyz")'
        # Run it 4 times (max_retries=3 means blocked on 4th attempt)
        for i in range(3):
            execute_payload(unique_code, max_retries=3)
        success, stdout, stderr = execute_payload(unique_code, max_retries=3)
        assert not success, "Circuit breaker did not trigger!"
        assert "Circuit breaker" in stderr


# ── Verifier Tests ───────────────────────────────────────────────────────────


class TestVerifier:
    """Tests for the deterministic verifier agent."""

    def test_real_exploit_verifies(self):
        """An exploit with real evidence should be verified."""
        from app.schemas import ExploitOutput
        from app.agents.verifier import verify_exploit

        exploit = ExploitOutput(
            vulnerability_confirmed=True,
            exploit_payload_used="test",
            sandbox_stdout="root:x:0:0:root:/root:/bin/bash\nEXPLOIT_SUCCESS",
            exploit_evidence="root:x:0:0:root:/root:/bin/bash",
        )
        result = verify_exploit(exploit)
        assert result.verified, f"Should verify: {result.reason}"

    def test_missing_marker_rejects(self):
        """Missing EXPLOIT_SUCCESS marker should reject."""
        from app.schemas import ExploitOutput
        from app.agents.verifier import verify_exploit

        exploit = ExploitOutput(
            vulnerability_confirmed=True,
            exploit_payload_used="test",
            sandbox_stdout="some output without marker",
            exploit_evidence=None,
        )
        result = verify_exploit(exploit)
        assert not result.verified

    def test_hallucinated_exploit_rejects(self):
        """Marker-only exploits with no evidence should be rejected."""
        from app.schemas import ExploitOutput
        from app.agents.verifier import verify_exploit

        exploit = ExploitOutput(
            vulnerability_confirmed=True,
            exploit_payload_used="test",
            sandbox_stdout="EXPLOIT_SUCCESS",
            exploit_evidence=None,
        )
        result = verify_exploit(exploit)
        assert not result.verified

    def test_self_reported_failure_rejects(self):
        """vulnerability_confirmed=False should always reject."""
        from app.schemas import ExploitOutput
        from app.agents.verifier import verify_exploit

        exploit = ExploitOutput(
            vulnerability_confirmed=False,
            exploit_payload_used="test",
            sandbox_stdout="data\nEXPLOIT_SUCCESS",
            exploit_evidence=None,
        )
        result = verify_exploit(exploit)
        assert not result.verified


# ── CPN Engine Tests ─────────────────────────────────────────────────────────


class TestCPNEngine:
    """Tests for the Colored Petri Net engine."""

    def test_linear_traversal(self):
        """Engine should traverse a simple linear graph."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        p1 = engine.add_place("start")
        p2 = engine.add_place("middle")
        p3 = engine.add_place("end", terminal=True)

        engine.add_transition("t1", p1, {"next": p2}, lambda s: setattr(s, "current_node", "middle") or s)
        engine.add_transition("t2", p2, {"next": p3}, lambda s: setattr(s, "current_node", "end") or s)

        state = MasterState(trace_id="test", task_id="t", current_node="start")
        final = engine.run(state)
        assert final.current_node == "end"
        assert final.completed

    def test_deadlock_detection(self):
        """Engine should detect and report deadlocks."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        engine.add_place("a")
        engine.add_place("b", terminal=True)

        state = MasterState(trace_id="test", task_id="t", current_node="a")
        final = engine.run(state)
        assert final.error and "Deadlock" in final.error

    def test_max_steps_breaker(self):
        """Engine should halt after 20 steps even if transitions keep firing."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        p = engine.add_place("loop")
        engine.add_transition("t", p, {"self": p}, lambda s: s)

        state = MasterState(trace_id="test", task_id="t", current_node="loop")
        final = engine.run(state)
        assert final.error and "max steps" in final.error.lower()
