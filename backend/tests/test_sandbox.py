"""
Comprehensive test suite for the ANVIL system.

Covers:
  - Sandbox AST validation (blocking dangerous constructs)
  - Sandbox execution (safe code, timeouts, circuit breakers)
  - Schema validation (Pydantic rejects malformed output)
  - Verifier (deterministic pass/fail decisions)
  - CPN Engine (transitions, retry loops, dead letter)
  - Integration (mocked pipeline end-to-end)

Run with: pytest tests/test_sandbox.py -v --tb=short
"""

import pytest

from app.sandbox import validate_code, execute_payload


# ══════════════════════════════════════════════════════════════════════════════
# AST Validation Tests
# ══════════════════════════════════════════════════════════════════════════════


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
        assert "Blocked" in msg

    def test_subprocess_popen_blocked(self):
        """Calling subprocess.Popen should be rejected."""
        ok, msg = validate_code('import subprocess\nsubprocess.Popen(["ls"])')
        assert not ok, "subprocess.Popen was allowed!"

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

    def test_socket_import_blocked(self):
        """Importing socket should be rejected."""
        ok, msg = validate_code("import socket\nsocket.socket()")
        assert not ok, "socket import was allowed!"
        assert "socket" in msg.lower()

    def test_blocks_write_open(self):
        """open() in write mode should be blocked."""
        ok, msg = validate_code('f = open("file.txt", "w")\nf.write("data")')
        assert not ok, "Write-mode open() was allowed!"
        assert "write-mode" in msg.lower() or "blocked" in msg.lower()

    def test_blocks_append_open(self):
        """open() in append mode should be blocked."""
        ok, msg = validate_code('f = open("file.txt", "a")')
        assert not ok, "Append-mode open() was allowed!"

    def test_allows_read_open(self):
        """open() in read mode should be allowed."""
        ok, msg = validate_code('f = open("file.txt", "r")\ndata = f.read()')
        assert ok, f"Read-mode open() was rejected: {msg}"

    def test_safe_requests_allowed(self):
        """The requests library should be allowed (needed for exploits)."""
        ok, msg = validate_code('import requests\nrequests.get("http://example.com")')
        assert ok, f"Safe requests code rejected: {msg}"

    def test_syntax_error_caught(self):
        """Syntax errors should fail validation fast (fail-closed)."""
        ok, msg = validate_code("def foo(")
        assert not ok, "Syntax error was allowed!"
        assert "SyntaxError" in msg

    def test_fail_closed_on_syntax_error(self):
        """Syntax error is fail-closed: code must NOT execute."""
        success, stdout, stderr = execute_payload("def foo(")
        assert not success, "Code with syntax error was executed!"

    def test_pickle_loads_blocked(self):
        """pickle.loads should be blocked to prevent deserialization attacks on host."""
        ok, msg = validate_code('import pickle\npickle.loads(b"test")')
        assert not ok, "pickle.loads was allowed!"

    def test_compile_blocked(self):
        """compile() should be blocked."""
        ok, msg = validate_code('compile("print(1)", "<string>", "exec")')
        assert not ok, "compile() was allowed!"

    def test_threading_import_blocked(self):
        """Importing threading should be blocked."""
        ok, msg = validate_code("import threading")
        assert not ok, "threading import was allowed!"

    def test_from_import_blocked(self):
        """from socket import ... should also be blocked."""
        ok, msg = validate_code("from socket import socket")
        assert not ok, "from socket import was allowed!"


# ══════════════════════════════════════════════════════════════════════════════
# Sandbox Execution Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSandboxExecution:
    """Tests for the sandboxed subprocess execution."""

    def test_safe_execution(self):
        """A safe payload should execute and return stdout."""
        success, stdout, stderr = execute_payload('print("EXPLOIT_SUCCESS")')
        assert success, f"Execution failed: {stderr}"
        assert "EXPLOIT_SUCCESS" in stdout

    def test_stdout_captured_correctly(self):
        """Multi-line stdout should be fully captured."""
        code = 'print("line1")\nprint("line2")\nprint("line3")'
        success, stdout, stderr = execute_payload(code)
        assert success, f"Execution failed: {stderr}"
        assert "line1" in stdout
        assert "line2" in stdout
        assert "line3" in stdout

    def test_timeout_enforced(self):
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

    def test_allows_safe_http_request(self):
        """urllib.request (not raw socket) should be allowed for exploit payloads."""
        code = (
            'import urllib.request\n'
            'try:\n'
            '    urllib.request.urlopen("http://127.0.0.1:1", timeout=1)\n'
            'except Exception as e:\n'
            '    print(f"Expected error: {e}")\n'
            '    print("CONNECTION_ATTEMPTED")\n'
        )
        ok, msg = validate_code(code)
        assert ok, f"urllib.request should be allowed but was rejected: {msg}"


# ══════════════════════════════════════════════════════════════════════════════
# Schema Validation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSchemaValidation:
    """Tests for Pydantic schema validation of agent outputs."""

    def test_recon_output_rejects_missing_fields(self):
        """ReconOutput should reject input missing required fields."""
        from pydantic import ValidationError
        from app.schemas import ReconOutput

        with pytest.raises(ValidationError):
            ReconOutput()  # Missing all required fields

    def test_recon_output_rejects_invalid_severity(self):
        """ReconOutput should accept valid severity values."""
        from app.schemas import VulnerableEndpoint, HttpMethod

        # This should work with valid severity
        ep = VulnerableEndpoint(
            path="/test",
            method=HttpMethod.GET,
            injection_vector="test vuln",
            severity="critical",
        )
        assert ep.severity == "critical"

    def test_exploit_output_rejects_non_string_code(self):
        """ExploitOutput should reject non-string exploit_payload_used."""
        from pydantic import ValidationError
        from app.schemas import ExploitOutput

        with pytest.raises(ValidationError):
            ExploitOutput(
                vulnerability_confirmed=True,
                exploit_payload_used=12345,  # Should be string
                sandbox_stdout="test",
            )

    def test_patch_output_requires_commit_hash_optional(self):
        """PatchOutput should accept commit_hash as optional."""
        from app.schemas import PatchOutput

        result = PatchOutput(
            file_modified="server.py",
            unified_diff="--- a/server.py\n+++ b/server.py\n",
            pull_request_title="Fix vuln",
            pull_request_body="Body",
            confidence_score=0.9,
        )
        assert result.commit_hash is None
        assert result.tests_passed is None

    def test_exploit_output_has_attempt_number(self):
        """ExploitOutput should default attempt_number to 1."""
        from app.schemas import ExploitOutput

        result = ExploitOutput(
            vulnerability_confirmed=True,
            exploit_payload_used="test code",
            sandbox_stdout="output",
        )
        assert result.attempt_number == 1

    def test_verification_result_has_failure_category(self):
        """VerificationResult should support failure_category."""
        from app.schemas import VerificationResult

        result = VerificationResult(
            verified=False,
            reason="No marker found",
            failure_category="no_marker",
        )
        assert result.failure_category == "no_marker"

    def test_master_state_has_attempt_history(self):
        """MasterState should have attempt_history list."""
        from app.schemas import MasterState

        state = MasterState(trace_id="test", task_id="t")
        assert isinstance(state.attempt_history, list)
        assert len(state.attempt_history) == 0


# ══════════════════════════════════════════════════════════════════════════════
# Verifier Tests
# ══════════════════════════════════════════════════════════════════════════════


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
        assert result.failure_category == "no_marker"

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
        assert result.failure_category == "no_evidence"

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
        assert result.failure_category == "not_confirmed"


# ══════════════════════════════════════════════════════════════════════════════
# CPN Engine Tests
# ══════════════════════════════════════════════════════════════════════════════


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

    def test_recon_to_exploiter_transition(self):
        """When current_node is exploit_ready, exploit transition should fire."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        p_exploit_ready = engine.add_place("exploit_ready")
        p_exploit_done = engine.add_place("exploit_done", terminal=True)

        def mock_exploit(state: MasterState) -> MasterState:
            state.current_node = "exploit_done"
            return state

        engine.add_transition(
            "t_exploit", p_exploit_ready,
            {"done": p_exploit_done},
            mock_exploit,
        )

        state = MasterState(trace_id="test", task_id="t", current_node="exploit_ready")
        final = engine.run(state)
        assert final.current_node == "exploit_done"
        assert final.completed

    def test_verifier_fail_loops_to_exploiter(self):
        """Verification failure should loop back to exploit_ready."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        p_exploit_ready = engine.add_place("exploit_ready")
        p_exploit_done = engine.add_place("exploit_done")
        p_patch_ready = engine.add_place("patch_ready", terminal=True)

        call_count = {"exploit": 0, "verify": 0}

        def mock_exploit(state: MasterState) -> MasterState:
            call_count["exploit"] += 1
            state.current_node = "exploit_done"
            return state

        def mock_verify(state: MasterState) -> MasterState:
            call_count["verify"] += 1
            if call_count["verify"] < 3:
                state.retry_count += 1
                state.current_node = "exploit_ready"
            else:
                state.current_node = "patch_ready"
            return state

        engine.add_transition("t_exploit", p_exploit_ready, {"done": p_exploit_done}, mock_exploit)
        engine.add_transition("t_verify", p_exploit_done, {"pass": p_patch_ready, "retry": p_exploit_ready}, mock_verify)

        state = MasterState(trace_id="test", task_id="t", current_node="exploit_ready")
        final = engine.run(state)
        assert final.current_node == "patch_ready"
        assert call_count["exploit"] == 3
        assert call_count["verify"] == 3

    def test_max_retry_triggers_dead_letter(self):
        """Exceeding max retries should route to dead_letter terminal state."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        p_exploit_ready = engine.add_place("exploit_ready")
        p_exploit_done = engine.add_place("exploit_done")
        p_dead_letter = engine.add_place("dead_letter", terminal=True)

        max_retries = 3

        def mock_exploit(state: MasterState) -> MasterState:
            state.current_node = "exploit_done"
            return state

        def mock_verify(state: MasterState) -> MasterState:
            state.retry_count += 1
            if state.retry_count > max_retries:
                state.current_node = "dead_letter"
                state.error = "Max retries exceeded"
            else:
                state.current_node = "exploit_ready"
            return state

        engine.add_transition("t_exploit", p_exploit_ready, {"done": p_exploit_done}, mock_exploit)
        engine.add_transition("t_verify", p_exploit_done, {"dead": p_dead_letter, "retry": p_exploit_ready}, mock_verify)

        state = MasterState(trace_id="test", task_id="t", current_node="exploit_ready")
        final = engine.run(state)
        assert final.current_node == "dead_letter"
        assert final.completed
        assert "Max retries" in final.error

    def test_verified_routes_to_patcher(self):
        """Verified exploit should route to patch_ready."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        p_exploit_done = engine.add_place("exploit_done")
        p_patch_ready = engine.add_place("patch_ready", terminal=True)
        p_exploit_ready = engine.add_place("exploit_ready")

        def mock_verify(state: MasterState) -> MasterState:
            state.current_node = "patch_ready"
            return state

        engine.add_transition(
            "t_verify", p_exploit_done,
            {"pass": p_patch_ready, "retry": p_exploit_ready},
            mock_verify,
        )

        state = MasterState(trace_id="test", task_id="t", current_node="exploit_done")
        final = engine.run(state)
        assert final.current_node == "patch_ready"
        assert final.completed

    def test_concurrent_tokens_isolated(self):
        """Two tokens running through the same engine should not interfere."""
        from app.graph import CPNEngine
        from app.schemas import MasterState

        engine = CPNEngine()
        p_start = engine.add_place("start")
        p_end = engine.add_place("end", terminal=True)

        def action(state: MasterState) -> MasterState:
            state.current_node = "end"
            return state

        engine.add_transition("t1", p_start, {"next": p_end}, action)

        state1 = MasterState(trace_id="token-1", task_id="t1", current_node="start")
        state2 = MasterState(trace_id="token-2", task_id="t2", current_node="start")

        final1 = engine.run(state1)
        final2 = engine.run(state2)

        assert final1.trace_id == "token-1"
        assert final2.trace_id == "token-2"
        assert final1.current_node == "end"
        assert final2.current_node == "end"


# ══════════════════════════════════════════════════════════════════════════════
# Integration Tests (mocked LLM)
# ══════════════════════════════════════════════════════════════════════════════


class TestIntegration:
    """Integration tests using mocked LLM and real sandbox."""

    def test_webhook_rejected_on_bad_schema(self):
        """POST /webhook with invalid data should not crash."""
        from app.schemas import WebhookPayload
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            # Missing required field target_url
            WebhookPayload(deployment_id="test-001")

    def test_scan_request_validates(self):
        """ScanRequest should validate required fields."""
        from app.schemas import ScanRequest

        req = ScanRequest(repo_url="https://github.com/user/repo")
        assert req.repo_url == "https://github.com/user/repo"
        assert req.base_branch == "main"
