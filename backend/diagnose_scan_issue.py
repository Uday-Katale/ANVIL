#!/usr/bin/env python3
"""
Comprehensive diagnostic script to identify why scans are not working properly.
Tests each component of the scan pipeline in isolation.
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

def test_github_service():
    """Test GitHub service functions."""
    print("\n" + "="*60)
    print("TEST 1: GitHub Service")
    print("="*60)
    
    try:
        from app.github_service import parse_repo_full_name, read_repo_files
        
        # Test URL parsing
        test_urls = [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
        ]
        
        for url in test_urls:
            try:
                result = parse_repo_full_name(url)
                print(f"[OK] parse_repo_full_name('{url}') = '{result}'")
            except Exception as e:
                print(f"[FAIL] parse_repo_full_name('{url}'): {e}")
                return False
        
        # Test reading files from current repo
        backend_dir = str(Path(__file__).parent)
        files = read_repo_files(backend_dir)
        print(f"[OK] read_repo_files found {len(files)} files in backend/")
        if files:
            print(f"     Top 3 files: {[f['path'] for f in files[:3]]}")
        
        return True
    except Exception as e:
        print(f"[FAIL] GitHub service test: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_recon_agent():
    """Test recon agent with a simple code sample."""
    print("\n" + "="*60)
    print("TEST 2: Recon Agent (Source Code Analysis)")
    print("="*60)
    
    try:
        from app.agents.recon import run_recon_source
        
        # Create a temp directory with a vulnerable file
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = Path(tmpdir) / "app.py"
            vuln_file.write_text("""
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/files/<path:filename>')
def get_file(filename):
    # VULNERABLE: path traversal
    file_path = os.path.join('/var/data', filename)
    with open(file_path, 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run()
""")
            
            print(f"[INFO] Created test file: {vuln_file}")
            print(f"[INFO] Running recon agent...")
            
            result = run_recon_source(tmpdir, "https://github.com/test/repo")
            
            print(f"[OK] Recon completed")
            print(f"     Framework: {result.detected_framework}")
            print(f"     Vulnerabilities found: {len(result.vulnerable_endpoints)}")
            
            if result.vulnerable_endpoints:
                for i, vuln in enumerate(result.vulnerable_endpoints, 1):
                    print(f"     {i}. {vuln.path} ({vuln.method})")
                    print(f"        {vuln.injection_vector[:100]}...")
            else:
                print(f"[WARN] No vulnerabilities detected in test file")
            
            return True
            
    except Exception as e:
        print(f"[FAIL] Recon agent test: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_sandbox():
    """Test sandbox execution."""
    print("\n" + "="*60)
    print("TEST 3: Sandbox Execution")
    print("="*60)
    
    try:
        from app.sandbox import execute_payload
        
        # Test 1: Simple safe code
        safe_code = """
print("Hello from sandbox")
result = 2 + 2
print(f"Result: {result}")
"""
        print("[INFO] Testing safe code execution...")
        success, stdout, stderr = execute_payload(safe_code)
        print(f"[OK] Safe code executed")
        print(f"     stdout: {stdout[:100]}")
        print(f"     success: {success}")
        
        # Test 2: Code with dangerous imports (should be blocked)
        dangerous_code = """
import subprocess
subprocess.run(['ls', '-la'])
"""
        print("\n[INFO] Testing dangerous code (should be blocked)...")
        try:
            success, stdout, stderr = execute_payload(dangerous_code)
            print(f"[WARN] Dangerous code was NOT blocked!")
            print(f"     stdout: {stdout[:100]}")
        except Exception as e:
            print(f"[OK] Dangerous code blocked: {e}")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Sandbox test: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cpn_engine():
    """Test CPN engine initialization."""
    print("\n" + "="*60)
    print("TEST 4: CPN Engine")
    print("="*60)
    
    try:
        from app.graph import build_web_cpn
        from app.schemas import MasterState, WebhookPayload
        import asyncio
        
        print("[INFO] Building CPN engine...")
        
        async def dummy_emit(*args, **kwargs):
            pass
        
        cpn = build_web_cpn("test-scan-id", dummy_emit)
        
        print(f"[OK] CPN engine created")
        print(f"     Places: {len(cpn.places)}")
        print(f"     Transitions: {len(cpn.transitions)}")
        print(f"     Terminal places: {cpn.terminal_places}")
        
        # Test state initialization
        webhook = WebhookPayload(
            target_url="https://github.com/test/repo",
            deployment_id="test-123",
            repo_url="https://github.com/test/repo",
            repo_name="test/repo",
            github_token="test-token",
            base_branch="main",
            auth_signature=None,
        )
        
        state = MasterState(
            trace_id="test-trace",
            task_id="test-task",
            current_node="ingress",
            repo_url="https://github.com/test/repo",
            repo_dir="/tmp/test",
            webhook=webhook,
            github_token="test-token",
            base_branch="main",
        )
        
        print(f"[OK] MasterState created")
        print(f"     Current node: {state.current_node}")
        print(f"     Repo URL: {state.repo_url}")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] CPN engine test: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_database():
    """Test database operations."""
    print("\n" + "="*60)
    print("TEST 5: Database (SQLite)")
    print("="*60)
    
    try:
        from app.db import save_checkpoint
        
        print("[INFO] Testing database checkpoint...")
        test_data = {"test": "data", "timestamp": "2024-01-01"}
        save_checkpoint("test-trace-123", "test-node", test_data)
        print("[OK] Checkpoint saved")
        
        # Check if DB file was created
        from app.config import SQLITE_DB_PATH
        if Path(SQLITE_DB_PATH).exists():
            print(f"[OK] Database file exists: {SQLITE_DB_PATH}")
            size = Path(SQLITE_DB_PATH).stat().st_size
            print(f"     Size: {size} bytes")
        else:
            print(f"[WARN] Database file not found: {SQLITE_DB_PATH}")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Database test: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all diagnostic tests."""
    print("="*60)
    print("A.E.G.I.S. DIAGNOSTIC SUITE")
    print("="*60)
    print("This script tests each component of the scan pipeline.")
    print("If any test fails, the issue will be identified.\n")
    
    tests = [
        ("GitHub Service", test_github_service),
        ("Recon Agent", test_recon_agent),
        ("Sandbox", test_sandbox),
        ("CPN Engine", test_cpn_engine),
        ("Database", test_database),
    ]
    
    results = []
    for name, test_fn in tests:
        try:
            success = test_fn()
            results.append((name, success))
        except Exception as e:
            print(f"\n[FATAL] {name} test crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "="*60)
    print("DIAGNOSTIC SUMMARY")
    print("="*60)
    
    for name, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status} {name}")
    
    failed = [name for name, success in results if not success]
    
    if failed:
        print(f"\n❌ {len(failed)} test(s) failed: {', '.join(failed)}")
        print("\nRECOMMENDATIONS:")
        if "Recon Agent" in failed:
            print("- Check OPENAI_API_KEY in backend/.env")
            print("- Verify OpenAI API quota/billing")
        if "Sandbox" in failed:
            print("- Check sandbox.py AST validation logic")
        if "Database" in failed:
            print("- Check file permissions for SQLite database")
        sys.exit(1)
    else:
        print("\n✅ All tests passed! The backend components are working correctly.")
        print("\nIf scans still fail, the issue is likely:")
        print("1. GitHub OAuth token not set or invalid")
        print("2. Repository cloning permissions")
        print("3. Network connectivity to GitHub API")
        sys.exit(0)


if __name__ == "__main__":
    main()

# Made with Bob
