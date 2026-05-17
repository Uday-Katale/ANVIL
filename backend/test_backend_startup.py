#!/usr/bin/env python3
"""Test if the FastAPI backend can start without errors."""

import sys
import time
import subprocess
import requests

def test_backend_startup():
    """Start the backend and test if it responds."""
    print("Starting FastAPI backend...")
    
    # Start uvicorn in a subprocess
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for startup
    print("Waiting for backend to start...")
    max_wait = 15
    for i in range(max_wait):
        time.sleep(1)
        try:
            resp = requests.get("http://127.0.0.1:8000/health", timeout=2)
            if resp.status_code == 200:
                print(f"[OK] Backend started successfully after {i+1} seconds")
                print(f"[OK] Health check response: {resp.json()}")
                proc.terminate()
                proc.wait(timeout=5)
                return True
        except requests.exceptions.RequestException:
            continue
    
    print("[FAIL] Backend failed to start within 15 seconds")
    print("\n--- STDOUT ---")
    stdout, stderr = proc.communicate(timeout=2)
    print(stdout)
    print("\n--- STDERR ---")
    print(stderr)
    proc.terminate()
    return False

if __name__ == "__main__":
    success = test_backend_startup()
    sys.exit(0 if success else 1)

# Made with Bob
