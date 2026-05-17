#!/usr/bin/env python3
"""Test all critical imports and identify any issues."""

import sys
import traceback

def test_import(module_path, description):
    """Test importing a module and report results."""
    try:
        __import__(module_path)
        print(f"[OK] {description}")
        return True
    except Exception as e:
        print(f"[FAIL] {description}")
        print(f"  Error: {e}")
        return False

print("Testing critical imports...\n")

tests = [
    ("app.config", "Configuration module"),
    ("app.schemas", "Pydantic schemas"),
    ("app.db", "Database module"),
    ("app.telemetry", "Telemetry/Omium integration"),
    ("app.github_service", "GitHub service"),
    ("app.sandbox", "Sandbox execution"),
    ("app.graph", "CPN graph engine"),
    ("app.agents.recon", "Recon agent"),
    ("app.agents.exploiter", "Exploiter agent"),
    ("app.agents.verifier", "Verifier agent"),
    ("app.agents.patcher", "Patcher agent"),
    ("app.pipeline", "Pipeline runner"),
    ("app.api", "API router"),
    ("app.auth", "Auth router"),
    ("app.main", "FastAPI app"),
]

failed = []
for module, desc in tests:
    if not test_import(module, desc):
        failed.append(module)

print(f"\n{'='*60}")
if failed:
    print(f"FAILED: {len(failed)} modules failed to import")
    print(f"Failed modules: {', '.join(failed)}")
    sys.exit(1)
else:
    print("SUCCESS: All modules imported successfully!")
    sys.exit(0)

# Made with Bob
