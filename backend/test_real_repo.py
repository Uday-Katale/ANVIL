"""
ANVIL CLI Test Runner -- Production-grade test harness for running
the full scan pipeline against a real GitHub repository.

Usage:
    python test_real_repo.py

Required environment variables (in .env file):
    OPENAI_API_KEY  -- your OpenAI API key
    GITHUB_TOKEN    -- a GitHub Personal Access Token with 'repo' scope
"""

import asyncio
import io
import os
import shutil
import sys
import uuid

# Fix Windows console encoding for Unicode output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Ensure the project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv


def _validate_env():
    """Validate all required environment variables before starting."""
    load_dotenv()

    errors = []
    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()

    if not github_token or github_token == "ghp_your_copied_token_here":
        errors.append("GITHUB_TOKEN is missing or still has the placeholder value.")
    if not openai_key or openai_key == "sk-your-openai-api-key-here":
        errors.append("OPENAI_API_KEY is missing or still has the placeholder value.")

    if errors:
        print("\n[-] CONFIGURATION ERRORS:")
        for e in errors:
            print(f"    x {e}")
        print("\n    Please update your .env file and try again.\n")
        sys.exit(1)

    return github_token, openai_key


def _cleanup_old_scans():
    """Remove old scan directories to prevent stale clone errors."""
    scans_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans")
    if os.path.isdir(scans_dir):
        count = len(os.listdir(scans_dir))
        if count > 5:
            print(f"[~] Cleaning up {count} old scan directories...")
            shutil.rmtree(scans_dir, ignore_errors=True)
            os.makedirs(scans_dir, exist_ok=True)


async def main():
    # -- 1. Validate environment --
    github_token, _ = _validate_env()

    # -- 2. Get target info --
    print("")
    print("=" * 54)
    print("       ANVIL -- Autonomous Security Engine")
    print("=" * 54)
    print("")

    repo_url = input("  Enter GitHub Repo URL: ").strip()
    if not repo_url:
        print("[-] No URL provided. Exiting.")
        sys.exit(1)

    base_branch = input("  Enter branch to scan (default: main): ").strip() or "main"
    scan_id = f"cli-{uuid.uuid4().hex[:12]}"

    # -- 3. Clean up old scans --
    _cleanup_old_scans()

    # -- 4. Initialize telemetry --
    print(f"\n[+] Scan ID: {scan_id}")
    print(f"[+] Target:  {repo_url} (branch: {base_branch})")
    print(f"[+] Initializing telemetry...")

    from app.telemetry import init_telemetry
    init_telemetry()

    # -- 5. Run the pipeline --
    print("[+] Starting scan pipeline...\n")
    print("-" * 54)

    from app.pipeline import run_scan, get_scan_result

    try:
        await run_scan(
            scan_id=scan_id,
            token=github_token,
            repo_url=repo_url,
            base_branch=base_branch,
        )
    except Exception as e:
        print(f"\n[-] Pipeline exception: {e}")

    # -- 6. Display results --
    print("-" * 54)
    result = get_scan_result(scan_id)

    print("")
    print("=" * 54)
    print("                  SCAN RESULTS")
    print("=" * 54)
    print("")

    if not result:
        print("  Status: FAILED -- No result was stored")
        print("  Check the logs above for details.\n")
        return

    status_icon = "[OK]" if result.status == "completed" else "[FAIL]"
    print(f"  Status:   {status_icon} {result.status.upper()}")
    print(f"  Stage:    {result.stage.value}")

    if result.recon:
        vuln_count = len(result.recon.vulnerable_endpoints)
        print(f"  Vulns:    {vuln_count} found")
        for i, ep in enumerate(result.recon.vulnerable_endpoints, 1):
            print(f"            [{i}] {ep.path} -- {ep.injection_vector[:80]}")

    if result.exploit:
        exploit_status = "CONFIRMED" if result.exploit.vulnerability_confirmed else "Not confirmed"
        print(f"  Exploit:  {exploit_status}")
        if result.exploit.exploit_evidence:
            print(f"  Evidence: {result.exploit.exploit_evidence[:120]}...")

    if result.verification:
        ver_status = "VERIFIED" if result.verification.verified else "Not verified"
        print(f"  Verified: {ver_status}")

    if result.patch:
        if result.pr_url:
            print(f"\n  >> Pull Request: {result.pr_url}")

    if result.error:
        print(f"\n  !! Error: {result.error}")

    print("")


if __name__ == "__main__":
    asyncio.run(main())
