"""
GitHub service — handles all GitHub API and git CLI interactions.

Provides:
  - clone_repo: shallow-clones a repo using token-based HTTPS auth
  - read_repo_files: reads source files from disk for analysis
  - create_branch_and_pr: commits a fix and opens a Pull Request
  - parse_repo_full_name: extracts 'owner/repo' from any GitHub URL
  - cleanup_scan_dir: removes temporary scan directories
  - exchange_code_for_token: exchanges OAuth code for access token
  - get_github_user: fetches the authenticated user's info
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import httpx
from github import Github

from app.config import GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET

logger = logging.getLogger(__name__)

# All scan clones go under this directory (relative to CWD)
SCAN_TEMP_DIR = os.getenv("SCAN_TEMP_DIR", "scans")


# ── URL Parsing ──────────────────────────────────────────────────────────────

def parse_repo_full_name(repo_url: str) -> str:
    """Extract 'owner/repo' from an HTTPS or SSH GitHub URL."""
    # HTTPS: https://github.com/owner/repo or https://github.com/owner/repo.git
    match = re.match(r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", repo_url)
    if match:
        return match.group(1)

    # SSH: git@github.com:owner/repo.git
    match = re.match(r"git@github\.com:([^/]+/[^/]+?)(?:\.git)?$", repo_url)
    if match:
        return match.group(1)

    raise ValueError(f"Cannot parse GitHub repo from URL: {repo_url}")


# ── Clone ────────────────────────────────────────────────────────────────────

def clone_repo(token: str, repo_url: str, scan_id: str) -> str:
    """
    Clone a GitHub repo into a temporary directory inside SCAN_TEMP_DIR.
    Uses the token for HTTPS authentication.
    Returns the absolute path to the cloned directory.

    If the destination already exists (from a previous failed run),
    it is removed before cloning.
    """
    full_name = parse_repo_full_name(repo_url)
    clone_url = f"https://x-access-token:{token}@github.com/{full_name}.git"

    dest = Path(SCAN_TEMP_DIR) / scan_id
    repo_path = dest / "repo"

    # Clean up stale clone from any previous run
    if repo_path.exists():
        logger.warning("Removing stale clone directory: %s", repo_path)
        shutil.rmtree(repo_path, ignore_errors=True)

    dest.mkdir(parents=True, exist_ok=True)

    logger.info("Cloning %s into %s", full_name, repo_path)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr}")

    repo_dir = str(repo_path)
    logger.info("Clone complete: %s", repo_dir)
    return repo_dir


# ── Read repo files for analysis ─────────────────────────────────────────────

# Extensions we'll feed to the recon agent for vulnerability analysis
_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php",
    ".go", ".rs", ".c", ".cpp", ".h", ".cs", ".swift", ".kt",
    ".html", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".env", ".sql", ".sh", ".bash", ".dockerfile",
}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "vendor", ".tox",
}

_MAX_FILE_SIZE = 100_000  # 100 KB limit per file


def read_repo_files(repo_dir: str) -> list[dict]:
    """
    Walk *repo_dir* and read scannable source files.
    Returns list of {"path": relative_path, "content": text_content}.
    """
    files = []
    root = Path(repo_dir)

    if not root.exists():
        logger.warning("Repo dir does not exist: %s", repo_dir)
        return files

    for path in root.rglob("*"):
        # Skip directories and non-scannable files
        if not path.is_file():
            continue

        # Skip ANVIL-generated launcher files
        if path.name == "__anvil_launcher__.py":
            continue

        # Check if any parent directory should be skipped
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue

        if path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
            continue

        if path.stat().st_size > _MAX_FILE_SIZE:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            files.append({"path": str(rel), "content": content})
        except Exception:
            pass  # Skip unreadable files silently

    logger.info("Read %d scannable files from %s", len(files), repo_dir)
    return files


def detect_entry_point(repo_dir: str) -> Optional[str]:
    """
    Detect the main runnable Python entry point of a web application.
    Returns the relative path to the entry script, or None.

    Heuristics (in priority order):
      1. A file containing `if __name__ == '__main__':` with `app.run(`
      2. A file named app.py, main.py, server.py, run.py, wsgi.py
      3. The first .py file importing flask/fastapi/django
    """
    root = Path(repo_dir)
    candidates = []

    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        has_main_guard = "__name__" in content and "__main__" in content
        has_app_run = "app.run(" in content or "uvicorn.run(" in content
        has_framework = any(fw in content for fw in ("flask", "Flask", "FastAPI", "fastapi", "Django", "django"))

        score = 0
        if has_main_guard and has_app_run:
            score = 100
        elif path.name in ("app.py", "main.py", "server.py", "run.py", "wsgi.py"):
            score = 50
        elif has_framework:
            score = 25
        
        if score > 0:
            candidates.append((score, str(rel), content))

    if not candidates:
        return None

    # Return the highest-scored candidate
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_path = candidates[0][1]
    logger.info("Detected entry point: %s (score=%d)", best_path, candidates[0][0])
    return best_path


# ── Cleanup ──────────────────────────────────────────────────────────────────

def cleanup_scan_dir(scan_id: str) -> None:
    """Remove the scan directory if it exists."""
    dest = Path(SCAN_TEMP_DIR) / scan_id
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
        logger.info("Cleaned up scan dir: %s", dest)


# ── GitHub API: branches + PRs ───────────────────────────────────────────────

def create_branch_and_pr(
    *,
    # Accept both naming conventions for backward compatibility
    github_token: str = None,
    token: str = None,
    repo_url: str = None,
    repo_full_name: str = None,
    branch_name: str = None,
    fix_branch: str = None,
    base_branch: str = "main",
    # Single file mode
    file_path: str = None,
    new_content: str = None,
    # Multi-file mode (from patcher)
    fixed_files: list = None,
    commit_message: str = "fix: automated security patch by ANVIL",
    pr_title: str = "Security Fix",
    pr_body: str = "",
) -> str:
    """
    Create a fix branch, commit the patched file(s), and open a Pull Request.
    Returns the URL of the created PR.
    """
    # Resolve parameter aliases
    _token = github_token or token
    _branch = branch_name or fix_branch
    if not _token:
        raise ValueError("github_token or token is required")
    if not _branch:
        raise ValueError("branch_name or fix_branch is required")

    # Resolve repo name
    if repo_full_name:
        full_name = repo_full_name
    elif repo_url:
        full_name = parse_repo_full_name(repo_url)
    else:
        raise ValueError("repo_url or repo_full_name is required")

    g = Github(_token)
    repo = g.get_repo(full_name)

    # Get the SHA of the base branch head
    base_ref = repo.get_git_ref(f"heads/{base_branch}")
    base_sha = base_ref.object.sha

    # Create the new branch
    try:
        repo.create_git_ref(ref=f"refs/heads/{_branch}", sha=base_sha)
        logger.info("Created branch: %s", _branch)
    except Exception as exc:
        if "Reference already exists" in str(exc):
            logger.warning("Branch %s already exists, reusing", _branch)
        else:
            raise

    # Build list of files to commit
    files_to_commit = []
    if fixed_files:
        files_to_commit = fixed_files  # [{path, content}, ...]
    elif file_path and new_content:
        files_to_commit = [{"path": file_path, "content": new_content}]
    else:
        raise ValueError("Either fixed_files or (file_path + new_content) is required")

    # Commit each file
    for f in files_to_commit:
        fpath = f["path"]
        fcontent = f["content"]
        try:
            contents = repo.get_contents(fpath, ref=_branch)
            repo.update_file(
                path=fpath,
                message=commit_message,
                content=fcontent,
                sha=contents.sha,
                branch=_branch,
            )
        except Exception:
            repo.create_file(
                path=fpath,
                message=commit_message,
                content=fcontent,
                branch=_branch,
            )
        logger.info("Committed fix to %s on branch %s", fpath, _branch)

    # Open the PR
    pr = repo.create_pull(
        title=pr_title,
        body=pr_body,
        head=_branch,
        base=base_branch,
    )
    logger.info("PR created: %s", pr.html_url)
    return pr.html_url


# ── OAuth helpers ────────────────────────────────────────────────────────────

async def exchange_code_for_token(code: str) -> str:
    """Exchange a GitHub OAuth authorization code for an access token."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()

    token = data.get("access_token")
    if not token:
        raise ValueError(f"GitHub token exchange failed: {data}")
    return token


async def get_github_user(token: str) -> dict:
    """Fetch the authenticated user's profile from GitHub."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()
