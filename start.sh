#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ANVIL — localhost launcher (no Docker)
#
# Usage:  ./start.sh
#
# Starts Redis (if not already running), FastAPI backend, and Vite frontend
# in separate terminal windows / tmux panes, or falls back to background jobs.
# ─────────────────────────────────────────────────────────────────────────────

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

# ── 0. Preflight checks ───────────────────────────────────────────────────────

command -v python3 >/dev/null 2>&1 || { echo "❌  python3 not found. Install Python 3.11+"; exit 1; }
command -v node    >/dev/null 2>&1 || { echo "❌  node not found. Install Node.js 20+"; exit 1; }
command -v redis-server >/dev/null 2>&1 || {
  echo "⚠️   redis-server not found."
  echo "    macOS:   brew install redis"
  echo "    Ubuntu:  sudo apt install redis-server"
  echo "    Windows: install Memurai or run in WSL"
  exit 1
}

# ── 1. Check .env exists ──────────────────────────────────────────────────────

if [ ! -f "$BACKEND/.env" ]; then
  echo "⚠️   backend/.env not found — copying from .env.example"
  cp "$BACKEND/.env.example" "$BACKEND/.env"
  echo "    ✏️   Please edit backend/.env and fill in your API keys, then re-run."
  exit 1
fi

# ── 2. Start Redis (if not already running) ───────────────────────────────────

if redis-cli ping >/dev/null 2>&1; then
  echo "✅  Redis already running"
else
  echo "🚀  Starting Redis..."
  redis-server --daemonize yes --loglevel warning
  sleep 1
  redis-cli ping >/dev/null && echo "✅  Redis started" || { echo "❌  Redis failed to start"; exit 1; }
fi

# ── 3. Start FastAPI backend ──────────────────────────────────────────────────

echo "🚀  Starting FastAPI backend on http://localhost:8000 ..."
cd "$BACKEND"

# Create virtual environment if it doesn't exist
if [ ! -d .venv ]; then
  echo "📦  Creating Python virtual environment..."
  python3 -m venv .venv
fi

# Activate the virtual environment
source .venv/bin/activate

# Install deps if uvicorn isn't available in the venv
if ! python3 -c "import uvicorn" 2>/dev/null; then
  echo "📦  Installing Python dependencies..."
  pip install -r requirements.txt
fi

python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo "    Backend PID: $BACKEND_PID"

# ── 4. Start Vite frontend ────────────────────────────────────────────────────

echo "🚀  Starting Vite frontend on http://localhost:5173 ..."
cd "$FRONTEND"

if [ ! -d node_modules ]; then
  echo "📦  Installing Node dependencies..."
  npm install
fi

npm run dev &
FRONTEND_PID=$!
echo "    Frontend PID: $FRONTEND_PID"

# ── 5. Wait and handle Ctrl-C ────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════"
echo "  ANVIL is running!"
echo "  Frontend  →  http://localhost:5173"
echo "  Backend   →  http://localhost:8000/docs"
echo "  Press Ctrl-C to stop all services."
echo "═══════════════════════════════════════════"
echo ""

trap "echo ''; echo 'Stopping...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

wait
