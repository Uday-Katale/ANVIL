/**
 * A.E.G.I.S. API Client
 * All communication with the FastAPI backend lives here.
 * The Vite proxy forwards /api → http://localhost:8000/api
 */

const BASE = import.meta.env.VITE_API_URL || ''; // relative — Vite proxy handles it locally

// ── Auth ──────────────────────────────────────────────────────────────────────

/** Returns the GitHub user object or null if unauthenticated. */
export async function getMe() {
  try {
    const res = await fetch(`${BASE}/api/auth/me`, { credentials: 'include' });
    if (res.status === 401) return null;
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/** Kick off GitHub OAuth — navigates the browser to /api/auth/github */
export function loginWithGitHub() {
  window.location.href = `${BASE}/api/auth/github`;
}

/** Clear the session cookie. */
export async function logout() {
  await fetch(`${BASE}/api/auth/logout`, { method: 'POST', credentials: 'include' });
}

// ── Scan ──────────────────────────────────────────────────────────────────────

/**
 * Start a new scan.
 * @param {string} repoUrl  - e.g. "https://github.com/owner/repo"
 * @param {string} baseBranch - default "main"
 * @returns {{ scan_id, stream_url, status }} or throws
 */
export async function startScan(repoUrl, baseBranch = 'main') {
  const res = await fetch(`${BASE}/api/scan`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_url: repoUrl, base_branch: baseBranch }),
  });

  if (res.status === 401) {
    const err = new Error('Not authenticated');
    err.code = 401;
    throw err;
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Subscribe to real-time SSE events for a scan.
 *
 * @param {string} scanId
 * @param {(event: ScanEvent) => void} onEvent  - called for every stage event
 * @param {(err: Error) => void}       onError  - called on fatal error
 * @returns {() => void}  call this to close the connection
 */
export function streamScan(scanId, onEvent, onError) {
  const url = `${BASE}/api/scan/${scanId}/stream`;
  const es = new EventSource(url, { withCredentials: true });

  // The backend sets `event:` to the stage name, `data:` to JSON
  const STAGES = ['queued','cloning','recon','exploit','verify','patch','pushing','completed','failed'];

  // Track whether we've hit a terminal state (completed/failed)
  let terminated = false;
  let retryCount = 0;
  const MAX_RETRIES = 8;

  STAGES.forEach(stage => {
    es.addEventListener(stage, (e) => {
      try {
        // Connection succeeded — reset retry counter
        retryCount = 0;
        const data = JSON.parse(e.data);
        onEvent({ ...data, stage });

        // Mark terminal so we don't treat post-close errors as failures
        if (stage === 'completed' || stage === 'failed') {
          terminated = true;
        }
      } catch (err) {
        console.warn('Failed to parse SSE data:', e.data);
      }
    });
  });

  es.addEventListener('keepalive', () => {
    // Keepalive received — connection is healthy, reset retry counter
    retryCount = 0;
  });

  es.onerror = () => {
    // After a terminal event, ignore close/error — it's expected
    if (terminated) {
      es.close();
      return;
    }
    // EventSource auto-reconnects; only fatal-out after max retries
    if (es.readyState === EventSource.CLOSED) {
      // Browser gave up reconnecting
      onError(new Error('SSE connection closed unexpectedly'));
      return;
    }
    retryCount++;
    if (retryCount > MAX_RETRIES) {
      es.close();
      onError(new Error('SSE connection failed after multiple retries'));
    }
    // Otherwise, let EventSource auto-reconnect silently
  };

  // Return cleanup fn
  return () => {
    terminated = true;
    es.close();
  };
}

/**
 * Fetch the full ScanResult for a completed scan.
 * @param {string} scanId
 * @returns {ScanResult}
 */
export async function getScanResult(scanId) {
  const res = await fetch(`${BASE}/api/scan/${scanId}`, { credentials: 'include' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
