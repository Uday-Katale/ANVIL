import { useState, useCallback, useRef } from 'react';
import { startScan, streamScan, getScanResult } from '../api/client.js';

/**
 * SSE stage → Petri net node mapping
 */
const STAGE_TO_NODE = {
  queued:    'trigger',
  cloning:   'trigger',
  recon:     'recon',
  exploit:   'exploit',
  verify:    'verify',
  patch:     'patch',
  pushing:   'patch',
  completed: 'end',
  failed:    'error',
};

/**
 * SSE stage → terminal log type
 */
const STAGE_TYPE = {
  queued:    'system',
  cloning:   'agent',
  recon:     'agent',
  exploit:   'warn',
  verify:    'agent',
  patch:     'success',
  pushing:   'success',
  completed: 'finish',
  failed:    'error',
};

/**
 * Format a ScanEvent into a human-readable terminal log line
 */
function eventToLogLine(ev) {
  const icons = {
    queued:    '▶',
    cloning:   '[CLONING]',
    recon:     '[RECON AGENT]',
    exploit:   '[EXPLOIT AGENT]',
    verify:    '[VERIFIER]',
    patch:     '[PATCHER AGENT]',
    pushing:   '[PATCHER AGENT]',
    completed: '▶',
    failed:    '✗',
  };
  const icon = icons[ev.stage] || '>';
  let text = `${icon} ${ev.message}`;
  if (ev.detail) text += `\n  ↳ ${ev.detail}`;
  return { text, type: ev.status === 'error' ? 'warn' : STAGE_TYPE[ev.stage] || 'system' };
}

/**
 * Manages the full scan lifecycle:
 *   idle → scanning → complete | failed
 */
export function useScan() {
  const [phase, setPhase]         = useState('idle');      // idle|scanning|complete|failed
  const [scanId, setScanId]       = useState(null);
  const [petriStage, setPetriStage] = useState('idle');
  const [logs, setLogs]           = useState([]);          // terminal log lines
  const [progress, setProgress]   = useState(0);           // 0–100
  const [result, setResult]       = useState(null);        // ScanResult when complete
  const [error, setError]         = useState(null);        // string on failure
  const [retryInfo, setRetryInfo] = useState(null);        // {attempt, max} during verify retry
  const closeSSE = useRef(null);

  // Use a ref to track phase so SSE callbacks always see the latest value
  // This fixes the stale closure bug where the onError callback captured
  // the initial 'idle' phase value instead of the current one.
  const phaseRef = useRef('idle');
  const setPhaseTracked = useCallback((newPhase) => {
    phaseRef.current = newPhase;
    setPhase(newPhase);
  }, []);

  // Track the repo URL being scanned so we can display it
  const [repoUrl, setRepoUrl] = useState(null);

  /** Append a line to the terminal */
  const addLog = useCallback((text, type = 'system') => {
    setLogs(prev => [...prev, { text, type, id: Date.now() + Math.random() }]);
  }, []);

  /** Fire the scan against a repo URL */
  const start = useCallback(async (url, baseBranch = 'main') => {
    // Reset state
    setPhaseTracked('scanning');
    setScanId(null);
    setRepoUrl(url);
    setLogs([]);
    setProgress(0);
    setResult(null);
    setError(null);
    setRetryInfo(null);
    setPetriStage('idle');

    addLog('▶ A.E.G.I.S. v2.0.0 — Autonomous Exploit Generation and Intelligent Security', 'system');
    addLog(`▶ Omium trace initialized — W3C Trace Context propagation active`, 'system');
    addLog(`▶ Redis Streams connected. SQLite WAL checkpoint active.`, 'system');
    addLog(`⚡ [WEBHOOK] POST /api/scan — repo: ${url}`, 'event');

    try {
      const resp = await startScan(url, baseBranch);
      const id = resp.scan_id;
      setScanId(id);

      addLog(`  ↳ HTTP 202 Accepted — scan_id: ${id}`, 'system');
      addLog(`  ↳ Petri net initialized at IDLE → TRIGGER`, 'system');
      setPetriStage('trigger');

      // Subscribe to SSE stream
      closeSSE.current = streamScan(
        id,
        // onEvent
        async (ev) => {
          // Update progress bar
          setProgress(ev.progress_pct ?? 0);

          // Update Petri net
          const node = STAGE_TO_NODE[ev.stage];
          if (node) setPetriStage(node);

          // Detect retry during verify
          if (ev.stage === 'verify' && ev.status === 'running' && ev.message?.includes('retrying')) {
            const m = ev.message.match(/attempt (\d+)\/(\d+)/);
            if (m) setRetryInfo({ attempt: parseInt(m[1]), max: parseInt(m[2]) });
          } else {
            setRetryInfo(null);
          }

          // Special: capture flag from exploit stdout
          if (ev.stage === 'exploit' && ev.status === 'done' && ev.detail?.includes('FLAG{')) {
            addLog(`  ↳ stdout: ${ev.detail}`, 'flag');
          }

          // Add standard log line
          const line = eventToLogLine(ev);
          addLog(line.text, line.type);
          if (ev.detail && !ev.detail.includes('FLAG{')) {
            addLog(`  ↳ ${ev.detail}`, 'data');
          }

          // Petri net checkpoint messages
          const transitions = {
            cloning:   'Petri net: IDLE → CLONING',
            recon:     'Petri net: CLONING → RECON [t2_run_recon firing]',
            exploit:   'Petri net: RECON → EXPLOIT [is_vulnerable=True]',
            verify:    'Petri net: EXPLOIT → VERIFY [exploit_done]',
            patch:     'Petri net: VERIFY → PATCH [verified=True]',
            pushing:   'Petri net: PATCH → PUSHING',
            completed: 'Petri net: PUSHING → END_WORKFLOW ✓',
          };
          if (transitions[ev.stage] && ev.status !== 'running') {
            addLog(`  ↳ ${transitions[ev.stage]}`, 'system');
          }

          // Terminal state on completion
          if (ev.stage === 'completed') {
            addLog(`▶ A.E.G.I.S. mission complete — fetching full result...`, 'finish');
            try {
              const fullResult = await getScanResult(id);
              // Ensure repo_url is present in result for display
              if (!fullResult.repo_url) fullResult.repo_url = url;
              setResult(fullResult);
              setPhaseTracked('complete');
            } catch (e) {
              addLog(`  ↳ Warning: could not fetch full result: ${e.message}`, 'warn');
              // Still mark as complete — the scan itself succeeded
              setResult({ repo_url: url, scan_id: id, status: 'completed' });
              setPhaseTracked('complete');
            }
            closeSSE.current?.();
          }

          if (ev.stage === 'failed') {
            setError(ev.message);
            setPhaseTracked('failed');
            addLog(`✗ Pipeline failed: ${ev.message}`, 'warn');
            closeSSE.current?.();
          }
        },
        // onError — uses phaseRef to avoid stale closure
        (err) => {
          // Don't treat a closed connection after completion as an error
          if (phaseRef.current === 'complete') return;
          addLog(`✗ SSE connection error: ${err.message}`, 'warn');
          setError(err.message);
          setPhaseTracked('failed');
        },
      );
    } catch (err) {
      addLog(`✗ Failed to start scan: ${err.message}`, 'warn');
      setError(err.message);
      setPhaseTracked('failed');
    }
  }, [addLog, setPhaseTracked]);

  const reset = useCallback(() => {
    closeSSE.current?.();
    setPhaseTracked('idle');
    setScanId(null);
    setRepoUrl(null);
    setLogs([]);
    setProgress(0);
    setResult(null);
    setError(null);
    setRetryInfo(null);
    setPetriStage('idle');
  }, [setPhaseTracked]);

  return { phase, scanId, petriStage, logs, progress, result, error, retryInfo, repoUrl, start, reset };
}
