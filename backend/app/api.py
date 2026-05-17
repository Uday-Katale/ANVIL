"""
Scan API router — endpoints for starting scans, streaming progress,
and retrieving results.

Uses Server-Sent Events (SSE) for real-time pipeline progress.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from app.auth import require_auth
from app.pipeline import get_scan_queue, get_scan_result, list_scans, start_scan
from app.schemas import ScanRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan")
async def create_scan(body: ScanRequest, request: Request):
    """
    Start a new vulnerability scan on a GitHub repository.
    Returns the scan_id and SSE stream URL immediately.
    """
    token = require_auth(request)

    scan_id = start_scan(
        token=token,
        repo_url=body.repo_url,
        base_branch=body.base_branch,
    )

    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan_id,
            "status": "accepted",
            "stream_url": f"/api/scan/{scan_id}/stream",
            "message": "Scan pipeline started",
        },
    )


@router.get("/scan/{scan_id}/stream")
async def scan_stream(scan_id: str):
    """
    Server-Sent Events endpoint for real-time scan progress.
    Streams ScanEvent JSON objects as they arrive.

    Sends an initial 'connected' event so the client knows the stream is alive,
    then keepalives every 30s to prevent proxy timeouts.
    """
    queue = get_scan_queue(scan_id)
    if queue is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    async def event_generator():
        try:
            # Send an immediate connection-confirmation event so the client
            # knows the stream is alive before any pipeline events arrive.
            yield {
                "event": "connected",
                "data": json.dumps({"scan_id": scan_id, "status": "stream_connected"}),
            }

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    yield {
                        "event": event.stage.value,
                        "data": event.model_dump_json(),
                    }
                    # Stop streaming after terminal events
                    if event.stage.value in ("completed", "failed"):
                        break
                except asyncio.TimeoutError:
                    # Check if the scan queue is still valid (scan may have
                    # been cleaned up while we were waiting)
                    if get_scan_queue(scan_id) is None:
                        logger.info("Scan %s queue removed, closing SSE", scan_id)
                        break
                    # Send keepalive to prevent proxy/browser timeout
                    yield {"event": "keepalive", "data": "{}"}
        except asyncio.CancelledError:
            logger.info("SSE stream cancelled for scan %s", scan_id)

    return EventSourceResponse(
        event_generator(),
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
        # Tell browsers to wait 5s between reconnect attempts
        ping=0,
    )


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get the full result of a completed scan."""
    result = get_scan_result(scan_id)
    if result is None:
        # Check if scan exists but is still running
        queue = get_scan_queue(scan_id)
        if queue is not None:
            return JSONResponse({"scan_id": scan_id, "status": "running"})
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    return JSONResponse(result.model_dump(mode="json"))


@router.get("/scans")
async def list_all_scans(request: Request):
    """List all scans for the current session."""
    require_auth(request)
    return JSONResponse(list_scans())
