"""
Celery tasks — the bridge between the FastAPI ingress and the CPN engine.

When a webhook is received, `run_pipeline` is dispatched as an async
Celery task. It restores the W3C Trace Context, initializes the Master
State, and runs the CPN engine to completion.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from app.celery_app import celery_app
from app.db import log_execution, save_checkpoint, update_execution
from app.graph import build_red_team_cpn
from app.schemas import MasterState, WebhookPayload
from app.telemetry import (
    detach_trace_context,
    extract_trace_context,
    init_telemetry,
    trace_operation,
)

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="app.tasks.run_pipeline", max_retries=0)
def run_pipeline(
    self,
    trace_id: str,
    task_id: str,
    webhook_data: Dict[str, Any],
    trace_context: Dict[str, str],
) -> Dict[str, Any]:
    """
    Main pipeline task. Restores trace context from the FastAPI ingress,
    builds the CPN, and runs it to completion.
    """
    # Restore W3C Trace Context from the Celery metadata
    init_telemetry()
    ctx_token = extract_trace_context(trace_context)

    try:
        with trace_operation(
            "pipeline_execution",
            attributes={
                "pipeline.trace_id": trace_id,
                "pipeline.task_id": task_id,
            },
        ) as span:
            # Parse and validate the webhook payload
            webhook = WebhookPayload(**webhook_data)

            # Initialize the Master State (the coloured CPN token)
            state = MasterState(
                trace_id=trace_id,
                task_id=task_id,
                current_node="ingress",
                webhook=webhook,
            )

            # Log execution start
            row_id = log_execution(
                trace_id=trace_id,
                task_id=task_id,
                agent_name="orchestrator",
                status="running",
                input_json=json.dumps(webhook_data),
            )

            # Checkpoint the initial state
            save_checkpoint(trace_id, "ingress", state.model_dump(mode="json"))

            # Build and run the CPN
            logger.info("Starting CPN execution for trace %s", trace_id)
            cpn = build_red_team_cpn()
            final_state = cpn.run(state)

            # Log completion
            status = "completed" if not final_state.error else "failed"
            update_execution(
                row_id,
                status=status,
                output_json=final_state.model_dump_json(),
                error=final_state.error,
            )

            span.set_attribute("pipeline.final_node", final_state.current_node)
            span.set_attribute("pipeline.status", status)
            span.set_attribute("pipeline.completed", final_state.completed)

            logger.info(
                "Pipeline %s finished: node=%s, status=%s",
                trace_id, final_state.current_node, status,
            )

            return final_state.model_dump(mode="json")

    finally:
        detach_trace_context(ctx_token)
