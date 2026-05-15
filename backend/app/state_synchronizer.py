"""
State Synchronizer Daemon — single-threaded consumer.

Consumes agent results from the Redis Stream and atomically
merges them into the SQLite master state. This dedicated daemon
guarantees sequential, atomic state updates — no write-locks or
race conditions.

Run as: python -m app.state_synchronizer
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import time
from typing import Any, Dict

import redis

from app.config import REDIS_CONSUMER_GROUP, REDIS_RESULT_STREAM, REDIS_URL
from app.db import load_latest_checkpoint, save_checkpoint

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [StateSynchronizer] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

_running = True


def _handle_signal(sig, frame):
    global _running
    logger.info("Received signal %s, shutting down…", sig)
    _running = False


def _ensure_consumer_group(r: redis.Redis) -> None:
    """Create the consumer group if it doesn't exist."""
    try:
        r.xgroup_create(REDIS_RESULT_STREAM, REDIS_CONSUMER_GROUP, id="0", mkstream=True)
        logger.info("Created consumer group '%s' on stream '%s'", REDIS_CONSUMER_GROUP, REDIS_RESULT_STREAM)
    except redis.ResponseError as e:
        if "BUSYGROUP" in str(e):
            pass  # Group already exists
        else:
            raise


def _merge_result(trace_id: str, result_data: Dict[str, Any]) -> None:
    """
    Deterministic reducer: load current state, merge the agent result,
    and atomically commit back to SQLite.
    """
    current = load_latest_checkpoint(trace_id) or {}
    agent_name = result_data.get("agent_name", "unknown")
    node_id = result_data.get("node_id", agent_name)

    # Merge agent output into the master state
    current[f"{agent_name}_output"] = result_data.get("output")
    current["last_updated_by"] = agent_name
    current["current_node"] = node_id

    save_checkpoint(trace_id, node_id, current)
    logger.info("Merged result from agent '%s' into trace %s", agent_name, trace_id)


def run_synchronizer() -> None:
    """Main loop: consume from Redis Stream and merge into SQLite."""
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    r = redis.from_url(REDIS_URL, decode_responses=True)
    _ensure_consumer_group(r)

    consumer_name = "sync-worker-1"
    logger.info("State Synchronizer started (consumer=%s)", consumer_name)

    while _running:
        try:
            # Block-read from the stream (2s timeout so we can check _running)
            messages = r.xreadgroup(
                REDIS_CONSUMER_GROUP,
                consumer_name,
                {REDIS_RESULT_STREAM: ">"},
                count=10,
                block=2000,
            )

            if not messages:
                continue

            for stream_name, entries in messages:
                for msg_id, data in entries:
                    try:
                        trace_id = data.get("trace_id", "unknown")
                        result_payload = json.loads(data.get("payload", "{}"))
                        _merge_result(trace_id, result_payload)
                        r.xack(REDIS_RESULT_STREAM, REDIS_CONSUMER_GROUP, msg_id)
                    except Exception as exc:
                        logger.error(
                            "Failed to process message %s: %s", msg_id, exc
                        )

        except redis.ConnectionError:
            logger.warning("Redis connection lost, retrying in 2s…")
            time.sleep(2)
        except Exception as exc:
            logger.error("Unexpected error: %s", exc)
            time.sleep(1)

    logger.info("State Synchronizer stopped")


if __name__ == "__main__":
    run_synchronizer()
