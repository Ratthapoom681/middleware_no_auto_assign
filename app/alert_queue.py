import json
import logging
import sqlite3
import threading
import time
from typing import Any, Callable

from .config import (
    ALERT_QUEUE_FAILURE_PREVIEW_LIMIT,
    ALERT_QUEUE_MAX_ATTEMPTS,
    ALERT_QUEUE_POLL_SECONDS,
    ALERT_QUEUE_RETRY_BASE_SECONDS,
    ALERT_QUEUE_RETRY_MAX_SECONDS,
    DB_PATH,
)

logger = logging.getLogger(__name__)


class PermanentAlertProcessingError(Exception):
    """Signals that an alert payload is invalid and should not be retried."""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_alert_queue_db() -> None:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                available_at REAL NOT NULL,
                locked_at REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                last_error TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_queue_status_available
            ON alert_queue(status, available_at, id)
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_queue_status_updated
            ON alert_queue(status, updated_at)
            """
        )
        conn.commit()
    finally:
        conn.close()


def recover_processing_jobs() -> int:
    now = time.time()
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE alert_queue
            SET status = 'pending',
                locked_at = NULL,
                available_at = ?,
                updated_at = ?,
                last_error = COALESCE(last_error, 'Recovered after worker restart')
            WHERE status = 'processing'
            """,
            (now, now),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def enqueue_alert(payload: dict[str, Any]) -> int:
    now = time.time()
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alert_queue (payload, status, attempts, available_at, created_at, updated_at, last_error)
            VALUES (?, 'pending', 0, ?, ?, ?, NULL)
            """,
            (json.dumps(payload, separators=(",", ":"), default=str), now, now, now),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()


def claim_next_alert() -> dict[str, Any] | None:
    now = time.time()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT id, payload, attempts, created_at
            FROM alert_queue
            WHERE status = 'pending' AND available_at <= ?
            ORDER BY available_at ASC, id ASC
            LIMIT 1
            """,
            (now,),
        ).fetchone()
        if row is None:
            conn.commit()
            return None

        next_attempt = int(row["attempts"]) + 1
        conn.execute(
            """
            UPDATE alert_queue
            SET status = 'processing',
                attempts = ?,
                locked_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (next_attempt, now, now, row["id"]),
        )
        conn.commit()

        try:
            payload = json.loads(row["payload"])
        except json.JSONDecodeError as exc:
            mark_alert_failed(int(row["id"]), f"Queued payload could not be decoded: {exc}")
            logger.error("Dropping alert queue item %s because stored payload is invalid JSON", row["id"])
            return None

        return {
            "id": int(row["id"]),
            "payload": payload,
            "attempts": next_attempt,
            "created_at": float(row["created_at"]),
        }
    finally:
        conn.close()


def complete_alert(job_id: int) -> None:
    conn = _connect()
    try:
        conn.execute("DELETE FROM alert_queue WHERE id = ?", (job_id,))
        conn.commit()
    finally:
        conn.close()


def retry_alert(job_id: int, error: str, delay_seconds: float) -> None:
    now = time.time()
    next_run = now + max(delay_seconds, 0.0)
    conn = _connect()
    try:
        conn.execute(
            """
            UPDATE alert_queue
            SET status = 'pending',
                available_at = ?,
                locked_at = NULL,
                updated_at = ?,
                last_error = ?
            WHERE id = ?
            """,
            (next_run, now, error[:4000], job_id),
        )
        conn.commit()
    finally:
        conn.close()


def mark_alert_failed(job_id: int, error: str) -> None:
    now = time.time()
    conn = _connect()
    try:
        conn.execute(
            """
            UPDATE alert_queue
            SET status = 'failed',
                locked_at = NULL,
                updated_at = ?,
                last_error = ?
            WHERE id = ?
            """,
            (now, error[:4000], job_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_queue_snapshot() -> dict[str, Any]:
    now = time.time()
    conn = _connect()
    try:
        counts_row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_total,
                SUM(CASE WHEN status = 'pending' AND available_at <= ? THEN 1 ELSE 0 END) AS ready_total,
                SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) AS processing_total,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_total
            FROM alert_queue
            """,
            (now,),
        ).fetchone()

        oldest_row = conn.execute(
            """
            SELECT created_at
            FROM alert_queue
            WHERE status IN ('pending', 'processing')
            ORDER BY created_at ASC
            LIMIT 1
            """
        ).fetchone()

        failures = conn.execute(
            """
            SELECT id, attempts, last_error, created_at, updated_at
            FROM alert_queue
            WHERE status = 'failed'
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            (ALERT_QUEUE_FAILURE_PREVIEW_LIMIT,),
        ).fetchall()

        return {
            "pending": int(counts_row["pending_total"] or 0),
            "ready": int(counts_row["ready_total"] or 0),
            "processing": int(counts_row["processing_total"] or 0),
            "failed": int(counts_row["failed_total"] or 0),
            "oldest_age_seconds": (
                max(0, int(now - float(oldest_row["created_at"]))) if oldest_row is not None else 0
            ),
            "failed_items": [
                {
                    "id": int(row["id"]),
                    "attempts": int(row["attempts"]),
                    "last_error": row["last_error"] or "",
                    "created_at": float(row["created_at"]),
                    "updated_at": float(row["updated_at"]),
                }
                for row in failures
            ],
        }
    finally:
        conn.close()


class AlertQueueWorker:
    def __init__(self, processor: Callable[[dict[str, Any]], None]) -> None:
        self.processor = processor
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        init_alert_queue_db()
        recovered = recover_processing_jobs()
        if recovered:
            logger.warning("Recovered %s queued alerts that were mid-processing during the last shutdown", recovered)

        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._wake_event.clear()
        self._thread = threading.Thread(target=self._run, name="alert-queue-worker", daemon=True)
        self._thread.start()
        logger.info(
            "Alert queue worker started (poll=%ss, max_attempts=%s, base_retry=%ss, max_retry=%ss)",
            ALERT_QUEUE_POLL_SECONDS,
            ALERT_QUEUE_MAX_ATTEMPTS,
            ALERT_QUEUE_RETRY_BASE_SECONDS,
            ALERT_QUEUE_RETRY_MAX_SECONDS,
        )

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(ALERT_QUEUE_POLL_SECONDS * 2, 5))
        self._thread = None

    def enqueue(self, payload: dict[str, Any]) -> int:
        job_id = enqueue_alert(payload)
        self._wake_event.set()
        return job_id

    def _run(self) -> None:
        while not self._stop_event.is_set():
            job = claim_next_alert()
            if job is None:
                self._wake_event.wait(ALERT_QUEUE_POLL_SECONDS)
                self._wake_event.clear()
                continue

            job_id = int(job["id"])
            attempts = int(job["attempts"])

            try:
                self.processor(job["payload"])
                complete_alert(job_id)
                logger.info("Alert queue job %s processed successfully on attempt %s", job_id, attempts)
            except PermanentAlertProcessingError as exc:
                mark_alert_failed(job_id, str(exc))
                logger.error("Alert queue job %s failed permanently: %s", job_id, exc)
            except Exception as exc:
                if attempts >= ALERT_QUEUE_MAX_ATTEMPTS:
                    mark_alert_failed(job_id, str(exc))
                    logger.error(
                        "Alert queue job %s exhausted %s attempts and is now marked failed: %s",
                        job_id,
                        ALERT_QUEUE_MAX_ATTEMPTS,
                        exc,
                    )
                    continue

                delay = min(
                    ALERT_QUEUE_RETRY_BASE_SECONDS * (2 ** max(attempts - 1, 0)),
                    ALERT_QUEUE_RETRY_MAX_SECONDS,
                )
                retry_alert(job_id, str(exc), delay)
                logger.warning(
                    "Alert queue job %s failed on attempt %s and will retry in %.0fs: %s",
                    job_id,
                    attempts,
                    delay,
                    exc,
                )
