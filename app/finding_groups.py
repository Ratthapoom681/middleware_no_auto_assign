import hashlib
import logging
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .config import DB_PATH, FindingGroupRule
from .matching import build_alert_match_tokens, rule_matches
from .models import WazuhAlert

logger = logging.getLogger(__name__)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_finding_group_db() -> None:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_group_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                observed_at REAL NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_finding_group_events_lookup
            ON finding_group_events(rule_name, title, dst_ip, observed_at)
            """
        )
        conn.commit()
    finally:
        conn.close()


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "group"


def _parse_alert_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    for candidate in (normalized, normalized.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue

    return datetime.now(timezone.utc)


def _count_unique_sources(
    rule_name: str,
    title: str,
    dst_ip: str,
    cutoff_ts: float,
) -> int:
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT COUNT(DISTINCT src_ip) AS unique_total
            FROM finding_group_events
            WHERE rule_name = ? AND title = ? AND dst_ip = ? AND observed_at >= ?
            """,
            (rule_name, title, dst_ip, cutoff_ts),
        ).fetchone()
        return int(row["unique_total"] or 0)
    finally:
        conn.close()


def _store_observation(rule_name: str, title: str, dst_ip: str, src_ip: str, observed_at: float) -> None:
    retention_cutoff = observed_at - (7 * 24 * 60 * 60)
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO finding_group_events (rule_name, title, dst_ip, src_ip, observed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (rule_name, title, dst_ip, src_ip, observed_at),
        )
        cursor.execute(
            "DELETE FROM finding_group_events WHERE observed_at < ?",
            (retention_cutoff,),
        )
        conn.commit()
    finally:
        conn.close()


def _build_group_key(rule_name: str, title: str, dst_ip: str, bucket_start: int) -> tuple[str, str]:
    digest = hashlib.md5(f"{rule_name}|{title}|{dst_ip}|{bucket_start}".encode()).hexdigest()
    short_key = digest[:12]
    group_key = f"middleware-group:{_slugify(rule_name)}:{short_key}"
    return group_key, short_key


def evaluate_finding_group_rule(
    alert: WazuhAlert,
    finding_data: dict[str, Any],
    rules: list[FindingGroupRule],
) -> dict[str, Any] | None:
    if not rules:
        return None

    src_ip = str(alert.data.get("srcip")).strip() if alert.data and alert.data.get("srcip") else ""
    dst_ip = str(alert.data.get("dstip")).strip() if alert.data and alert.data.get("dstip") else ""
    title = str(finding_data.get("title") or "").strip()
    severity = str(finding_data.get("severity") or "").strip()
    numerical_severity = int(finding_data.get("numerical_severity") or 0)
    if not src_ip or not title:
        return None

    alert_tokens = build_alert_match_tokens(alert)
    observed_at = _parse_alert_time(alert.timestamp).timestamp()

    for rule in rules:
        if not rule.enabled:
            continue

        if rule.match_rule_groups and not any(
            rule_matches(match, alert_tokens) for match in rule.match_rule_groups
        ):
            continue

        if rule.severity_values:
            severity_match = severity in rule.severity_values
            if not severity_match and "Informational" in rule.severity_values and numerical_severity <= 1:
                severity_match = True
            if not severity_match:
                continue

        if rule.require_same_dst_ip and not dst_ip:
            continue
        title_scope = title if rule.require_same_title else "__any_title__"
        dst_ip_scope = dst_ip if rule.require_same_dst_ip else "__any_dst_ip__"

        _store_observation(rule.name, title_scope, dst_ip_scope, src_ip, observed_at)
        window_seconds = rule.window_minutes * 60
        cutoff_ts = observed_at - window_seconds
        unique_src_count = _count_unique_sources(rule.name, title_scope, dst_ip_scope, cutoff_ts)
        if unique_src_count <= rule.unique_src_ip_threshold:
            continue

        bucket_start = int(observed_at // window_seconds) * window_seconds
        group_key, short_key = _build_group_key(rule.name, title_scope, dst_ip_scope, bucket_start)
        return {
            "rule_name": rule.name,
            "window_minutes": rule.window_minutes,
            "unique_src_count": unique_src_count,
            "group_key": group_key,
            "group_short_key": short_key,
            "dst_ip": dst_ip,
            "title": title,
            "observed_at": observed_at,
            "require_same_title": rule.require_same_title,
            "require_same_dst_ip": rule.require_same_dst_ip,
            "search_title": title if rule.require_same_title else "",
            "search_dst_ip": dst_ip if rule.require_same_dst_ip else "",
        }

    return None
