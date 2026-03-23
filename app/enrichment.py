import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from time import time
from typing import Any, Optional

import httpx

from .config import (
    DB_PATH,
    EPSS_API_URL,
    EPSS_CACHE_TTL_SECONDS,
    EPSS_TIMEOUT_SECONDS,
    KEV_FEED_URL,
    KEV_REFRESH_SECONDS,
    KEV_TIMEOUT_SECONDS,
    NVD_API_KEY,
    NVD_API_URL,
    NVD_CACHE_TTL_SECONDS,
    NVD_TIMEOUT_SECONDS,
)
from .models import WazuhAlert
from .wazuh_parser import extract_cves, extract_direct_cwe, map_internal_cwe

logger = logging.getLogger(__name__)


@dataclass
class CveEnrichment:
    cve_id: str
    cwe: Optional[int] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    known_exploited: bool = False
    ransomware_used: Optional[bool] = None
    kev_date: Optional[str] = None
    ransomware_campaign_use: str = "Unknown"


@dataclass
class AlertEnrichmentResult:
    cwe: Optional[int]
    cwe_source: str
    primary_cve: Optional[str]
    cve_ids: list[str] = field(default_factory=list)
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    known_exploited: Optional[bool] = None
    ransomware_used: Optional[bool] = None
    kev_date: Optional[str] = None
    metadata: dict[str, str] = field(default_factory=dict)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_enrichment_db() -> None:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_enrichment_cache (
                cve_id TEXT PRIMARY KEY,
                nvd_cwe INTEGER,
                nvd_checked_at REAL,
                epss_score REAL,
                epss_percentile REAL,
                epss_checked_at REAL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS kev_catalog (
                cve_id TEXT PRIMARY KEY,
                known_exploited INTEGER NOT NULL,
                ransomware_used INTEGER,
                kev_date TEXT,
                ransomware_campaign_use TEXT NOT NULL,
                refreshed_at REAL NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS enrichment_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _normalize_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    return bool(int(value))


class AlertEnrichmentService:
    def __init__(self) -> None:
        self._kev_refresh_lock = threading.Lock()

    def initialize(self) -> None:
        init_enrichment_db()
        self._ensure_fresh_kev_catalog()

    def enrich_alert(self, alert: WazuhAlert) -> AlertEnrichmentResult:
        direct_cwe = extract_direct_cwe(alert)
        cve_ids = extract_cves(alert)
        external_results = [self._enrich_cve(cve_id) for cve_id in cve_ids]
        primary_cve = self._select_primary_cve(external_results)

        if direct_cwe is not None:
            cwe = direct_cwe
            cwe_source = "alert"
        elif primary_cve and primary_cve.cwe is not None:
            cwe = primary_cve.cwe
            cwe_source = "nvd"
        else:
            cwe, cwe_source = map_internal_cwe(alert)

        metadata = {"enrichment_cwe_source": cwe_source}
        if cve_ids:
            metadata["enrichment_cve_count"] = str(len(cve_ids))
            metadata["enrichment_cves"] = ", ".join(cve_ids)[:300]
        else:
            metadata["enrichment_status"] = "no_cve"

        if primary_cve:
            metadata["enrichment_primary_cve"] = primary_cve.cve_id
            metadata["kev_ransomware_campaign_use"] = primary_cve.ransomware_campaign_use

        return AlertEnrichmentResult(
            cwe=cwe,
            cwe_source=cwe_source,
            primary_cve=primary_cve.cve_id if primary_cve else None,
            cve_ids=cve_ids,
            epss_score=primary_cve.epss_score if primary_cve else None,
            epss_percentile=primary_cve.epss_percentile if primary_cve else None,
            known_exploited=primary_cve.known_exploited if primary_cve else None,
            ransomware_used=primary_cve.ransomware_used if primary_cve else None,
            kev_date=primary_cve.kev_date if primary_cve else None,
            metadata=metadata,
        )

    def _select_primary_cve(self, results: list[CveEnrichment]) -> Optional[CveEnrichment]:
        if not results:
            return None

        def sort_key(result: CveEnrichment) -> tuple[float, float, int]:
            epss_score = result.epss_score if result.epss_score is not None else -1.0
            epss_percentile = result.epss_percentile if result.epss_percentile is not None else -1.0
            known_exploited = 1 if result.known_exploited else 0
            return (epss_score, epss_percentile, known_exploited)

        return max(results, key=sort_key)

    def _enrich_cve(self, cve_id: str) -> CveEnrichment:
        cwe = self._get_nvd_cwe(cve_id)
        epss_score, epss_percentile = self._get_epss(cve_id)
        kev = self._get_kev(cve_id)

        return CveEnrichment(
            cve_id=cve_id,
            cwe=cwe,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            known_exploited=kev["known_exploited"],
            ransomware_used=kev["ransomware_used"],
            kev_date=kev["kev_date"],
            ransomware_campaign_use=kev["ransomware_campaign_use"],
        )

    def _get_nvd_cwe(self, cve_id: str) -> Optional[int]:
        normalized_cve = cve_id.strip().upper()
        cached = self._load_cached_nvd_cwe(normalized_cve)
        if cached["hit"]:
            return cached["cwe"]

        headers: dict[str, str] = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        timeout = httpx.Timeout(NVD_TIMEOUT_SECONDS, connect=min(NVD_TIMEOUT_SECONDS, 5.0))
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(NVD_API_URL, params={"cveId": normalized_cve}, headers=headers)
                response.raise_for_status()
                cwe = self._extract_cwe_from_nvd_payload(response.json())
                self._store_nvd_cwe(normalized_cve, cwe)
                return cwe
        except Exception as exc:
            logger.warning("Failed to resolve CWE from NVD for %s: %s", normalized_cve, exc)
            return None

    def _get_epss(self, cve_id: str) -> tuple[Optional[float], Optional[float]]:
        normalized_cve = cve_id.strip().upper()
        cached = self._load_cached_epss(normalized_cve)
        if cached["hit"]:
            return cached["epss_score"], cached["epss_percentile"]

        timeout = httpx.Timeout(EPSS_TIMEOUT_SECONDS, connect=min(EPSS_TIMEOUT_SECONDS, 5.0))
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(EPSS_API_URL, params={"cve": normalized_cve})
                response.raise_for_status()
                epss_score, epss_percentile = self._extract_epss_from_payload(response.json(), normalized_cve)
                self._store_epss(normalized_cve, epss_score, epss_percentile)
                return epss_score, epss_percentile
        except Exception as exc:
            logger.warning("Failed to resolve EPSS for %s: %s", normalized_cve, exc)
            return None, None

    def _get_kev(self, cve_id: str) -> dict[str, Any]:
        self._ensure_fresh_kev_catalog()
        normalized_cve = cve_id.strip().upper()
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT known_exploited, ransomware_used, kev_date, ransomware_campaign_use
                FROM kev_catalog
                WHERE cve_id = ?
                """,
                (normalized_cve,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return {
                "known_exploited": False,
                "ransomware_used": None,
                "kev_date": None,
                "ransomware_campaign_use": "Unknown",
            }

        return {
            "known_exploited": bool(row["known_exploited"]),
            "ransomware_used": _normalize_bool(row["ransomware_used"]),
            "kev_date": row["kev_date"],
            "ransomware_campaign_use": row["ransomware_campaign_use"] or "Unknown",
        }

    def _ensure_fresh_kev_catalog(self) -> None:
        now = time()
        state_value = self._load_state("kev_catalog_refreshed_at")
        if state_value is not None:
            try:
                if now - float(state_value) < KEV_REFRESH_SECONDS:
                    return
            except ValueError:
                pass

        with self._kev_refresh_lock:
            state_value = self._load_state("kev_catalog_refreshed_at")
            if state_value is not None:
                try:
                    if now - float(state_value) < KEV_REFRESH_SECONDS:
                        return
                except ValueError:
                    pass

            timeout = httpx.Timeout(KEV_TIMEOUT_SECONDS, connect=min(KEV_TIMEOUT_SECONDS, 5.0))
            try:
                with httpx.Client(timeout=timeout) as client:
                    response = client.get(KEV_FEED_URL)
                    response.raise_for_status()
                    payload = response.json()
                self._replace_kev_catalog(payload)
                self._store_state("kev_catalog_refreshed_at", str(now))
            except Exception as exc:
                logger.warning("Failed to refresh KEV catalog from %s: %s", KEV_FEED_URL, exc)

    def _replace_kev_catalog(self, payload: dict[str, Any]) -> None:
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("KEV feed did not contain a vulnerabilities list")

        refreshed_at = time()
        rows: list[tuple[str, int, Optional[int], Optional[str], str, float]] = []
        for entry in vulnerabilities:
            if not isinstance(entry, dict):
                continue
            cve_id = str(entry.get("cveID") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue

            ransomware_campaign_use = str(entry.get("knownRansomwareCampaignUse") or "Unknown").strip() or "Unknown"
            ransomware_used = None
            if ransomware_campaign_use.lower() == "known":
                ransomware_used = 1
            elif ransomware_campaign_use.lower() == "no":
                ransomware_used = 0

            rows.append(
                (
                    cve_id,
                    1,
                    ransomware_used,
                    str(entry.get("dateAdded") or "").strip() or None,
                    ransomware_campaign_use,
                    refreshed_at,
                )
            )

        conn = _connect()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM kev_catalog")
            cursor.executemany(
                """
                INSERT INTO kev_catalog (cve_id, known_exploited, ransomware_used, kev_date, ransomware_campaign_use, refreshed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
        finally:
            conn.close()

    def _load_cached_nvd_cwe(self, cve_id: str) -> dict[str, Any]:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT nvd_cwe, nvd_checked_at FROM cve_enrichment_cache WHERE cve_id = ?",
                (cve_id,),
            ).fetchone()
        finally:
            conn.close()

        if row is None or row["nvd_checked_at"] is None:
            return {"hit": False, "cwe": None}
        if time() - float(row["nvd_checked_at"]) >= NVD_CACHE_TTL_SECONDS:
            return {"hit": False, "cwe": None}
        return {"hit": True, "cwe": row["nvd_cwe"]}

    def _store_nvd_cwe(self, cve_id: str, cwe: Optional[int]) -> None:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO cve_enrichment_cache (cve_id, nvd_cwe, nvd_checked_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    nvd_cwe = excluded.nvd_cwe,
                    nvd_checked_at = excluded.nvd_checked_at
                """,
                (cve_id, cwe, time()),
            )
            conn.commit()
        finally:
            conn.close()

    def _load_cached_epss(self, cve_id: str) -> dict[str, Any]:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT epss_score, epss_percentile, epss_checked_at FROM cve_enrichment_cache WHERE cve_id = ?",
                (cve_id,),
            ).fetchone()
        finally:
            conn.close()

        if row is None or row["epss_checked_at"] is None:
            return {"hit": False, "epss_score": None, "epss_percentile": None}
        if time() - float(row["epss_checked_at"]) >= EPSS_CACHE_TTL_SECONDS:
            return {"hit": False, "epss_score": None, "epss_percentile": None}
        return {
            "hit": True,
            "epss_score": row["epss_score"],
            "epss_percentile": row["epss_percentile"],
        }

    def _store_epss(self, cve_id: str, score: Optional[float], percentile: Optional[float]) -> None:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO cve_enrichment_cache (cve_id, epss_score, epss_percentile, epss_checked_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    epss_score = excluded.epss_score,
                    epss_percentile = excluded.epss_percentile,
                    epss_checked_at = excluded.epss_checked_at
                """,
                (cve_id, score, percentile, time()),
            )
            conn.commit()
        finally:
            conn.close()

    def _load_state(self, key: str) -> Optional[str]:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value FROM enrichment_state WHERE key = ?",
                (key,),
            ).fetchone()
        finally:
            conn.close()
        return None if row is None else str(row["value"])

    def _store_state(self, key: str, value: str) -> None:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO enrichment_state (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()

    def _extract_cwe_from_nvd_payload(self, payload: dict[str, Any]) -> Optional[int]:
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return None

        for vulnerability in vulnerabilities:
            cve = vulnerability.get("cve")
            if not isinstance(cve, dict):
                continue

            weaknesses = cve.get("weaknesses")
            if not isinstance(weaknesses, list):
                continue

            for weakness in weaknesses:
                descriptions = weakness.get("description")
                if not isinstance(descriptions, list):
                    continue

                for description in descriptions:
                    if not isinstance(description, dict):
                        continue
                    value = description.get("value")
                    if not isinstance(value, str):
                        continue
                    digits = "".join(char for char in value if char.isdigit())
                    if digits:
                        return int(digits)

        return None

    def _extract_epss_from_payload(
        self,
        payload: dict[str, Any],
        cve_id: str,
    ) -> tuple[Optional[float], Optional[float]]:
        data = payload.get("data")
        if not isinstance(data, list):
            return None, None

        for item in data:
            if not isinstance(item, dict):
                continue
            if str(item.get("cve") or "").strip().upper() != cve_id:
                continue
            try:
                score = float(item["epss"]) if item.get("epss") is not None else None
                percentile = float(item["percentile"]) if item.get("percentile") is not None else None
            except (TypeError, ValueError):
                return None, None
            return score, percentile

        return None, None


alert_enrichment_service = AlertEnrichmentService()
