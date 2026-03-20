import logging
from typing import Any, Optional

import httpx

from .config import NVD_API_KEY, NVD_API_URL, NVD_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)


class NvdCweLookup:
    def __init__(self) -> None:
        self._cache: dict[str, Optional[int]] = {}

    def get_cwe_for_cve(self, cve_id: str) -> Optional[int]:
        normalized_cve = cve_id.strip().upper()
        if not normalized_cve:
            return None

        if normalized_cve in self._cache:
            return self._cache[normalized_cve]

        cwe_id: Optional[int] = None
        headers: dict[str, str] = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        timeout = httpx.Timeout(NVD_TIMEOUT_SECONDS, connect=min(NVD_TIMEOUT_SECONDS, 5.0))

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(NVD_API_URL, params={"cveId": normalized_cve}, headers=headers)
                response.raise_for_status()
                cwe_id = self._extract_cwe_from_payload(response.json())
        except Exception as exc:
            logger.warning("Failed to resolve CWE from NVD for %s: %s", normalized_cve, exc)

        self._cache[normalized_cve] = cwe_id
        return cwe_id

    def _extract_cwe_from_payload(self, payload: dict[str, Any]) -> Optional[int]:
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


nvd_cwe_lookup = NvdCweLookup()
