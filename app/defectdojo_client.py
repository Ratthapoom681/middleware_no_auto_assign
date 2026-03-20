import httpx
import json
import logging
from urllib.parse import quote
from tenacity import retry, wait_exponential, stop_after_attempt
from typing import Optional, Dict, Any
from .config import DefectDojoConfig, DOJO_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

class DefectDojoClient:
    def __init__(self, base_url: str, api_key: str, dojo_config: DefectDojoConfig):
        self.base_url = base_url
        self.dojo_config = dojo_config
        self.headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json"
        }
        # Caches
        self.user_cache = {}
        self.context_cache = {}
        self.endpoint_cache = {}

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _request(self, method: str, endpoint: str, **kwargs):
        url = f"{self.base_url}/api/v2/{endpoint}"
        timeout = httpx.Timeout(DOJO_TIMEOUT_SECONDS, connect=min(DOJO_TIMEOUT_SECONDS, 10.0))
        with httpx.Client(timeout=timeout) as client:
            try:
                response = client.request(method, url, headers=self.headers, **kwargs)
            except httpx.TimeoutException as exc:
                raise RuntimeError(
                    f"DefectDojo API {method} {endpoint} timed out after {DOJO_TIMEOUT_SECONDS:.1f}s"
                ) from exc
            except httpx.HTTPError as exc:
                raise RuntimeError(
                    f"DefectDojo API {method} {endpoint} request failed: {exc}"
                ) from exc
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                request_payload = kwargs.get("json")
                payload_preview = (
                    json.dumps(request_payload, default=str)[:2000]
                    if request_payload is not None
                    else None
                )
                body_preview = response.text[:4000]
                raise RuntimeError(
                    f"DefectDojo API {method} {endpoint} failed with HTTP {response.status_code}. "
                    f"Response body: {body_preview}. "
                    f"Request payload: {payload_preview}"
                ) from exc

            return response.json() if response.content else None

    def get_user(self, username: str) -> Optional[Dict]:
        if username in self.user_cache:
            return self.user_cache[username]
            
        try:
            res = self._request("GET", f"users/?username={username}")
            if res and res.get("count", 0) > 0:
                user = res["results"][0]
                self.user_cache[username] = user
                return user
        except Exception as e:
            logger.error(f"Failed to fetch user {username}: {e}")
        return None

    def is_user_active(self, username: str) -> bool:
        user = self.get_user(username)
        return bool(user and user.get("is_active", False))

    def _list_all(self, endpoint: str) -> list[Dict[str, Any]]:
        results: list[Dict[str, Any]] = []
        next_endpoint = endpoint

        while next_endpoint:
            response = self._request("GET", next_endpoint)
            if isinstance(response, dict) and "results" in response:
                results.extend(response.get("results", []))
                next_url = response.get("next")
                if next_url and "/api/v2/" in next_url:
                    next_endpoint = next_url.split("/api/v2/", 1)[1]
                else:
                    next_endpoint = None
            else:
                break

        return results

    def _safe_list_all(self, endpoint: str, label: str) -> list[Dict[str, Any]]:
        try:
            return self._list_all(endpoint)
        except Exception as exc:
            logger.warning("Failed to load DefectDojo %s for admin UI: %s", label, exc)
            return []

    def get_admin_options(self) -> Dict[str, list[Dict[str, Any]]]:
        return {
            "product_types": self._safe_list_all("product_types/?limit=200", "product types"),
            "products": self._safe_list_all("products/?limit=200", "products"),
            "engagements": self._safe_list_all("engagements/?limit=200", "engagements"),
            "tests": self._safe_list_all("tests/?limit=200", "tests"),
            "users": self._safe_list_all("users/?limit=200", "users"),
        }

    def create_admin_object(self, object_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        creators = {
            "product-type": lambda: self._request("POST", "product_types/", json=payload),
            "product": lambda: self._request("POST", "products/", json=payload),
            "engagement": lambda: self._request("POST", "engagements/", json=payload),
            "test": lambda: self._request("POST", "tests/", json=payload),
            "user": lambda: self._request("POST", "users/", json=payload),
        }
        if object_type not in creators:
            raise ValueError(f"Unsupported DefectDojo object type: {object_type}")
        return creators[object_type]()

    def ensure_context(self, category: str = "General Monitoring") -> Dict[str, int]:
        """Ensures a default Product, Engagement, and category-specific Test exist."""
        cache_key = f"context:{category}"
        if cache_key in self.context_cache:
            return self.context_cache[cache_key]

        product_type_cfg = self.dojo_config.product_type
        product_cfg = self.dojo_config.product
        engagement_cfg = self.dojo_config.engagement
        test_cfg = self.dojo_config.test

        # 1. Product Type
        pt_res = self._request("GET", f"product_types/?name={quote(product_type_cfg.name)}")
        pt_id = pt_res["results"][0]["id"] if pt_res["count"] > 0 else self._request(
            "POST",
            "product_types/",
            json={"name": product_type_cfg.name, "description": product_type_cfg.description},
        )["id"]

        # 2. Product
        prod_res = self._request("GET", f"products/?name={quote(product_cfg.name)}")
        prod_id = prod_res["results"][0]["id"] if prod_res["count"] > 0 else self._request(
            "POST",
            "products/",
            json={"name": product_cfg.name, "description": product_cfg.description, "prod_type": pt_id},
        )["id"]

        # 3. Engagement
        eng_res = self._request("GET", f"engagements/?product={prod_id}&name={quote(engagement_cfg.name)}")
        eng_id = eng_res["results"][0]["id"] if eng_res["count"] > 0 else self._request(
            "POST",
            "engagements/",
            json={
                "name": engagement_cfg.name,
                "product": prod_id,
                "target_start": engagement_cfg.target_start,
                "target_end": engagement_cfg.target_end,
                "status": engagement_cfg.status,
            },
        )["id"]

        # 4. Test
        test_title = f"{test_cfg.title_prefix} - {category}"
        test_res = self._request("GET", f"tests/?engagement={eng_id}&title={quote(test_title)}")
        test_id = test_res["results"][0]["id"] if test_res["count"] > 0 else self._request(
            "POST",
            "tests/",
            json={
                "title": test_title,
                "engagement": eng_id,
                "test_type": test_cfg.test_type_id,
                "target_start": test_cfg.target_start,
                "target_end": test_cfg.target_end,
            },
        )["id"]

        context = {
            "product_type_id": pt_id,
            "product_id": prod_id,
            "engagement_id": eng_id,
            "test_id": test_id,
        }
        self.context_cache[cache_key] = context
        return context

    def get_finding_by_dedup(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        search = self._request("GET", f"findings/?unique_id_from_tool={quote(dedup_key)}")
        if search and search.get("count", 0) > 0:
            for candidate in search["results"]:
                if self._is_open_finding(candidate):
                    return candidate
        return None

    def find_existing_finding(self, finding_data: Dict[str, Any], endpoint_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        dedup_key = finding_data["unique_id_from_tool"]
        existing_finding = self.get_finding_by_dedup(dedup_key)
        if existing_finding:
            logger.info("Pre-check matched existing DefectDojo finding by unique_id_from_tool for dedup key %s", dedup_key)
            return existing_finding

        title = finding_data.get("title")
        test_id = finding_data.get("test")
        cwe = finding_data.get("cwe")
        network_tags = self._extract_network_tags(finding_data.get("tags", []))
        if not title or not test_id:
            return None

        search = self._request("GET", f"findings/?test={test_id}&title={quote(title)}")
        if not search or search.get("count", 0) == 0:
            return None

        for candidate in search.get("results", []):
            if not self._is_open_finding(candidate):
                continue

            candidate_cwe = candidate.get("cwe")
            if cwe and candidate_cwe and int(candidate_cwe) != int(cwe):
                continue

            if endpoint_id is not None:
                candidate_endpoint_ids = self._extract_related_ids(candidate.get("endpoints", []))
                if endpoint_id not in candidate_endpoint_ids:
                    continue

            if network_tags:
                candidate_tags = set(self._extract_tag_names(candidate.get("tags", [])))
                if not (network_tags & candidate_tags):
                    continue

            logger.info(
                "Pre-check matched existing DefectDojo finding %s by title/test%s before create",
                candidate.get("id"),
                " and endpoint/CWE/IP" if endpoint_id is not None or cwe or network_tags else "",
            )
            return candidate

        return None

    def _is_open_finding(self, finding: Dict[str, Any]) -> bool:
        if finding.get("is_mitigated") is True:
            return False

        mitigated = finding.get("mitigated")
        if mitigated:
            return False

        active = finding.get("active")
        if active is False:
            return False

        return True

    def ensure_endpoint(self, host: str, product_id: int) -> Optional[int]:
        cache_key = f"{product_id}:{host}"
        if cache_key in self.endpoint_cache:
            return self.endpoint_cache[cache_key]

        try:
            search = self._request("GET", f"endpoints/?product={product_id}&host={quote(host)}")
            if search and search.get("count", 0) > 0:
                endpoint_id = search["results"][0]["id"]
                logger.info("Reusing DefectDojo endpoint %s for host %s", endpoint_id, host)
                self.endpoint_cache[cache_key] = endpoint_id
                return endpoint_id

            endpoint = self._request("POST", "endpoints/", json={"host": host, "product": product_id})
            endpoint_id = endpoint["id"]
            logger.info("Created DefectDojo endpoint %s for host %s", endpoint_id, host)
            self.endpoint_cache[cache_key] = endpoint_id
            return endpoint_id
        except Exception as exc:
            logger.warning("Failed to ensure endpoint for host %s: %s", host, exc)
            return None

    def attach_endpoint_to_finding(self, finding_id: int, endpoint_id: int) -> bool:
        try:
            existing = self._request(
                "GET",
                f"endpoint_status/?finding={finding_id}&endpoint={endpoint_id}",
            )
            if existing and existing.get("count", 0) > 0:
                logger.info(
                    "Endpoint %s is already linked to finding %s via endpoint_status",
                    endpoint_id,
                    finding_id,
                )
                return True

            self._request(
                "POST",
                "endpoint_status/",
                json={"finding": finding_id, "endpoint": endpoint_id},
            )
            logger.info("Attached endpoint %s to finding %s via endpoint_status", endpoint_id, finding_id)
            return True
        except Exception as exc:
            logger.warning(
                "Failed to attach endpoint %s to finding %s via endpoint_status: %s",
                endpoint_id,
                finding_id,
                exc,
            )

        try:
            self._request("PATCH", f"findings/{finding_id}/", json={"endpoints": [endpoint_id]})
            logger.info("Attached endpoint %s to finding %s via findings patch fallback", endpoint_id, finding_id)
            return True
        except Exception as exc:
            logger.warning(
                "Failed to attach endpoint %s to finding %s via findings patch fallback: %s",
                endpoint_id,
                finding_id,
                exc,
            )
            return False

    def _extract_related_ids(self, values: Any) -> list[int]:
        ids: list[int] = []
        if not isinstance(values, list):
            return ids

        for value in values:
            if isinstance(value, int):
                ids.append(value)
            elif isinstance(value, dict) and isinstance(value.get("id"), int):
                ids.append(value["id"])
        return ids

    def _extract_tag_names(self, values: Any) -> list[str]:
        names: list[str] = []
        if not isinstance(values, list):
            return names

        for value in values:
            if isinstance(value, str):
                names.append(value)
            elif isinstance(value, dict) and isinstance(value.get("name"), str):
                names.append(value["name"])
        return names

    def _extract_network_tags(self, values: list[str]) -> set[str]:
        return {
            value for value in values
            if value.startswith("src_ip:") or value.startswith("observed_ip:") or value.startswith("dst_ip:")
        }

    def push_finding(
        self,
        finding_data: dict,
        assign_note: str,
        existing_finding: Optional[Dict[str, Any]] = None,
        endpoint_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        dedup_key = finding_data["unique_id_from_tool"]

        if existing_finding is None:
            existing_finding = self.find_existing_finding(finding_data, endpoint_id=endpoint_id)

        if existing_finding:
            finding_id = existing_finding["id"]
            logger.info(
                "Skipping create for dedup key %s because DefectDojo finding %s already exists",
                dedup_key,
                finding_id,
            )
            return {"finding_id": finding_id, "action": "skipped_duplicate"}

        payload = dict(finding_data)
        if endpoint_id:
            payload["endpoints"] = [endpoint_id]

        logger.info("Creating new DefectDojo finding for dedup key %s", dedup_key)
        try:
            finding_id = self._request("POST", "findings/", json=payload)["id"]
        except Exception as exc:
            if "endpoints" not in payload:
                raise
            logger.warning(
                "Creating finding with endpoints failed for dedup key %s: %s. Retrying without endpoint association first.",
                dedup_key,
                exc,
            )
            payload.pop("endpoints", None)
            finding_id = self._request("POST", "findings/", json=payload)["id"]
        should_add_note = True
        action = "created"

        if endpoint_id is not None:
            self.attach_endpoint_to_finding(finding_id, endpoint_id)
            
        # Add a note regarding assignment using the finding-scoped endpoint.
        if should_add_note:
            try:
                self._request("POST", f"findings/{finding_id}/notes/", json={"entry": assign_note})
            except Exception as e:
                logger.warning(f"Note attachment variation failed, skipping note: {e}")

        return {"finding_id": finding_id, "action": action}
