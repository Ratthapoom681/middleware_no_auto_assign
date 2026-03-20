import logging
from fastapi import FastAPI, Request, BackgroundTasks
from .admin_ui import configure_admin, router as admin_router
from .config import AppConfig, load_config, DOJO_URL, DOJO_API_KEY
from .matching import build_alert_match_tokens, rule_matches
from .models import WazuhAlert
from .wazuh_parser import (
    extract_cve,
    extract_cwe,
    generate_dedup_key,
    generate_impact,
    generate_markdown_description,
    generate_mitigation,
    get_rule_description,
    map_severity,
)
from .routing import determine_owner_group
from .cve_lookup import nvd_cwe_lookup
from .defectdojo_client import DefectDojoClient
from .log_stream import install_log_stream_handler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
install_log_stream_handler()
logger = logging.getLogger(__name__)

app = FastAPI(title="Wazuh to DefectDojo Integrator")
config = load_config()
dd_client = DefectDojoClient(DOJO_URL, DOJO_API_KEY, config.defectdojo)
DEFAULT_FOUND_BY_TEST_TYPE_ID = 1


def reload_runtime_config(new_config: AppConfig) -> None:
    global config, dd_client
    config = new_config
    dd_client = DefectDojoClient(DOJO_URL, DOJO_API_KEY, config.defectdojo)


configure_admin(
    lambda: config,
    reload_runtime_config,
    lambda: dd_client.get_admin_options(),
    lambda object_type, payload: dd_client.create_admin_object(object_type, payload),
)
app.include_router(admin_router)


def build_tags(alert: WazuhAlert, owner_group: str, assignment_error: bool) -> list[str]:
    tags = ["source:wazuh", f"wazuh_rule:{alert.rule.id}", f"owner_group:{owner_group}"]
    alert_tokens = build_alert_match_tokens(alert)

    for group in alert.rule.groups:
        normalized_group = group.strip().lower().replace(" ", "-").replace(",", "-").replace("\"", "")
        tags.append(f"wazuh_group:{normalized_group}")

    for tag_rule in config.tag_rules:
        if any(rule_matches(match, alert_tokens) for match in tag_rule.match_rule_groups):
            tags.extend(tag_rule.tags)

    if alert.data:
        for tag_name, field_name in (
            ("src_ip", "srcip"),
            ("observed_ip", "ip"),
            ("dst_ip", "dstip"),
        ):
            value = alert.data.get(field_name)
            if value:
                tags.append(f"{tag_name}:{str(value).strip()}")

    if assignment_error:
        tags.append("assignment_error")

    # Keep tags stable and avoid duplicates when multiple rules map to the same label.
    return list(dict.fromkeys(tags))


def get_test_category(tags: list[str]) -> str:
    for tag, test_name in config.categories.tag_to_test.items():
        if tag in tags:
            return test_name
    return config.categories.default_test


def _normalize_endpoint_value(value: object) -> str | None:
    if value is None:
        return None

    normalized = str(value).strip()
    if not normalized:
        return None

    if normalized.lower() in {"unknown", "n/a", "none", "-"}:
        return None

    return normalized


def get_endpoint_host(alert: WazuhAlert) -> str | None:
    candidates: list[object] = []

    if alert.data:
        candidates.extend([
            alert.data.get("dstip"),
            alert.data.get("dst_ip"),
            alert.data.get("hostname"),
            alert.data.get("host"),
        ])

    candidates.extend([
        alert.location,
        alert.agent.ip,
        alert.agent.name,
        alert.manager.get("name") if alert.manager else None,
    ])

    for candidate in candidates:
        endpoint_host = _normalize_endpoint_value(candidate)
        if endpoint_host:
            return endpoint_host

    return None

@app.on_event("startup")
def startup_event():
    logger.info("Service started. Auto-assignment is disabled in this variant.")

def process_alert(raw_payload: dict):
    # 1. Parse Alert
    try:
        alert = WazuhAlert(**raw_payload, raw_payload=raw_payload)
    except Exception as e:
        logger.error(f"Failed to parse alert: {e}")
        return

    try:
        # 2. Routing
        owner_group = determine_owner_group(alert, config)
        group_config = config.teams.get(owner_group)
        tags = build_tags(alert, owner_group, assignment_error=False)
        test_category = get_test_category(tags)

        # 3. Prepare DefectDojo test context
        context = dd_client.ensure_context(test_category)
        test_id = context["test_id"]
        product_id = context["product_id"]
        dedup_key = generate_dedup_key(alert)
        existing_finding = dd_client.get_finding_by_dedup(dedup_key)

        if group_config is None:
            logger.warning(
                "Owner group '%s' is not defined in config.yaml teams. Falling back to unassigned finding.",
                owner_group,
            )
            assignment_error = True
        else:
            assignment_error = False

        # 4. Prepare Finding Payload
        tags = build_tags(alert, owner_group, assignment_error)

        finding_data = {
            "test": test_id,
            "title": f"[Wazuh] {get_rule_description(alert)} on {alert.agent.name}",
            "description": generate_markdown_description(alert),
            "impact": generate_impact(alert),
            "mitigation": generate_mitigation(alert),
            "severity": map_severity(alert.rule.level),
            "numerical_severity": alert.rule.level,
            "active": True,
            "verified": True,
            "tags": tags,
            "found_by": [DEFAULT_FOUND_BY_TEST_TYPE_ID],
            "unique_id_from_tool": dedup_key
        }

        cwe = extract_cwe(alert)
        if not cwe:
            cve_id = extract_cve(alert)
            if cve_id:
                cwe = nvd_cwe_lookup.get_cwe_for_cve(cve_id)
        if cwe:
            finding_data["cwe"] = cwe

        assign_note = (
            f"Automated Routing: Mapped to group '{owner_group}'. "
            "Auto-assignment is disabled in this deployment."
        )
        endpoint_id = None
        endpoint_host = get_endpoint_host(alert)
        if endpoint_host:
            endpoint_id = dd_client.ensure_endpoint(endpoint_host, product_id)
        else:
            logger.warning("No usable endpoint host found for alert %s", alert.id)

        existing_finding = existing_finding or dd_client.find_existing_finding(
            finding_data,
            endpoint_id=endpoint_id,
        )

        # 5. Push to DefectDojo
        result = dd_client.push_finding(
            finding_data,
            assign_note,
            existing_finding=existing_finding,
            endpoint_id=endpoint_id,
        )
        if result["action"] == "skipped_duplicate":
            logger.info(
                "Dedup matched existing finding %s for rule %s (Dedup: %s). "
                "No new finding was sent to DefectDojo.",
                result["finding_id"],
                alert.rule.id,
                dedup_key,
            )
        else:
            logger.info(
                "Alert for rule %s was sent to DefectDojo as new finding %s (Dedup: %s) for owner group %s with no auto-assigned reviewer",
                alert.rule.id,
                result["finding_id"],
                dedup_key,
                owner_group,
            )
    except Exception as e:
        logger.exception("Failed to process alert %s with DefectDojo: %s", raw_payload.get("id"), e)

@app.post("/webhook")
async def wazuh_webhook(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    # Execute synchronously in background to release webhook instantly
    background_tasks.add_task(process_alert, payload)
    return {"status": "accepted"}
