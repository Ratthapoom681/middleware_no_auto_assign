import logging
import re
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request
from .alert_queue import AlertQueueWorker, PermanentAlertProcessingError
from .assignment import get_assigned_user, get_next_user, init_db, remember_assignment
from .admin_ui import configure_admin, router as admin_router
from .config import AppConfig, load_config, DOJO_URL, DOJO_API_KEY
from .enrichment import alert_enrichment_service
from .finding_groups import evaluate_finding_group_rule, init_finding_group_db
from .matching import build_alert_match_tokens, rule_matches
from .models import WazuhAlert
from .wazuh_parser import (
    generate_dedup_key,
    generate_impact,
    generate_markdown_description,
    generate_mitigation,
    get_rule_description,
    is_vulnerability_detector_alert,
    map_severity,
)
from .routing import determine_owner_group
from .defectdojo_client import DefectDojoClient
from .log_stream import install_log_stream_handler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
install_log_stream_handler()
logger = logging.getLogger(__name__)

app = FastAPI(title="Wazuh to DefectDojo Integrator")
config = load_config()
dd_client = DefectDojoClient(DOJO_URL, DOJO_API_KEY, config.defectdojo, config.dedup_settings)
alert_queue = AlertQueueWorker(lambda payload: process_alert(payload))
DEFAULT_FOUND_BY_TEST_TYPE_ID = 1


def reload_runtime_config(new_config: AppConfig) -> None:
    global config, dd_client
    config = new_config
    dd_client = DefectDojoClient(DOJO_URL, DOJO_API_KEY, config.defectdojo, config.dedup_settings)


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


def apply_finding_status_rules(alert: WazuhAlert, finding_data: dict) -> None:
    alert_tokens = build_alert_match_tokens(alert)

    for rule in config.finding_status_rules:
        if rule.match_rule_groups and not any(
            rule_matches(match, alert_tokens) for match in rule.match_rule_groups
        ):
            continue

        if rule.severity_min is not None and alert.rule.level < rule.severity_min:
            continue

        if rule.severity_max is not None and alert.rule.level > rule.severity_max:
            continue

        if rule.set_active is not None:
            finding_data["active"] = rule.set_active

        if rule.set_verified is not None:
            finding_data["verified"] = rule.set_verified

        if rule.set_false_positive is not None:
            finding_data["false_p"] = rule.set_false_positive

        if rule.set_out_of_scope is not None:
            finding_data["out_of_scope"] = rule.set_out_of_scope

        if rule.set_risk_accepted is not None:
            finding_data["risk_accepted"] = rule.set_risk_accepted

        if rule.set_under_review is not None:
            finding_data["under_review"] = rule.set_under_review


def _normalize_endpoint_value(value: object) -> str | None:
    if value is None:
        return None

    normalized = str(value).strip()
    if not normalized:
        return None

    if normalized.lower() in {"unknown", "n/a", "none", "-"}:
        return None

    # Skip obvious file paths and other non-host values commonly found in Wazuh `location`.
    if "/" in normalized or "\\" in normalized:
        return None

    ipv4_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    hostname_pattern = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    if re.fullmatch(ipv4_pattern, normalized) or re.fullmatch(hostname_pattern, normalized):
        return normalized

    return None


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


def select_reviewer(owner_group: str, group_config, dedup_key: str) -> tuple[dict | None, bool]:
    if group_config is None:
        return None, True

    candidate_usernames: list[str] = []
    for username in group_config.users:
        normalized = (username or "").strip()
        if normalized and normalized not in candidate_usernames:
            candidate_usernames.append(normalized)

    fallback_user = (group_config.fallback_user or "").strip()
    if fallback_user and fallback_user not in candidate_usernames:
        candidate_usernames.append(fallback_user)

    if not candidate_usernames:
        logger.warning(
            "Finding is under review but owner group '%s' has no configured DefectDojo users available for reviewer auto-assignment.",
            owner_group,
        )
        return None, True

    assigned_username = get_assigned_user(dedup_key, candidate_usernames)
    candidate_order = list(candidate_usernames)
    if assigned_username:
        candidate_order = [assigned_username] + [username for username in candidate_usernames if username != assigned_username]
    else:
        next_username = get_next_user(owner_group, candidate_usernames)
        if next_username:
            next_index = candidate_usernames.index(next_username)
            candidate_order = candidate_usernames[next_index:] + candidate_usernames[:next_index]

    for candidate_username in candidate_order:
        reviewer = dd_client.get_user(candidate_username)
        if reviewer and reviewer.get("id") and reviewer.get("is_active", False):
            return reviewer, False

    logger.warning(
        "Finding is under review but owner group '%s' has no active DefectDojo users available for reviewer auto-assignment.",
        owner_group,
    )
    return None, True


@app.on_event("startup")
def startup_event():
    init_db()
    init_finding_group_db()
    alert_enrichment_service.initialize()
    alert_queue.start()
    logger.info(
        "Service started. Reviewer auto-assignment is enabled only for findings marked under review, and alerts are processed through the durable queue."
    )


@app.on_event("shutdown")
def shutdown_event():
    alert_queue.stop()

def process_alert(raw_payload: dict):
    # 1. Parse Alert
    try:
        alert = WazuhAlert(**raw_payload, raw_payload=raw_payload)
    except Exception as e:
        raise PermanentAlertProcessingError(f"Failed to parse alert: {e}") from e

    if not is_vulnerability_detector_alert(alert):
        logger.info(
            "Skipping alert %s because it is not a Wazuh vulnerability detector alert (rule=%s, groups=%s).",
            alert.id,
            alert.rule.id,
            ",".join(alert.rule.groups),
        )
        return

    try:
        # 2. Routing
        owner_group = determine_owner_group(alert, config)
        group_config = config.teams.get(owner_group)
        tags = build_tags(alert, owner_group, assignment_error=False)
        test_category = get_test_category(tags)
        group_rule_enabled = any(rule.enabled for rule in config.finding_group_rules)

        # 3. Prepare DefectDojo test context
        context = dd_client.ensure_context(
            test_category,
            finding_group_mode="vuln_id_from_tool" if group_rule_enabled else None,
        )
        test_id = context["test_id"]
        product_id = context["product_id"]
        dedup_key = generate_dedup_key(alert)
        existing_finding = dd_client.get_finding_by_dedup(dedup_key)

        assignment_error = group_config is None
        if group_config is None:
            logger.warning(
                "Owner group '%s' is not defined in config.yaml teams. Falling back to unassigned finding.",
                owner_group,
            )

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
            "active": config.finding_defaults.active,
            "verified": config.finding_defaults.verified,
            "false_p": config.finding_defaults.false_positive,
            "out_of_scope": config.finding_defaults.out_of_scope,
            "risk_accepted": config.finding_defaults.risk_accepted,
            "tags": tags,
            "found_by": [DEFAULT_FOUND_BY_TEST_TYPE_ID],
            "unique_id_from_tool": dedup_key
        }

        if config.finding_defaults.under_review is not None:
            finding_data["under_review"] = config.finding_defaults.under_review

        apply_finding_status_rules(alert, finding_data)
        enrichment = alert_enrichment_service.enrich_alert(alert)
        enrichment_tags = [f"cwe_source:{enrichment.cwe_source}"]
        if not enrichment.cve_ids:
            enrichment_tags.append("enrichment:no_cve")
        elif len(enrichment.cve_ids) > 1:
            enrichment_tags.append("enrichment:multi_cve")

        tags = list(dict.fromkeys(finding_data["tags"] + enrichment_tags))
        finding_data["tags"] = tags

        reviewer = None
        if finding_data.get("under_review") is True:
            reviewer, reviewer_assignment_error = select_reviewer(owner_group, group_config, dedup_key)
            if reviewer is not None:
                finding_data["reviewers"] = [reviewer["id"]]
            assignment_error = assignment_error or reviewer_assignment_error
            tags = list(dict.fromkeys(build_tags(alert, owner_group, assignment_error) + enrichment_tags))
            finding_data["tags"] = tags

        if enrichment.cwe is not None:
            finding_data["cwe"] = enrichment.cwe
        if enrichment.epss_score is not None:
            finding_data["epss_score"] = enrichment.epss_score
        if enrichment.epss_percentile is not None:
            finding_data["epss_percentile"] = enrichment.epss_percentile
        if enrichment.known_exploited is not None:
            finding_data["known_exploited"] = enrichment.known_exploited
        if enrichment.ransomware_used is not None:
            finding_data["ransomware_used"] = enrichment.ransomware_used
        if enrichment.kev_date:
            finding_data["kev_date"] = enrichment.kev_date

        finding_group_match = evaluate_finding_group_rule(alert, finding_data, config.finding_group_rules)
        if finding_group_match:
            finding_data["vuln_id_from_tool"] = finding_group_match["group_key"]
            tags = list(
                dict.fromkeys(
                    tags
                    + [
                        "finding_group_active",
                        f"finding_group_rule:{finding_group_match['rule_name'].strip().lower().replace(' ', '-')}",
                        f"finding_group_key:{finding_group_match['group_short_key']}",
                    ]
                )
            )
            finding_data["tags"] = tags

        assign_note = f"Automated Routing: Mapped to group '{owner_group}'."
        if reviewer is not None:
            assign_note += f" Auto-assigned reviewer '{reviewer.get('username')}' because the finding is under review."
        elif finding_data.get("under_review") is True:
            assign_note += " Finding is under review, but no reviewer could be auto-assigned."
        else:
            assign_note += " Finding is not under review, so no reviewer was auto-assigned."
        if finding_group_match:
            assign_note += (
                f" Finding grouping rule '{finding_group_match['rule_name']}' activated after "
                f"{finding_group_match['unique_src_count']} unique source IPs targeted dst_ip "
                f"'{finding_group_match['dst_ip']}' within {finding_group_match['window_minutes']} minutes."
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
            finding_metadata=enrichment.metadata,
        )
        if finding_group_match:
            try:
                anchor_time = datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00")) if alert.timestamp else datetime.now(timezone.utc)
                if anchor_time.tzinfo is None:
                    anchor_time = anchor_time.replace(tzinfo=timezone.utc)
            except Exception:
                anchor_time = datetime.now(timezone.utc)
            dd_client.apply_group_key_to_recent_findings(
                test_id,
                finding_group_match["search_title"],
                finding_group_match["search_dst_ip"],
                finding_group_match["group_key"],
                finding_group_match["window_minutes"],
                anchor_time=anchor_time.astimezone(timezone.utc),
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
            if reviewer is not None:
                remember_assignment(dedup_key, owner_group, reviewer.get("username"))
            logger.info(
                "Alert for rule %s was sent to DefectDojo as new finding %s (Dedup: %s) for owner group %s%s",
                alert.rule.id,
                result["finding_id"],
                dedup_key,
                owner_group,
                f" with reviewer {reviewer.get('username')}" if reviewer is not None else " with no auto-assigned reviewer",
            )
    except Exception as e:
        logger.exception("Failed to process alert %s with DefectDojo: %s", raw_payload.get("id"), e)
        raise

@app.post("/webhook")
async def wazuh_webhook(request: Request):
    payload = await request.json()
    try:
        job_id = alert_queue.enqueue(payload)
    except Exception as exc:
        logger.exception("Failed to enqueue alert %s: %s", payload.get("id"), exc)
        raise HTTPException(status_code=503, detail="Failed to enqueue alert for background processing.") from exc

    return {"status": "accepted", "queue_id": job_id}
