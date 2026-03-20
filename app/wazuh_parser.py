import hashlib
import json
from .matching import build_alert_match_tokens, rule_matches
from .models import WazuhAlert

def map_severity(level: int) -> str:
    if level <= 4: return "Low"
    if level <= 7: return "Medium"
    if level <= 10: return "High"
    return "Critical"

def generate_dedup_key(alert: WazuhAlert) -> str:
    host_identity = alert.agent.id or alert.agent.name
    alert_tokens = build_alert_match_tokens(alert)
    src_ip = alert.data.get("srcip") if alert.data else None
    cve = None
    if alert.data and "vulnerability" in alert.data and "cve" in alert.data["vulnerability"]:
        cve = alert.data["vulnerability"]["cve"]

    base = f"{alert.rule.id}-{host_identity}"

    if any(rule_matches(match, alert_tokens) for match in ["authentication_failed", "invalid_login", "sshd", "pam"]) and src_ip:
        base += f"-{src_ip}"
    elif any(rule_matches(match, alert_tokens) for match in ["vulnerability", "vuln", "syscollector"]) and cve:
        base += f"-{cve}"
            
    return hashlib.md5(base.encode()).hexdigest()

def extract_cwe(alert: WazuhAlert) -> int | None:
    candidates = []

    if alert.data:
        candidates.extend([
            alert.data.get("cwe"),
            alert.data.get("cwe_id"),
            alert.data.get("weakness"),
        ])
        vulnerability = alert.data.get("vulnerability")
        if isinstance(vulnerability, dict):
            candidates.extend([
                vulnerability.get("cwe"),
                vulnerability.get("cwe_id"),
                vulnerability.get("weakness"),
            ])

    raw_vulnerability = alert.raw_payload.get("vulnerability") if isinstance(alert.raw_payload, dict) else None
    if isinstance(raw_vulnerability, dict):
        candidates.extend([
            raw_vulnerability.get("cwe"),
            raw_vulnerability.get("cwe_id"),
            raw_vulnerability.get("weakness"),
        ])

    for candidate in candidates:
        if candidate is None:
            continue
        digits = "".join(char for char in str(candidate) if char.isdigit())
        if digits:
            return int(digits)

    groups = {group.lower() for group in alert.rule.groups}
    if "vulnerability" in groups or "vuln" in groups or "syscollector" in groups:
        return 1104
    if "authentication_failed" in groups or "invalid_login" in groups or "sshd" in groups or "pam" in groups:
        return 307

    return None

def generate_markdown_description(alert: WazuhAlert) -> str:
    desc = f"### Wazuh Alert Summary\n\n"
    desc += f"**Description:** {alert.rule.description}\n"
    desc += f"**Rule ID:** {alert.rule.id} (Level {alert.rule.level})\n"
    desc += f"**Agent:** {alert.agent.name} ({alert.agent.id})\n"
    desc += f"**Location:** {alert.location}\n\n"
    
    if alert.full_log:
        desc += f"**Full Log:**\n```text\n{alert.full_log}\n```\n\n"

    cwe = extract_cwe(alert)
    if cwe:
        desc += f"**CWE:** CWE-{cwe}\n\n"

    desc += f"**Raw JSON Payload:**\n```json\n{json.dumps(alert.raw_payload, indent=2)}\n```\n"
    return desc

def generate_impact(alert: WazuhAlert) -> str:
    groups = {group.lower() for group in alert.rule.groups}
    src_ip = alert.data.get("srcip") if alert.data else None

    if "vulnerability" in groups or "vuln" in groups or "syscollector" in groups:
        return (
            "This finding indicates a potential vulnerable asset state on the monitored endpoint. "
            "If exploitable, it could allow unauthorized access, privilege escalation, service disruption, "
            "or data exposure depending on the affected software and reachable attack surface."
        )

    if "authentication_failed" in groups or "invalid_login" in groups or "sshd" in groups or "pam" in groups:
        source_text = f" from source IP {src_ip}" if src_ip else ""
        return (
            "This finding indicates repeated or suspicious authentication activity"
            f"{source_text}. If the activity is malicious and successful, it could lead to unauthorized "
            "access, account compromise, and lateral movement on the endpoint."
        )

    return (
        "This finding indicates suspicious or security-relevant activity detected by Wazuh on the endpoint. "
        "If confirmed malicious, it could affect system confidentiality, integrity, or availability."
    )

def generate_mitigation(alert: WazuhAlert) -> str:
    groups = {group.lower() for group in alert.rule.groups}

    if "vulnerability" in groups or "vuln" in groups or "syscollector" in groups:
        return (
            "Validate the vulnerable package or software version on the endpoint, apply the relevant vendor patch "
            "or upgrade, and confirm remediation with a follow-up scan. If patching is not immediately possible, "
            "document compensating controls and reduce exposure."
        )

    if "authentication_failed" in groups or "invalid_login" in groups or "sshd" in groups or "pam" in groups:
        return (
            "Review the authentication logs for the affected host, verify whether the source activity is authorized, "
            "block malicious source IPs if appropriate, enforce strong credentials and MFA where possible, and "
            "investigate for signs of brute-force or account abuse."
        )

    return (
        "Review the raw event details, validate whether the activity is expected, contain the affected host if needed, "
        "and apply the relevant remediation steps based on the alert source, impacted service, and confirmed root cause."
    )
