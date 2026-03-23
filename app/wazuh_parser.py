import hashlib
import json
import re
from .matching import build_alert_match_tokens, rule_matches
from .models import WazuhAlert

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

RULE_GROUP_CWE_MAP: list[tuple[list[str], int]] = [
    (["authentication_failed", "brute_force"], 307),
    (["authentication_success", "vpn_anomaly"], 287),
    (["web_attack"], 20),
    (["sql_injection"], 89),
    (["xss"], 79),
    (["path_traversal"], 22),
    (["firewall_drop"], 284),
    (["malware", "ransomware", "rootkit"], 506),
    (["recon"], 200),
    (["email_phishing"], 601),
    (["spam"], 0),
]

TITLE_KEYWORD_CWE_MAP: list[tuple[str, int]] = [
    ("buffer overflow", 119),
    ("null pointer", 476),
    ("privilege escal", 269),
    ("command inject", 77),
    ("ldap inject", 90),
    ("xxe", 611),
    ("ssrf", 918),
    ("deserializ", 502),
    ("weak cipher", 326),
    ("cleartext", 319),
]

def get_rule_description(alert: WazuhAlert) -> str:
    if alert.rule.description:
        return alert.rule.description

    if alert.rule.groups:
        return f"Wazuh event for groups: {', '.join(alert.rule.groups)}"

    return f"Wazuh rule {alert.rule.id}"


def extract_cve(alert: WazuhAlert) -> str | None:
    cves = extract_cves(alert)
    return cves[0] if cves else None


def extract_cves(alert: WazuhAlert) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    normalized_candidates: list[str] = []

    if alert.data:
        candidates.extend(
            _extract_candidate_strings(
                [
                    alert.data.get("cve"),
                    alert.data.get("cve_id"),
                    alert.data.get("cves"),
                ]
            )
        )

        vulnerability = alert.data.get("vulnerability")
        if isinstance(vulnerability, dict):
            candidates.extend(
                _extract_candidate_strings(
                    [
                        vulnerability.get("cve"),
                        vulnerability.get("cve_id"),
                        vulnerability.get("cves"),
                    ]
                )
            )

    raw_vulnerability = alert.raw_payload.get("vulnerability") if isinstance(alert.raw_payload, dict) else None
    if isinstance(raw_vulnerability, dict):
        candidates.extend(
            _extract_candidate_strings(
                [
                    raw_vulnerability.get("cve"),
                    raw_vulnerability.get("cve_id"),
                    raw_vulnerability.get("cves"),
                ]
            )
        )

    raw_payload_text = json.dumps(alert.raw_payload, default=str)
    candidates.extend(CVE_PATTERN.findall(raw_payload_text))

    for candidate in candidates:
        if not candidate:
            continue
        normalized = str(candidate).strip().upper()
        if not normalized.startswith("CVE-"):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        normalized_candidates.append(normalized)

    return normalized_candidates


def _extract_candidate_strings(values: list[object]) -> list[str]:
    candidates: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if item is not None:
                    candidates.append(str(item))
            continue
        candidates.append(str(value))
    return candidates

def map_severity(level: int) -> str:
    if level <= 4: return "Low"
    if level <= 7: return "Medium"
    if level <= 10: return "High"
    return "Critical"

def generate_dedup_key(alert: WazuhAlert) -> str:
    host_identity = alert.agent.id or alert.agent.name
    alert_tokens = build_alert_match_tokens(alert)
    src_ip = alert.data.get("srcip") if alert.data else None
    cve = extract_cve(alert)

    base = f"{alert.rule.id}-{host_identity}"

    if any(rule_matches(match, alert_tokens) for match in ["authentication_failed", "invalid_login", "sshd", "pam"]) and src_ip:
        base += f"-{src_ip}"
    elif any(rule_matches(match, alert_tokens) for match in ["vulnerability", "vuln", "syscollector"]) and cve:
        base += f"-{cve}"
            
    return hashlib.md5(base.encode()).hexdigest()


def extract_direct_cwe(alert: WazuhAlert) -> int | None:
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

    return None


def map_internal_cwe(alert: WazuhAlert) -> tuple[int, str]:
    rule_description = get_rule_description(alert).lower()

    for keyword, cwe in TITLE_KEYWORD_CWE_MAP:
        if keyword in rule_description:
            return cwe, "title_keyword"

    alert_tokens = build_alert_match_tokens(alert)
    for patterns, cwe in RULE_GROUP_CWE_MAP:
        if any(rule_matches(pattern, alert_tokens) for pattern in patterns):
            return cwe, "rule_group"

    return 0, "fallback"


def extract_cwe(alert: WazuhAlert) -> int | None:
    direct_cwe = extract_direct_cwe(alert)
    if direct_cwe is not None:
        return direct_cwe
    cwe, _ = map_internal_cwe(alert)
    return cwe


def is_vulnerability_detector_alert(alert: WazuhAlert) -> bool:
    if alert.data and isinstance(alert.data.get("vulnerability"), dict):
        return True

    raw_vulnerability = alert.raw_payload.get("vulnerability") if isinstance(alert.raw_payload, dict) else None
    if isinstance(raw_vulnerability, dict):
        return True

    alert_tokens = build_alert_match_tokens(alert)
    if any(
        rule_matches(match, alert_tokens)
        for match in [
            "vulnerability-detector",
            "vulnerability_detector",
            "vulnerability",
            "syscollector",
        ]
    ):
        return True

    return False

def generate_markdown_description(alert: WazuhAlert) -> str:
    rule_description = get_rule_description(alert)
    desc = f"### Wazuh Alert Summary\n\n"
    desc += f"**Description:** {rule_description}\n"
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
