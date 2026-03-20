import re
from typing import Set

from .models import WazuhAlert


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _variants(value: str) -> Set[str]:
    normalized = _normalize(value)
    variants = {value.lower(), normalized}
    if normalized:
        variants.add(normalized.replace("_", "-"))
        variants.add(normalized.replace("_", ""))
    return {variant for variant in variants if variant}


def build_alert_match_tokens(alert: WazuhAlert) -> Set[str]:
    tokens: Set[str] = set()

    for group in alert.rule.groups:
        tokens.update(_variants(group))

    if alert.decoder and alert.decoder.get("name"):
        tokens.update(_variants(str(alert.decoder["name"])))

    predecoder = alert.raw_payload.get("predecoder", {})
    if isinstance(predecoder, dict) and predecoder.get("program_name"):
        tokens.update(_variants(str(predecoder["program_name"])))

    return tokens


def rule_matches(match_value: str, alert_tokens: Set[str]) -> bool:
    return any(candidate in alert_tokens for candidate in _variants(match_value))
