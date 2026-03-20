from .config import AppConfig
from .matching import build_alert_match_tokens, rule_matches
from .models import WazuhAlert

def determine_owner_group(alert: WazuhAlert, config: AppConfig) -> str:
    alert_tokens = build_alert_match_tokens(alert)
    
    for rule in config.routing_rules:
        for match in rule.match_rule_groups:
            if rule_matches(match, alert_tokens):
                return rule.owner_group
                
    return config.default_owner_group
