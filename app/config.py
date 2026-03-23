import os
import yaml
from pydantic import BaseModel, model_validator
from typing import List, Dict, Optional, Literal

class RoutingRule(BaseModel):
    match_rule_groups: List[str]
    owner_group: str

class TagRule(BaseModel):
    match_rule_groups: List[str]
    tags: List[str]


class FindingDefaults(BaseModel):
    active: bool = True
    verified: bool = True
    false_positive: bool = False
    out_of_scope: bool = False
    risk_accepted: bool = False
    under_review: Optional[bool] = None


class FindingStatusRule(BaseModel):
    name: str
    match_rule_groups: List[str] = []
    severity_min: Optional[int] = None
    severity_max: Optional[int] = None
    set_active: Optional[bool] = None
    set_verified: Optional[bool] = None
    set_false_positive: Optional[bool] = None
    set_out_of_scope: Optional[bool] = None
    set_risk_accepted: Optional[bool] = None
    set_under_review: Optional[bool] = None

    @model_validator(mode="after")
    def validate_severity_range(self):
        if (
            self.severity_min is not None
            and self.severity_max is not None
            and self.severity_min > self.severity_max
        ):
            raise ValueError("severity_min cannot be greater than severity_max")
        return self


class FindingGroupRule(BaseModel):
    name: str
    enabled: bool = True
    match_rule_groups: List[str] = []
    severity_values: List[str] = ["Low"]
    unique_src_ip_threshold: int = 10
    window_minutes: int = 60
    require_same_title: bool = True
    require_same_dst_ip: bool = True

    @model_validator(mode="after")
    def validate_group_rule(self):
        normalized_values: list[str] = []
        for value in self.severity_values:
            normalized = str(value).strip().lower()
            mapping = {
                "informational": "Informational",
                "info": "Informational",
                "low": "Low",
                "medium": "Medium",
                "high": "High",
                "critical": "Critical",
            }
            if normalized not in mapping:
                raise ValueError(f"Unsupported severity value '{value}' in finding group rule '{self.name}'")
            normalized_values.append(mapping[normalized])
        self.severity_values = normalized_values

        if self.unique_src_ip_threshold < 1:
            raise ValueError("unique_src_ip_threshold must be at least 1")
        if self.window_minutes < 1:
            raise ValueError("window_minutes must be at least 1")
        return self


class DedupSettings(BaseModel):
    enabled: bool = True
    use_unique_id: bool = True
    use_title_test_fallback: bool = True
    require_same_endpoint: bool = True
    require_same_cwe: bool = True
    require_network_match: bool = True
    network_match_mode: Literal["any", "all"] = "any"
    network_match_fields: List[Literal["src_ip", "observed_ip", "dst_ip"]] = [
        "src_ip",
        "observed_ip",
        "dst_ip",
    ]
    ignore_mitigated: bool = True
    action_on_match: Literal["skip", "create_new"] = "skip"

class TeamConfig(BaseModel):
    users: List[str]
    fallback_user: str

class DefectDojoNamedConfig(BaseModel):
    name: str
    description: str = ""

class DefectDojoEngagementConfig(BaseModel):
    name: str
    status: str = "In Progress"
    target_start: str = "2020-01-01"
    target_end: str = "2099-12-31"

class DefectDojoTestConfig(BaseModel):
    title_prefix: str = "Wazuh Alerts"
    test_type_id: int = 1
    target_start: str = "2020-01-01"
    target_end: str = "2099-12-31"

class DefectDojoConfig(BaseModel):
    product_type: DefectDojoNamedConfig
    product: DefectDojoNamedConfig
    engagement: DefectDojoEngagementConfig
    test: DefectDojoTestConfig = DefectDojoTestConfig()

class CategoryConfig(BaseModel):
    tag_to_test: Dict[str, str] = {}
    default_test: str = "General Monitoring"

class AppConfig(BaseModel):
    defectdojo: DefectDojoConfig
    categories: CategoryConfig = CategoryConfig()
    finding_defaults: FindingDefaults = FindingDefaults()
    dedup_settings: DedupSettings = DedupSettings()
    teams: Dict[str, TeamConfig]
    routing_rules: List[RoutingRule]
    tag_rules: List[TagRule] = []
    finding_status_rules: List[FindingStatusRule] = []
    finding_group_rules: List[FindingGroupRule] = []
    default_owner_group: str

def load_config(path: str = "config.yaml") -> AppConfig:
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return AppConfig(**data)

def save_config(config: AppConfig, path: str = "config.yaml") -> None:
    with open(path, "w") as f:
        yaml.safe_dump(config.model_dump(mode="python"), f, sort_keys=False)

DOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8080").rstrip('/')
DOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
DB_PATH = os.getenv("ASSIGNMENT_DB_PATH", "assignments.sqlite")
DOJO_TIMEOUT_SECONDS = float(os.getenv("DEFECTDOJO_TIMEOUT_SECONDS", "30"))
NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0").rstrip("/")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_TIMEOUT_SECONDS = float(os.getenv("NVD_TIMEOUT_SECONDS", "10"))
ALERT_QUEUE_POLL_SECONDS = float(os.getenv("ALERT_QUEUE_POLL_SECONDS", "2"))
ALERT_QUEUE_MAX_ATTEMPTS = int(os.getenv("ALERT_QUEUE_MAX_ATTEMPTS", "5"))
ALERT_QUEUE_RETRY_BASE_SECONDS = float(os.getenv("ALERT_QUEUE_RETRY_BASE_SECONDS", "15"))
ALERT_QUEUE_RETRY_MAX_SECONDS = float(os.getenv("ALERT_QUEUE_RETRY_MAX_SECONDS", "300"))
ALERT_QUEUE_FAILURE_PREVIEW_LIMIT = int(os.getenv("ALERT_QUEUE_FAILURE_PREVIEW_LIMIT", "10"))
