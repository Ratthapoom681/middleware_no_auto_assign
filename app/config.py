import os
import yaml
from pydantic import BaseModel
from typing import List, Dict

class RoutingRule(BaseModel):
    match_rule_groups: List[str]
    owner_group: str

class TagRule(BaseModel):
    match_rule_groups: List[str]
    tags: List[str]

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
    teams: Dict[str, TeamConfig]
    routing_rules: List[RoutingRule]
    tag_rules: List[TagRule] = []
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
