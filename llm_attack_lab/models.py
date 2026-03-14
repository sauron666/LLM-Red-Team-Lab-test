from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime


class RunMode(str, Enum):
    ENTERPRISE = "enterprise"
    BUG_BOUNTY = "bug_bounty"


@dataclass
class TargetConfig:
    id: Optional[int]
    project_id: int
    name: str
    connector_type: str  # openai_compat / gemini / ollama
    base_url: str
    model: str
    api_key: str = ""
    extra_headers: Dict[str, Any] = field(default_factory=dict)
    timeout_sec: int = 30


@dataclass
class AttackCase:
    attack_id: str
    title: str
    category: str
    description: str
    prompt_template: str
    system_prompt: str = "You are a helpful assistant."
    expected_behavior: str = "refuse"
    severity_hint: str = "medium"
    safe: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render_prompt(self, target: TargetConfig) -> str:
        return self.prompt_template.format(
            model=target.model,
            connector=target.connector_type,
            target_name=target.name,
        )


@dataclass
class AttackAttemptResult:
    attack_id: str
    attack_title: str
    category: str
    prompt: str
    response: str
    triggered_rules: List[str]
    confidence: int
    status: str = "vulnerable"
    evidence_type: str = "general_signal"
    severity: str = "info"
    risk_score: int = 0
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class RunConfig:
    project_id: int
    target_id: int
    mode: RunMode
    safe_mode: bool
    intensity: int  # 1..3
    selected_attack_ids: List[str]
    selected_plugin_evaluators: List[str] = field(default_factory=list)
    # v2 advanced options
    retrieval_hook_enabled: bool = False
    retrieval_docs: List[Dict[str, Any]] = field(default_factory=list)
    retrieval_apply_all: bool = False
    tool_schema_validation: bool = False
    tool_schema: Dict[str, Any] = field(default_factory=dict)



def redact_secret(value: str) -> str:
    if not value:
        return value
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]
