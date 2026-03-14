from __future__ import annotations

from typing import Dict

from .base import BaseConnector
from .litellm_connector import LiteLLMConnector
from .custom_http_json import CustomHTTPJSONConnector
from .catalog import CONNECTOR_SPECS


def build_connector(target: Dict) -> BaseConnector:
    connector_type = (target.get("connector_type") or "").strip()
    spec = CONNECTOR_SPECS.get(connector_type, {})
    impl = (spec.get("implementation") or connector_type).strip()
    common = dict(
        base_url=target.get("base_url", ""),
        model=target.get("model", ""),
        api_key=target.get("api_key", ""),
        timeout_sec=int(target.get("timeout_sec", 30)),
        extra_headers=target.get("extra_headers", {}) or {},
    )
    if impl in ("openai_compat", "gemini", "ollama", "anthropic", "azure_openai"):
        common["provider_impl"] = impl
        return LiteLLMConnector(**common)
    if impl == "custom_http_json":
        return CustomHTTPJSONConnector(**common)
    if impl == "webchat_playwright":
        from .webchat_playwright import WebChatPlaywrightConnector
        return WebChatPlaywrightConnector(**common)
    raise ValueError(f"Unsupported connector_type: {connector_type} (impl={impl})")
