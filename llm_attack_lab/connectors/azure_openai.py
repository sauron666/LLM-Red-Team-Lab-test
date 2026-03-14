from __future__ import annotations

import httpx

from .base import BaseConnector, ConnectorError


class AzureOpenAIConnector(BaseConnector):
    """Azure OpenAI Chat Completions connector."""

    DEFAULT_API_VERSION = "2024-10-21"

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        api_version = str((self.extra_headers or {}).get("x-azure-api-version") or self.DEFAULT_API_VERSION)
        url = f"{self.base_url}/chat/completions?api-version={api_version}"
        headers = self.build_headers(
            {"Content-Type": "application/json"},
            default_api_key_header="api-key",
            exclude_extra_keys={"x-azure-api-version"},
        )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }
        try:
            with self.httpx_client() as client:
                r = client.post(url, headers=headers, json=payload)
                r.raise_for_status()
                data = r.json()
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            content = msg.get("content")
            if isinstance(content, list):
                return "\n".join([str(x.get("text", "")) for x in content if isinstance(x, dict)]).strip()
            return str(content or "")
        except Exception as e:
            raise ConnectorError(f"Azure OpenAI connector failed: {e}")
