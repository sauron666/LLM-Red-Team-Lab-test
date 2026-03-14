from __future__ import annotations

import httpx

from .base import BaseConnector, ConnectorError


class AnthropicConnector(BaseConnector):
    """Anthropic Messages API connector."""

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url}/v1/messages"
        headers = self.build_headers(
            {
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            },
            default_api_key_header="x-api-key",
        )
        payload = {
            "model": self.model,
            "max_tokens": 512,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        try:
            with self.httpx_client() as client:
                r = client.post(url, headers=headers, json=payload)
                r.raise_for_status()
                data = r.json()
            parts = []
            for item in (data.get("content") or []):
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(item.get("text", ""))
            return "\n".join(parts).strip() if parts else str(data)
        except Exception as e:
            raise ConnectorError(f"Anthropic connector failed: {e}")
