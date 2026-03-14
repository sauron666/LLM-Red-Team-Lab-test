from __future__ import annotations

import httpx

from .base import BaseConnector, ConnectorError


class OpenAICompatConnector(BaseConnector):
    def chat(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = self.build_headers({"Content-Type": "application/json"}, default_api_key_header="Authorization")
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
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            raise ConnectorError(f"OpenAI-compatible connector failed: {e}")
