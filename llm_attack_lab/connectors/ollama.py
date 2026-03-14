from __future__ import annotations

import httpx

from .base import BaseConnector, ConnectorError


class OllamaConnector(BaseConnector):
    def chat(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url}/api/chat"
        headers = self.build_headers({"Content-Type": "application/json"})
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        }
        try:
            with self.httpx_client() as client:
                r = client.post(url, headers=headers, json=payload)
                r.raise_for_status()
                data = r.json()
            msg = data.get("message", {})
            return msg.get("content", "")
        except Exception as e:
            raise ConnectorError(f"Ollama connector failed: {e}")
