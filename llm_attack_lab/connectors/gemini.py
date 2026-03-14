from __future__ import annotations

import httpx

from .base import BaseConnector, ConnectorError


class GeminiConnector(BaseConnector):
    def chat(self, system_prompt: str, user_prompt: str) -> str:
        base = self.base_url or "https://generativelanguage.googleapis.com"
        model = self.model.strip() or "gemini-2.0-flash"

        # Preferred auth: x-goog-api-key header (official)
        # Optional fallback: query parameter if explicitly configured.
        auth = self._auth_cfg()
        auth_mode = str(auth.get("mode") or "").strip().lower()

        query_param = str(auth.get("query_param") or "key").strip()
        query_key = str(auth.get("query_api_key") or "").strip()

        # If query_api_key is explicitly set, use query parameter.
        use_query = bool(query_key)
        url = f"{base.rstrip('/')}/v1beta/models/{model}:generateContent"
        if use_query:
            sep = '&' if '?' in url else '?'
            url = f"{url}{sep}{query_param}={query_key}"

        headers = self.build_headers(
            {"Content-Type": "application/json"},
            default_api_key_header="x-goog-api-key",
        )

        # If no explicit auth config and no api_key, fail fast
        if not use_query and not (headers.get("x-goog-api-key") or headers.get("X-Goog-Api-Key") or self.api_key.strip()):
            raise ConnectorError("Gemini connector requires API key (x-goog-api-key) or explicit _auth config.")

        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.2},
        }
        try:
            with self.httpx_client() as client:
                r = client.post(url, headers=headers, json=payload)
                r.raise_for_status()
                data = r.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise ConnectorError(f"No Gemini candidates returned: {data}")
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            return text
        except Exception as e:
            raise ConnectorError(f"Gemini connector failed: {e}")
