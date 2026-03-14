from __future__ import annotations

import httpx
from typing import Any, Dict, Optional
import litellm

from .base import BaseConnector, ConnectorError


class LiteLLMConnector(BaseConnector):
    """
    Universal connector leveraging `litellm` to support 100+ LLM providers.
    Removes the need for manual HTTP POST handling for standard APIs.
    """
    def __init__(self, provider_impl: str = "", **kwargs):
        super().__init__(**kwargs)
        self.provider_impl = provider_impl

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        # Prevent litellm from printing excessive debug info
        litellm.set_verbose = False
        
        # Configure auth
        auth = self._auth_cfg()
        api_key_val = str(auth.get("token") or auth.get("value") or auth.get("api_key") or self.api_key or "").strip()
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        model_name = self.model
        
        # Add required provider prefixes for litellm if they are missing
        if self.provider_impl == "gemini" and not model_name.startswith("gemini/") and not model_name.startswith("vertex_ai/"):
            model_name = f"gemini/{model_name}"
        elif self.provider_impl == "anthropic" and not model_name.startswith("anthropic/"):
            model_name = f"anthropic/{model_name}"
        elif self.provider_impl == "ollama" and not model_name.startswith("ollama/"):
            model_name = f"ollama/{model_name}"
        elif self.provider_impl == "azure_openai" and not model_name.startswith("azure/"):
            model_name = f"azure/{model_name}"

        kwargs: Dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 1024,
        }

        # Handle specific base URLs or prefixes depending on connector configuration
        if self.base_url:
            # litellm breaks if you pass the default base_url to native gemini/anthropic
            if self.provider_impl == "gemini" and self.base_url.startswith("https://generativelanguage.googleapis.com"):
                pass
            elif self.provider_impl == "anthropic" and self.base_url.startswith("https://api.anthropic.com"):
                pass
            else:
                kwargs["api_base"] = self.base_url
            
        if api_key_val:
            kwargs["api_key"] = api_key_val
            
        # Optional TLS overrides
        tls = self._tls_cfg()
        if tls and (tls.get("insecure") is True or tls.get("verify") is False):
            # Tell litellm to disable verification if supported, or rely on environment
            import os
            os.environ["LITELLM_VERIFY_SSL"] = "False"
        
        # Extra headers
        headers = self.build_headers({}, exclude_extra_keys={"_auth", "_tls", "_proxy", "_http_connector"})
        if headers:
            kwargs["extra_headers"] = headers

        try:
            # Map known models to their litellm prefix if not provided
            # e.g., if it's anthropic, litellm likes 'anthropic/claude-3-opus...' or just handles it if key is set.
            # But we can rely on litellm's generic routing.
            response = litellm.completion(**kwargs)
            return response.choices[0].message.content
        except litellm.exceptions.AuthenticationError as e:
            raise ConnectorError(f"Authentication failed: {e}. Please check your API key.")
        except Exception as e:
            raise ConnectorError(f"LiteLLM connector failed: {e}")

    def test_connection(self) -> str:
        # A lightweight check against the provider to verify auth/network.
        try:
            self.chat("You are a test assistant.", "Reply with exactly: OK")
            return "SUCCESS"
        except Exception as e:
            raise ConnectorError(f"Connection test failed: {e}")
