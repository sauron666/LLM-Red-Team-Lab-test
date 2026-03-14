from typing import Dict, Type
from .base import BaseConnector
from .openai_compat import OpenAICompatConnector
from .gemini import GeminiConnector
from .ollama import OllamaConnector
from .custom_http_json import CustomHTTPJSONConnector

class ConnectorRegistry:
    def __init__(self):
        self._map: Dict[str, Type[BaseConnector]] = {
            "openai_compat": OpenAICompatConnector,
            "gemini": GeminiConnector,
            "ollama": OllamaConnector,
            "custom_http_json": CustomHTTPJSONConnector,
        }
    def names(self):
        return sorted(self._map.keys())
    def create(self, name: str, **kwargs)->BaseConnector:
        if name not in self._map:
            raise ValueError(f"Unknown connector: {name}")
        return self._map[name](**kwargs)
