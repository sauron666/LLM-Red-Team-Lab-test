from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Iterable

from ..transport import build_httpx_client, extract_transport_cfg_from_headers


class ConnectorError(RuntimeError):
    pass


class BaseConnector(ABC):
    def __init__(self, base_url: str, model: str, api_key: str = "", timeout_sec: int = 30, extra_headers: Optional[Dict[str, Any]] = None):
        self.base_url = (base_url or "").rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_sec = timeout_sec
        self.extra_headers: Dict[str, Any] = extra_headers or {}

    def _cfg(self, key: str) -> Dict[str, Any]:
        raw = self.extra_headers or {}
        val = raw.get(key)
        return dict(val) if isinstance(val, dict) else {}

    def _auth_cfg(self) -> Dict[str, Any]:
        return self._cfg("_auth")

    def _lab_cfg(self) -> Dict[str, Any]:
        return self._cfg("_lab")

    def _tls_cfg(self) -> Dict[str, Any]:
        return self._cfg("_tls")

    def httpx_client(self, *, follow_redirects: bool = False):
        """Return an httpx.Client configured from target transport settings.

        Uses extra_headers['_tls'] and extra_headers['_proxy'] (if present).
        """
        tls_cfg, proxy_cfg = extract_transport_cfg_from_headers(self.extra_headers)
        return build_httpx_client(
            timeout_sec=int(self.timeout_sec or 30),
            follow_redirects=bool(follow_redirects),
            tls_cfg=tls_cfg,
            proxy_cfg=proxy_cfg,
            verify_override=None,
        )

    def httpx_verify(self) -> bool:
        """Return whether TLS cert verification should be enabled.

        Controlled via extra_headers._tls:
          - {"verify": false} or {"verify_tls": false}
          - {"insecure": true} (alias for verify=false)
        Default is True.
        """
        tls = self._tls_cfg()
        if not isinstance(tls, dict):
            return True
        if "verify" in tls:
            try:
                return bool(tls.get("verify"))
            except Exception:
                return True
        if "verify_tls" in tls:
            try:
                return bool(tls.get("verify_tls"))
            except Exception:
                return True
        if tls.get("insecure") is True:
            return False
        return True

    def playwright_ignore_https_errors(self) -> bool:
        tls = self._tls_cfg()
        if isinstance(tls, dict):
            if "ignore_https_errors" in tls:
                return bool(tls.get("ignore_https_errors"))
            if tls.get("insecure") is True:
                return True
            if "verify" in tls and bool(tls.get("verify")) is False:
                return True
        return False

    def public_extra_headers(self, *, exclude_keys: Optional[Iterable[str]] = None) -> Dict[str, str]:
        exclude = {str(x) for x in (exclude_keys or [])}
        out: Dict[str, str] = {}
        for k, v in (self.extra_headers or {}).items():
            if not isinstance(k, str):
                continue
            if k.startswith("_") or k in exclude:
                continue
            if v is None:
                continue
            out[k] = str(v)
        return out

    def build_headers(
        self,
        base_headers: Optional[Dict[str, str]] = None,
        *,
        default_api_key_header: Optional[str] = None,
        exclude_extra_keys: Optional[Iterable[str]] = None,
    ) -> Dict[str, str]:
        """Build outbound headers by combining public extra headers and auth/session config.

        Supported auth modes in extra_headers['_auth']:
          - none
          - bearer  (token / value)
          - api_key  (header_name + token/value)
          - cookie / session / sso (cookie / cookie_header + optional headers)
        """
        headers: Dict[str, str] = dict(base_headers or {})
        headers.update(self.public_extra_headers(exclude_keys=exclude_extra_keys))

        auth = self._auth_cfg()
        mode = str(auth.get("mode") or "").strip().lower()

        def _add_token_header(header_name: str, token: str):
            if not token:
                return
            hn = str(header_name or "").strip()
            if not hn:
                return
            if hn.lower() == "authorization":
                tok = token if token.lower().startswith(("bearer ", "basic ")) else f"Bearer {token}"
                headers[hn] = tok
            else:
                headers[hn] = token

        # Default API key behavior (unless overridden by auth config)
        if self.api_key and default_api_key_header and mode in {"", "none"}:
            _add_token_header(default_api_key_header, str(self.api_key))

        # Explicit auth config behavior
        token_like = str(auth.get("token") or auth.get("value") or auth.get("api_key") or "").strip()
        if mode == "bearer":
            _add_token_header("Authorization", token_like or self.api_key)
        elif mode == "api_key":
            header_name = str(auth.get("header_name") or default_api_key_header or "x-api-key")
            _add_token_header(header_name, token_like or self.api_key)
        elif mode in {"cookie", "session", "sso"}:
            cookie = str(auth.get("cookie") or auth.get("cookie_header") or "").strip()
            if cookie:
                headers["Cookie"] = cookie
            # Optional extra session/SSO headers (e.g., CSRF)
            for hk, hv in (auth.get("headers") or auth.get("session_headers") or {}).items() if isinstance((auth.get("headers") or auth.get("session_headers") or {}), dict) else []:
                headers[str(hk)] = str(hv)
            # Hybrid SSO apps sometimes also require bearer
            if mode == "sso":
                h_name = str(auth.get("header_name") or "").strip()
                if h_name and token_like:
                    _add_token_header(h_name, token_like)
                elif token_like and auth.get("include_bearer"):
                    _add_token_header("Authorization", token_like)
        elif mode == "none":
            pass
        elif mode and token_like and default_api_key_header:
            # Unknown mode but explicit token present - best-effort
            _add_token_header(default_api_key_header, token_like)

        return headers

    @abstractmethod
    def chat(self, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError

    def test_connection(self) -> str:
        # A safe minimal call. For some connectors it may still require a valid model.
        return self.chat("You are a test assistant.", "Reply with exactly: OK")
