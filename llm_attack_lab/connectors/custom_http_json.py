from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from .base import BaseConnector, ConnectorError
from ..transport import build_httpx_client, extract_transport_cfg_from_headers


_PLACEHOLDER_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _json_loads_maybe(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _split_path(path: str) -> List[str]:
    out: List[str] = []
    for part in str(path or "").split("."):
        part = part.strip()
        if part:
            out.append(part)
    return out


def _walk_get(data: Any, path: str) -> Any:
    cur = data
    for part in _split_path(path):
        if isinstance(cur, list):
            if not part.isdigit():
                return None
            idx = int(part)
            if idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
        elif isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        else:
            return None
    return cur


def _walk_set(data: Any, path: str, value: Any) -> bool:
    parts = _split_path(path)
    if not parts:
        return False
    cur = data
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if isinstance(cur, list):
            if not part.isdigit():
                return False
            idx = int(part)
            while idx >= len(cur):
                cur.append({})
            if last:
                cur[idx] = value
                return True
            if not isinstance(cur[idx], (dict, list)):
                cur[idx] = {}
            cur = cur[idx]
        elif isinstance(cur, dict):
            if last:
                cur[part] = value
                return True
            nxt = cur.get(part)
            if not isinstance(nxt, (dict, list)):
                nxt = {}
                cur[part] = nxt
            cur = nxt
        else:
            return False
    return False


def _render_template_obj(obj: Any, vars_map: Dict[str, str]) -> Any:
    if isinstance(obj, dict):
        return {k: _render_template_obj(v, vars_map) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render_template_obj(v, vars_map) for v in obj]
    if isinstance(obj, str):
        def _repl(m):
            key = m.group(1)
            return str(vars_map.get(key, m.group(0)))
        return _PLACEHOLDER_RE.sub(_repl, obj)
    return obj


def _truncate(text: str, limit: int = 2400) -> str:
    t = (text or "").strip()
    if len(t) <= limit:
        return t
    return t[:limit] + "\n...[truncated]"


class CustomHTTPJSONConnector(BaseConnector):
    """Generic connector for custom/internal chat APIs.

    Configuration is read from extra_headers['_http_connector'] and supports:
      - method: POST/GET/... (default POST)
      - path: relative or absolute request path (default '')
      - body_template: dict/list/string JSON template, placeholders {{prompt}}, {{system_prompt}}, {{model}}
      - raw_body: optional raw body string template (placeholders supported)
      - content_type: application/json, application/x-www-form-urlencoded, etc.
      - prompt_field/system_field/model_field: dotted paths
      - include_model: bool (default true)
      - response_text_paths: list[str]
      - stream: bool (SSE support; joins token chunks)
      - follow_redirects: bool (default false)
      - path_params: dict (e.g. {'session_id': '...'}), used with format placeholders in path

    Optional internal session bootstrap:
      bootstrap: {
        enabled: true,
        method: 'POST',
        path: '/chat/v1/session',
        body_template: {...},
        headers: {...} (optional additional headers),
        extract: {'session_id': 'data.session_id'} (json path)
      }
    """

    DEFAULT_RESPONSE_PATHS = [
        "choices.0.message.content",
        "choices.0.delta.content",
        "output_text",
        "text",
        "message",
        "response",
        "answer",
        "content",
        "data.message",
        "data.response",
        "data.content",
        "result",
        "result.text",
        "reply",
    ]

    def _cfg_http(self) -> Dict[str, Any]:
        raw = self.extra_headers.get("_http_connector")
        return dict(raw) if isinstance(raw, dict) else {}

    def _build_url(self, cfg: Dict[str, Any]) -> str:
        path = str(cfg.get("path") or "").strip()
        if not path:
            return self.base_url
        params: Dict[str, Any] = {}
        if isinstance(cfg.get("path_params"), dict):
            params.update(cfg.get("path_params") or {})
        if isinstance(self._lab_cfg(), dict):
            params.update({k: v for k, v in self._lab_cfg().items() if isinstance(k, str)})
        try:
            path = path.format(**params)
        except Exception:
            pass
        if path.startswith(("http://", "https://")):
            return path
        return urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))

    def _request_payload(self, cfg: Dict[str, Any], system_prompt: str, user_prompt: str) -> tuple[Any, Optional[str]]:
        body_template = cfg.get("body_template")
        vars_map = {"prompt": user_prompt, "system_prompt": system_prompt, "model": self.model}

        if body_template is None:
            payload: Any = {}
        elif isinstance(body_template, (dict, list)):
            payload = _render_template_obj(deepcopy(body_template), vars_map)
        elif isinstance(body_template, str):
            rendered = _render_template_obj(body_template, vars_map)
            parsed = _json_loads_maybe(rendered)
            payload = parsed if parsed is not None else {"message": rendered}
        else:
            payload = {}

        if not isinstance(payload, (dict, list)):
            payload = {"message": str(payload)}

        prompt_field = str(cfg.get("prompt_field") or "").strip()
        system_field = str(cfg.get("system_field") or "").strip()
        model_field = str(cfg.get("model_field") or "model").strip()
        include_model = bool(cfg.get("include_model", True))

        if isinstance(payload, dict) and not payload:
            if cfg.get("messages_mode"):
                payload = {
                    model_field if include_model else "_": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                }
                if not include_model:
                    payload.pop("_", None)
            else:
                payload = {"message": user_prompt}
                if include_model:
                    payload[model_field] = self.model
                if system_field:
                    _walk_set(payload, system_field, system_prompt)

        if isinstance(payload, dict):
            if include_model and model_field:
                _walk_set(payload, model_field, self.model)
            if prompt_field:
                _walk_set(payload, prompt_field, user_prompt)
            elif "message" in payload and isinstance(payload.get("message"), str):
                payload["message"] = user_prompt
            elif "prompt" in payload and isinstance(payload.get("prompt"), str):
                payload["prompt"] = user_prompt
            elif isinstance(payload.get("messages"), list):
                msgs = payload.get("messages") or []
                if msgs and isinstance(msgs, list):
                    for m in msgs:
                        if isinstance(m, dict) and str(m.get("role")) == "user":
                            m["content"] = user_prompt
                            break
                    else:
                        msgs.append({"role": "user", "content": user_prompt})
                    for m in msgs:
                        if isinstance(m, dict) and str(m.get("role")) == "system":
                            m["content"] = system_prompt
                            break
            if system_field:
                _walk_set(payload, system_field, system_prompt)

        raw_body = cfg.get("raw_body")
        if isinstance(raw_body, str) and raw_body.strip():
            rendered = _render_template_obj(raw_body, vars_map)
            return None, rendered

        return payload, None

    def _extract_text_from_json(self, data: Any, cfg: Dict[str, Any]) -> str:
        paths: List[str] = []
        if isinstance(cfg.get("response_text_paths"), list):
            paths.extend([str(x) for x in cfg.get("response_text_paths") if str(x).strip()])
        elif isinstance(cfg.get("response_text_path"), str):
            paths.append(str(cfg.get("response_text_path")))
        paths.extend([p for p in self.DEFAULT_RESPONSE_PATHS if p not in paths])

        for p in paths:
            v = _walk_get(data, p)
            if isinstance(v, str) and v.strip():
                return v.strip()
            if isinstance(v, list):
                parts = [str(x) for x in v if isinstance(x, (str, int, float))]
                if parts:
                    return "\n".join(parts)

        if isinstance(data, (dict, list)):
            return json.dumps(data, ensure_ascii=False, indent=2)
        return str(data)

    def _extract_sse_text(self, response_text: str) -> str:
        chunks: List[str] = []
        for line in (response_text or "").replace("\r\n", "\n").split("\n"):
            if not line.startswith("data:"):
                continue
            payload = line.split(":", 1)[1].strip()
            if not payload or payload == "[DONE]":
                continue
            parsed = _json_loads_maybe(payload)
            if parsed is None:
                chunks.append(payload)
                continue
            for p in [
                "choices.0.delta.content",
                "choices.0.message.content",
                "delta.text",
                "text",
                "content",
                "data.content",
            ]:
                v = _walk_get(parsed, p)
                if isinstance(v, str) and v:
                    chunks.append(v)
                    break
        if chunks:
            return "".join(chunks).strip()
        return (response_text or "").strip()

    def _maybe_bootstrap_session(self, cfg: Dict[str, Any], *, client: httpx.Client, headers: Dict[str, str]) -> None:
        bootstrap = cfg.get("bootstrap")
        if not isinstance(bootstrap, dict):
            return
        if not bool(bootstrap.get("enabled", False)):
            return
        path_params = cfg.get("path_params") if isinstance(cfg.get("path_params"), dict) else {}
        if isinstance(path_params, dict) and str(path_params.get("session_id") or "").strip():
            return

        b_method = str(bootstrap.get("method") or "POST").upper()
        b_path = str(bootstrap.get("path") or "").strip()
        if not b_path:
            return

        b_url = b_path if b_path.startswith(("http://", "https://")) else urljoin(self.base_url.rstrip("/") + "/", b_path.lstrip("/"))
        b_headers = dict(headers)
        if isinstance(bootstrap.get("headers"), dict):
            for k, v in (bootstrap.get("headers") or {}).items():
                if isinstance(k, str) and v is not None:
                    b_headers[k] = str(v)

        # Default: JSON bootstrap
        b_body = bootstrap.get("body_template")
        b_raw = bootstrap.get("raw_body")
        try:
            if isinstance(b_raw, str) and b_raw.strip():
                resp = client.request(b_method, b_url, headers=b_headers, content=b_raw.encode("utf-8"))
            elif isinstance(b_body, (dict, list)):
                resp = client.request(b_method, b_url, headers=b_headers, json=b_body)
            elif isinstance(b_body, str) and b_body.strip():
                parsed = _json_loads_maybe(b_body)
                if parsed is not None:
                    resp = client.request(b_method, b_url, headers=b_headers, json=parsed)
                else:
                    resp = client.request(b_method, b_url, headers=b_headers, content=b_body.encode("utf-8"))
            else:
                resp = client.request(b_method, b_url, headers=b_headers)
            resp.raise_for_status()
        except Exception:
            # bootstrap is best-effort; don't fail the whole run
            return

        sid = ""
        try:
            data = resp.json()
            extract = bootstrap.get("extract")
            if isinstance(extract, dict):
                for key, path in extract.items():
                    if str(key) == "session_id" and isinstance(path, str):
                        v = _walk_get(data, path)
                        if isinstance(v, str) and _UUID_RE.fullmatch(v.strip()):
                            sid = v.strip()
                            break
        except Exception:
            data = None

        if not sid:
            # fallback: regex uuid anywhere in response
            m = _UUID_RE.search(resp.text or "")
            if m:
                sid = m.group(0)

        if sid:
            cfg.setdefault("path_params", {})
            if isinstance(cfg["path_params"], dict):
                cfg["path_params"]["session_id"] = sid
            # persist into extra_headers so GUI/export keeps it
            self.extra_headers.setdefault("_http_connector", {})
            if isinstance(self.extra_headers.get("_http_connector"), dict):
                self.extra_headers["_http_connector"].setdefault("path_params", {})
                if isinstance(self.extra_headers["_http_connector"].get("path_params"), dict):
                    self.extra_headers["_http_connector"]["path_params"]["session_id"] = sid

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        cfg = self._cfg_http()
        method = str(cfg.get("method") or "POST").upper()
        url = self._build_url(cfg)
        payload, raw_body = self._request_payload(cfg, system_prompt, user_prompt)
        headers = self.build_headers({"Accept": "application/json, text/event-stream;q=0.9, */*;q=0.8"}, default_api_key_header=None)

        content_type = str(cfg.get("content_type") or "application/json").lower()
        if raw_body is not None:
            if "content-type" not in {k.lower() for k in headers}:
                headers["Content-Type"] = str(cfg.get("raw_content_type") or "application/json")
        elif content_type.startswith("application/json"):
            headers.setdefault("Content-Type", "application/json")
        elif content_type.startswith("application/x-www-form-urlencoded"):
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        verify_tls_cfg = cfg.get("verify_tls", None)
        if verify_tls_cfg is None:
            verify_tls = bool(self.httpx_verify())
        else:
            verify_tls = bool(verify_tls_cfg) and bool(self.httpx_verify())
        follow_redirects = bool(cfg.get("follow_redirects", False))
        stream = bool(cfg.get("stream", False))

        tls_cfg, proxy_cfg = extract_transport_cfg_from_headers(self.extra_headers)

        try:
            with build_httpx_client(
                timeout_sec=self.timeout_sec,
                verify_override=verify_tls,
                follow_redirects=follow_redirects,
                tls_cfg=tls_cfg,
                proxy_cfg=proxy_cfg,
            ) as client:
                # Optional internal session bootstrap (best-effort)
                self._maybe_bootstrap_session(cfg, client=client, headers=headers)
                # Rebuild URL after potential bootstrap updates
                url = self._build_url(cfg)

                if raw_body is not None:
                    resp = client.request(method, url, headers=headers, content=raw_body.encode("utf-8"))
                elif content_type.startswith("application/x-www-form-urlencoded"):
                    form_data = payload if isinstance(payload, dict) else {"payload": json.dumps(payload, ensure_ascii=False)}
                    resp = client.request(method, url, headers=headers, data=form_data)
                else:
                    resp = client.request(method, url, headers=headers, json=payload)

                # Provide better diagnostics on non-2xx
                try:
                    resp.raise_for_status()
                except httpx.HTTPStatusError as he:
                    body_preview = _truncate(resp.text)
                    raise ConnectorError(
                        f"Custom HTTP JSON request failed: HTTP {resp.status_code} for {url}\n"
                        f"Response preview:\n{body_preview}"
                    ) from he

                ctype = (resp.headers.get("content-type") or "").lower()
                if stream or "event-stream" in ctype:
                    return self._extract_sse_text(resp.text)

                if "json" in ctype or (resp.text or "").lstrip().startswith(("{", "[")):
                    try:
                        data = resp.json()
                        return self._extract_text_from_json(data, cfg)
                    except Exception:
                        return _truncate(resp.text)
                return (resp.text or "").strip()

        except ConnectorError:
            raise
        except Exception as e:
            raise ConnectorError(f"Custom HTTP JSON connector failed: {e}")
