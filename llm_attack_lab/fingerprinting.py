from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .burp_bridge import ParsedRawRequest, infer_target_from_parsed_request


def _looks_uuid(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", s or ""))


def _safe_json_loads(body: str | None) -> Any:
    if not (body or "").strip():
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def fingerprint_endpoint(
    url: str,
    *,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    body: str | None = None,
) -> Dict[str, Any]:
    """Offline fingerprinting of an endpoint for connector onboarding.

    This does not send traffic; it infers connector/auth/body hints from URL + headers/body.
    """
    p = urlparse(url)
    parsed = ParsedRawRequest(
        method=(method or "POST").upper(),
        path=(p.path + (("?" + p.query) if p.query else "")) or "/",
        http_version="HTTP/1.1",
        headers=headers or {"Host": p.netloc},
        body=body or "",
        host=p.netloc,
        url=url,
    )
    target = infer_target_from_parsed_request(parsed)
    body_json = _safe_json_loads(body)

    path_parts = [x for x in (p.path or "").split("/") if x]
    session_uuid = next((x for x in path_parts if _looks_uuid(x)), None)
    auth_headers = [k for k in (headers or {}).keys() if k.lower() in {"authorization", "cookie", "x-api-key", "api-key", "x-csrf-token", "x-xsrf-token"} or "csrf" in k.lower()]
    has_cookie = any(k.lower() == "cookie" for k in (headers or {}).keys())
    has_authz = any(k.lower() == "authorization" for k in (headers or {}).keys())

    notes = []
    if target.get("connector_type") in {"custom_http_json", "internal_chat_router"}:
        notes.append("Unknown/custom chat API detected; use Custom HTTP JSON connector with captured body template.")
    if "/chat-router/" in (p.path or "").lower():
        notes.append("Looks like BFF/chat-router path. Capture a single authenticated request in Burp and import it for exact body schema.")
    if has_cookie:
        notes.append("Cookie/session auth detected. Configure extra_headers._auth.mode='session' or 'sso'.")
    if has_authz and not has_cookie:
        notes.append("Authorization header detected. Configure _auth.mode='bearer' or API key mode.")
    if body_json is None and body:
        notes.append("Request body is not JSON. You can still use Custom HTTP JSON connector with raw_body template.")

    http_cfg = ((target.get("extra_headers") or {}).get("_http_connector") if isinstance(target.get("extra_headers"), dict) else None) or {}
    prompt_field = http_cfg.get("prompt_field") if isinstance(http_cfg, dict) else None

    return {
        "url": url,
        "method": parsed.method,
        "connector_suggestion": target.get("connector_type"),
        "base_url": target.get("base_url"),
        "model_hint": target.get("model"),
        "session_uuid_detected": session_uuid,
        "auth_headers_detected": auth_headers,
        "prompt_field_guess": prompt_field,
        "target_template": target,
        "notes": notes,
    }


def guess_model_from_raw_http_response(raw_response: str) -> Dict[str, Any]:
    """Best-effort extraction of provider/model hints from a raw HTTP response (headers + body).

    Works well for OpenAI-compatible / Azure / Anthropic-style JSON responses and many internal routers
    that include a 'model' field somewhere in the JSON.
    """
    raw = (raw_response or "").replace("\r\n", "\n")
    parts = raw.split("\n\n", 1)
    head = parts[0] if parts else ""
    body = parts[1] if len(parts) > 1 else raw

    headers: Dict[str, str] = {}
    for line in head.split("\n")[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()

    info: Dict[str, Any] = {"ok": True, "model": None, "provider": None, "signals": []}
    ct = headers.get("content-type", "")
    if ct:
        info["signals"].append(f"content-type={ct}")

    # Try JSON parse
    body_str = (body or "").strip()
    obj = None
    if body_str.startswith("{") or body_str.startswith("["):
        try:
            obj = json.loads(body_str)
        except Exception:
            obj = None

    def find_model(o: Any) -> str | None:
        if isinstance(o, dict):
            if isinstance(o.get("model"), str) and o.get("model"):
                return o.get("model")
            # common nested patterns
            for k in ["data", "result", "meta", "response"]:
                v = o.get(k)
                m = find_model(v)
                if m:
                    return m
            # search shallow keys
            for k, v in o.items():
                if isinstance(v, (dict, list)):
                    m = find_model(v)
                    if m:
                        return m
        elif isinstance(o, list):
            for it in o[:6]:
                m = find_model(it)
                if m:
                    return m
        return None

    model = find_model(obj) if obj is not None else None
    if model:
        info["model"] = model
        info["signals"].append("model_field_found")

    # Provider hints from headers/body
    server = headers.get("server", "")
    if server:
        info["signals"].append(f"server={server}")
    www = headers.get("www-authenticate", "")
    if www:
        info["signals"].append("www-authenticate")

    lower = (body_str[:8000] or "").lower()
    if "anthropic" in lower or "claude" in lower:
        info["provider"] = info["provider"] or "anthropic"
    if "openai" in lower or "gpt-" in lower:
        info["provider"] = info["provider"] or "openai_compat"
    if "azure" in lower and "openai" in lower:
        info["provider"] = "azure_openai"

    # Header-based hints
    for hk in headers.keys():
        if "anthropic" in hk:
            info["provider"] = info["provider"] or "anthropic"
        if hk.startswith("x-openai") or "openai" in hk:
            info["provider"] = info["provider"] or "openai_compat"

    return info
