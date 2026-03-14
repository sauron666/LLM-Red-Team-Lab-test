from __future__ import annotations

import difflib
import json
import re
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

import httpx


@dataclass
class ParsedRawRequest:
    method: str
    path: str
    http_version: str
    headers: Dict[str, str]
    body: str
    host: str
    url: str


def parse_raw_http_request(raw_text: str, scheme: str = "https") -> ParsedRawRequest:
    raw_text = (raw_text or "").replace("\r\n", "\n")
    if "\n\n" in raw_text:
        header_part, body = raw_text.split("\n\n", 1)
    else:
        header_part, body = raw_text, ""

    lines = [ln for ln in header_part.split("\n") if ln.strip()]
    if not lines:
        raise ValueError("Empty raw HTTP request.")

    req_line = lines[0].strip()
    parts = req_line.split()
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {req_line}")
    method = parts[0].upper()
    path = parts[1]
    http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    host = headers.get("Host", "")
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        if not host:
            raise ValueError("Host header missing and path is not absolute URL.")
        url = f"{scheme}://{host}{path}"

    return ParsedRawRequest(method=method, path=path, http_version=http_version, headers=headers, body=body, host=host, url=url)


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in (headers or {}).items():
        kl = k.lower()
        if kl in ("authorization", "x-api-key", "api-key", "cookie", "set-cookie") or "token" in kl:
            out[k] = (v[:8] + "...") if isinstance(v, str) and len(v) > 8 else "***"
        else:
            out[k] = v
    return out


def _extract_auth_profile_from_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    auth: Dict[str, Any] = {}
    if not headers:
        return auth
    lower_map = {k.lower(): k for k in headers.keys()}

    # API key / bearer
    auth_h = headers.get(lower_map.get("authorization", ""), "") if lower_map.get("authorization") else headers.get("Authorization", "")
    if isinstance(auth_h, str) and auth_h.lower().startswith("bearer "):
        auth["mode"] = "bearer"
        auth["token"] = auth_h.split(" ", 1)[1].strip()
    else:
        for name in ("x-api-key", "api-key"):
            rk = lower_map.get(name)
            if rk and headers.get(rk):
                auth["mode"] = "api_key"
                auth["header_name"] = rk
                auth["token"] = str(headers.get(rk) or "")
                break

    # Cookie / session / SSO
    cookie_key = lower_map.get("cookie")
    cookie_val = str(headers.get(cookie_key) or "").strip() if cookie_key else ""
    sso_header_markers = (
        "csrf", "xsrf", "x-csrf", "x-xsrf",
        "x-auth-request", "x-ms-token", "x-amzn-oidc", "x-forwarded-access-token",
        "x-azure-ref", "x-client-cert",
    )
    session_headers: Dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in {"authorization", "x-api-key", "api-key", "cookie", "host", "content-length"}:
            continue
        if any(m in kl for m in sso_header_markers):
            session_headers[k] = v
    if cookie_val:
        # Cookie-based auth takes precedence for web/bff/router flows
        auth["mode"] = "sso" if session_headers else "session"
        auth["cookie"] = cookie_val
        if session_headers:
            auth["headers"] = session_headers
    elif session_headers and not auth:
        auth = {"mode": "sso", "headers": session_headers}

    return auth


def _root_and_path(parsed: ParsedRawRequest):
    p = urlparse(parsed.url)
    root = f"{p.scheme}://{p.netloc}"
    return p, root, p.path or "/"


def _infer_openai_base(path: str) -> str:
    marker = "/chat/completions"
    return path.split(marker, 1)[0] if marker in path else path.rstrip("/")

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _find_prompt_field_paths(obj: Any, prefix: str = "", depth: int = 0) -> List[str]:
    """Return candidate JSON dotted-paths that likely carry the user prompt.

    Heuristics are intentionally broad to support unknown internal/BFF chat routers.
    The list is sorted best-first.
    """
    scored: List[tuple[int, str]] = []

    exact_keys = {"message", "prompt", "input", "question", "query", "text", "content", "user_message", "usermessage"}
    key_tokens = ["message", "prompt", "input", "question", "query", "text", "content", "utterance", "instruction", "ask", "chat"]
    avoid_keys = {"id", "session", "sessionid", "conversation", "conversationid", "trace", "traceid", "requestid", "token", "apikey", "api_key", "key", "signature", "nonce", "timestamp"}

    def looks_like_base64(s: str) -> bool:
        t = (s or "").strip()
        if len(t) < 24:
            return False
        # rough check
        import re as _re
        if not _re.fullmatch(r"[A-Za-z0-9+/=_-]{24,}", t):
            return False
        # reject if mostly hex/uuid-like
        if _re.fullmatch(r"[0-9a-fA-F-]{24,}", t):
            return False
        return True

    def score_candidate(path: str, key: str, val: str) -> int:
        k = (key or "").lower()
        v = (val or "").strip()
        if not v:
            return -999
        s = 0
        if k in avoid_keys:
            s -= 10
        if k in exact_keys:
            s += 10
        if any(tok in k for tok in key_tokens):
            s += 6
        if any(tok in (path or "").lower() for tok in ["messages", "message", "prompt", "input", "content"]):
            s += 2
        # value shape
        if any(ch.isspace() for ch in v):
            s += 1
        if 10 <= len(v) <= 2500:
            s += 2
        elif 4 <= len(v) < 10:
            s += 1
        # punish likely IDs/tokens
        if UUID_RE.fullmatch(v) or v.count("-") >= 4:
            s -= 8
        if looks_like_base64(v):
            s -= 6
        return s

    def walk(x: Any, pref: str, d: int):
        if d > 6:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                kp = f"{pref}.{k}" if pref else str(k)
                if isinstance(v, str):
                    s = score_candidate(kp, str(k), v)
                    if s >= 2:
                        scored.append((s, kp))
                walk(v, kp, d + 1)
        elif isinstance(x, list):
            for i, v in enumerate(x[:8]):
                kp = f"{pref}.{i}" if pref else str(i)
                walk(v, kp, d + 1)

    walk(obj, prefix, depth)

    # Deduplicate while preserving best score
    best: Dict[str, int] = {}
    for s, pth in scored:
        best[pth] = max(best.get(pth, -999), s)

    ordered = sorted(best.items(), key=lambda t: (-t[1], t[0]))
    return [p for p, _ in ordered]


def _infer_http_connector_cfg(parsed: ParsedRawRequest, body_json: Dict[str, Any]) -> Dict[str, Any]:
    p = urlparse(parsed.url)
    path_q = p.path or "/"
    if p.query:
        path_q += f"?{p.query}"
    path_params: Dict[str, str] = {}
    session_id = None
    m = re.search(r"/session/([0-9a-fA-F-]{20,})/", p.path or "")
    if m:
        sid = m.group(1)
        session_id = sid
        path_q = path_q.replace(sid, "{session_id}")
        path_params["session_id"] = sid
    else:
        # Generic UUID replacement (single) to make replay reusable
        um = UUID_RE.search(path_q)
        if um:
            session_id = um.group(0)
            path_q = path_q.replace(session_id, "{session_id}", 1)
            path_params["session_id"] = session_id

    cfg: Dict[str, Any] = {
        "method": parsed.method,
        "path": path_q,
        "include_model": bool(body_json.get("model")),
        "stream": False,
        "response_text_paths": [
            "message", "response", "answer", "data.message", "data.response",
            "choices.0.message.content", "choices.0.delta.content", "content", "result", "reply"
        ],
    }
    if path_params:
        cfg["path_params"] = path_params
    # Preserve original body template so the custom connector can replay it reliably.
    if body_json:
        templ = json.loads(json.dumps(body_json))
        prompt_field = None
        system_field = None
        # OpenAI-like messages arrays
        msgs = body_json.get("messages") if isinstance(body_json, dict) else None
        if isinstance(msgs, list):
            for i, item in enumerate(msgs):
                if not isinstance(item, dict):
                    continue
                role = str(item.get("role") or "").lower()
                if role == "user" and isinstance(item.get("content"), str) and prompt_field is None:
                    prompt_field = f"messages.{i}.content"
                if role == "system" and isinstance(item.get("content"), str) and system_field is None:
                    system_field = f"messages.{i}.content"
            # replace content placeholders
            for i, item in enumerate(templ.get("messages", []) if isinstance(templ, dict) else []):
                if not isinstance(item, dict):
                    continue
                role = str(item.get("role") or "").lower()
                if role == "user":
                    item["content"] = "{{prompt}}"
                elif role == "system":
                    item["content"] = "{{system_prompt}}"
        # Non-messages prompt field
        if prompt_field is None:
            hits = _find_prompt_field_paths(body_json)
            preferred = [h for h in hits if h.split(".")[-1].lower() in {"message", "prompt", "input", "question", "query", "text", "user_message", "usermessage", "utterance", "instruction"}]
            prompt_field = (preferred or hits or [None])[0]
            if prompt_field and isinstance(templ, dict):
                # set placeholder into body template where possible
                cur = templ
                parts = prompt_field.split('.')
                try:
                    for part in parts[:-1]:
                        cur = cur[int(part)] if isinstance(cur, list) else cur.get(part)
                    last = parts[-1]
                    if isinstance(cur, list) and last.isdigit():
                        cur[int(last)] = "{{prompt}}"
                    elif isinstance(cur, dict):
                        cur[last] = "{{prompt}}"
                except Exception:
                    pass
        # System field outside messages
        for key in ("system", "system_prompt", "instructions"):
            if isinstance(body_json.get(key), str):
                system_field = key
                if isinstance(templ, dict):
                    templ[key] = "{{system_prompt}}"
                break
        if isinstance(templ, dict) and isinstance(templ.get("model"), str):
            templ["model"] = "{{model}}"
            cfg["model_field"] = "model"
        cfg["body_template"] = templ
        if prompt_field:
            cfg["prompt_field"] = prompt_field
        if system_field:
            cfg["system_field"] = system_field
    else:
        cfg["prompt_field"] = "message"
    return cfg



def _detect_connector_from_host_path(parsed: ParsedRawRequest, body_json: Dict[str, Any]) -> tuple[str, str, Dict[str, str]]:
    p, root, path = _root_and_path(parsed)
    host_l = (parsed.host or "").lower()
    q = parse_qs(p.query or "")
    headers_hint: Dict[str, str] = {}

    model = str(body_json.get("model") or "").strip()

    if "generativelanguage.googleapis.com" in host_l or ":generatecontent" in path.lower():
        model = model or "gemini-2.0-flash"
        return "gemini", root, headers_hint

    if path.endswith("/api/chat") or path.endswith("/api/generate") or "ollama" in host_l:
        model = model or "llama3.1"
        return "ollama", root, headers_hint

    if host_l.endswith(".openai.azure.com") and "/openai/deployments/" in path and "/chat/completions" in path:
        prefix = path.split("/chat/completions", 1)[0]
        dep = prefix.rsplit("/", 1)[-1] if "/" in prefix else ""
        model = model or dep or "YOUR-DEPLOYMENT"
        api_ver = (q.get("api-version") or [None])[0]
        if api_ver:
            headers_hint["x-azure-api-version"] = api_ver
        return "azure_openai", f"{root}{prefix}", headers_hint

    if "/v1/messages" in path and ("anthropic.com" in host_l or "claude" in host_l):
        # Anthropic Messages API doesn't require "model" in path
        model = model or "claude-3-5-sonnet-latest"
        return "anthropic", root, headers_hint

    if "/chat/completions" in path:
        # OpenAI-compatible family aliases by host
        base = f"{root}{_infer_openai_base(path)}"
        if "openrouter.ai" in host_l:
            return "openrouter", base, headers_hint
        if "api.groq.com" in host_l:
            return "groq", base, headers_hint
        if "api.mistral.ai" in host_l:
            return "mistral", base, headers_hint
        if "api.x.ai" in host_l:
            return "xai", base, headers_hint
        if "router.huggingface.co" in host_l:
            return "huggingface_router", base, headers_hint
        if "api.together.xyz" in host_l:
            return "together", base, headers_hint
        if "api.fireworks.ai" in host_l:
            return "fireworks", base, headers_hint
        if ("127.0.0.1:1234" in host_l) or ("localhost:1234" in host_l):
            return "lmstudio", base, headers_hint
        if ("127.0.0.1:8000" in host_l) or ("localhost:8000" in host_l):
            return "vllm", base, headers_hint
        if ("127.0.0.1:8080" in host_l) or ("localhost:8080" in host_l):
            return "llamacpp", base, headers_hint
        if ("127.0.0.1:5000" in host_l) or ("localhost:5000" in host_l):
            return "textgen_webui", base, headers_hint
        return "openai_compat", base, headers_hint

    # Custom/internal chat routers and BFF APIs (unknown provider behind them)
    path_l = path.lower()
    if any(tok in path_l for tok in ["/chat-router/", "/chat/", "/message", "/conversation", "/assistant"]) and parsed.method in {"POST", "PUT"}:
        if "/chat-router/" in path_l and "/session/" in path_l and "/message" in path_l:
            return "internal_chat_router", root, headers_hint
        if isinstance(body_json, dict) and body_json:
            return "custom_http_json", root, headers_hint
    # Fallback generic
    return "openai_compat", root, headers_hint


def infer_target_from_parsed_request(parsed: ParsedRawRequest) -> Dict[str, Any]:
    try:
        body_json = json.loads(parsed.body) if (parsed.body or "").strip() else {}
        if not isinstance(body_json, dict):
            body_json = {}
    except Exception:
        body_json = {}

    connector_type, base_url, inferred_headers = _detect_connector_from_host_path(parsed, body_json)
    model = str(body_json.get("model") or "").strip() or ("chat-router" if connector_type == "internal_chat_router" else "custom-chat" if connector_type == "custom_http_json" else "unknown-model")

    if connector_type == "anthropic" and not model:
        model = "claude-3-5-sonnet-latest"

    auth_profile = _extract_auth_profile_from_headers(parsed.headers)
    api_key = ""
    if str(auth_profile.get("mode") or "") in {"bearer", "api_key"}:
        api_key = str(auth_profile.get("token") or "")

    auth_passthrough_keys = {"host", "content-length", "authorization", "x-api-key", "api-key", "cookie"}
    for hk in (auth_profile.get("headers") or {}).keys() if isinstance(auth_profile.get("headers"), dict) else []:
        auth_passthrough_keys.add(str(hk).lower())

    passthrough_headers = {
        k: v for k, v in parsed.headers.items()
        if k.lower() not in auth_passthrough_keys
    }
    passthrough_headers.update(inferred_headers)
    if connector_type in {"custom_http_json", "internal_chat_router"}:
        try:
            passthrough_headers["_http_connector"] = _infer_http_connector_cfg(parsed, body_json)
        except Exception:
            pass
    if auth_profile:
        passthrough_headers["_auth"] = auth_profile
    passthrough_headers.setdefault("_lab", {"capture_mode": "manual", "onboarded_from": "burp"})

    p = urlparse(parsed.url)
    return {
        "name": f"Imported from Burp - {p.netloc}",
        "connector_type": connector_type,
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
        "extra_headers": passthrough_headers,
        "timeout_sec": 30,
        "raw_summary": {
            "method": parsed.method,
            "path": parsed.path,
            "headers": _redact_headers(parsed.headers),
            "body_preview": (parsed.body or "")[:500],
        },
    }


def parse_sse_events(text: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not text:
        return events
    blocks = text.replace("\r\n", "\n").split("\n\n")
    for block in blocks:
        if "data:" not in block:
            continue
        ev: Dict[str, Any] = {"raw": block}
        data_lines = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                ev["event"] = line.split(":", 1)[1].strip()
            elif line.startswith("id:"):
                ev["id"] = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].lstrip())
        if data_lines:
            data_text = "\n".join(data_lines)
            ev["data"] = data_text
            try:
                ev["data_json"] = json.loads(data_text)
            except Exception:
                pass
        events.append(ev)
    return events


def detect_stream_or_ws_payload(payload_text: str, content_type: str | None = None) -> Dict[str, Any]:
    content_type = (content_type or "").lower()
    text = payload_text or ""
    meta: Dict[str, Any] = {"kind": "http", "content_type": content_type}
    if "event-stream" in content_type or "\ndata:" in text or text.startswith("data:"):
        events = parse_sse_events(text)
        meta.update({"kind": "sse", "event_count": len(events), "events_preview": events[:25]})
        return meta
    # Very lightweight WS transcript detection (newline-delimited JSON or [WS] prefixes)
    lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if ln.strip()]
    ws_lines = [ln for ln in lines if ln.startswith("[WS]") or ln.startswith("{") or ln.startswith("<-") or ln.startswith("->")]
    if ws_lines and len(ws_lines) >= max(2, len(lines)//2):
        meta.update({"kind": "websocket", "frame_count": len(ws_lines), "frames_preview": ws_lines[:100]})
    return meta


def replay_parsed_request(parsed: ParsedRawRequest, *, allow_auth: bool = False, timeout_sec: int = 20, include_full_body: bool = False, verify_tls: bool = True, tls_cfg: dict | None = None, proxy_cfg: dict | None = None) -> Dict[str, Any]:
    headers = dict(parsed.headers)
    headers.pop("Host", None)
    if not allow_auth:
        for k in ["Authorization", "X-Api-Key", "x-api-key", "api-key", "Cookie", "cookie", "X-CSRF-Token", "x-csrf-token", "X-XSRF-TOKEN", "x-xsrf-token", "csrf-token"]:
            headers.pop(k, None)

    body = parsed.body.encode("utf-8") if parsed.body else None
    try:
        with build_httpx_client(timeout_sec=timeout_sec, follow_redirects=False, verify_override=verify_tls, tls_cfg=tls_cfg, proxy_cfg=proxy_cfg) as client:
            resp = client.request(parsed.method, parsed.url, headers=headers, content=body)
        text_body = resp.text
        stream_meta = detect_stream_or_ws_payload(text_body, resp.headers.get("content-type"))
        out = {
            "ok": True,
            "request": {
                "method": parsed.method,
                "url": parsed.url,
                "headers": _redact_headers(parsed.headers) if not allow_auth else parsed.headers,
                "body_preview": (parsed.body or "")[:1000],
            },
            "response": {
                "status_code": resp.status_code,
                "headers": {
                    "content-type": resp.headers.get("content-type"),
                    "server": resp.headers.get("server"),
                    "www-authenticate": resp.headers.get("www-authenticate"),
                },
                "body_preview": text_body[:2000],
                "stream_meta": stream_meta,
            },
        }
        if include_full_body:
            out["response"]["body_full"] = text_body
        return out
    except Exception as e:
        return {"ok": False, "request": {"method": parsed.method, "url": parsed.url}, "error": str(e)}


def unified_text_diff(a: str, b: str, from_name: str = "baseline", to_name: str = "attacked") -> str:
    a_lines = (a or "").splitlines()
    b_lines = (b or "").splitlines()
    return "\n".join(difflib.unified_diff(a_lines, b_lines, fromfile=from_name, tofile=to_name, lineterm=""))


def _load_json_loose(text: str):
    if not (text or "").strip():
        return None
    t = text.strip()
    try:
        return json.loads(t)
    except Exception:
        # try extracting the first JSON object/array
        for start, end in [("{", "}"), ("[", "]")]:
            si = t.find(start)
            ei = t.rfind(end)
            if si != -1 and ei != -1 and ei > si:
                try:
                    return json.loads(t[si:ei+1])
                except Exception:
                    continue
    return None


def _semantic_json_changes(a, b, path: str = "$", out: list | None = None):
    if out is None:
        out = []
    if type(a) != type(b):
        out.append({"path": path, "type": "type_change", "from_type": type(a).__name__, "to_type": type(b).__name__, "from": a, "to": b})
        return out
    if isinstance(a, dict):
        a_keys = set(a.keys())
        b_keys = set(b.keys())
        for k in sorted(a_keys - b_keys):
            out.append({"path": f"{path}.{k}", "type": "removed", "from": a[k]})
        for k in sorted(b_keys - a_keys):
            out.append({"path": f"{path}.{k}", "type": "added", "to": b[k]})
        for k in sorted(a_keys & b_keys):
            _semantic_json_changes(a[k], b[k], f"{path}.{k}", out)
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            out.append({"path": path, "type": "list_length", "from_len": len(a), "to_len": len(b)})
        lim = min(len(a), len(b))
        for i in range(lim):
            _semantic_json_changes(a[i], b[i], f"{path}[{i}]", out)
        for i in range(lim, len(a)):
            out.append({"path": f"{path}[{i}]", "type": "removed", "from": a[i]})
        for i in range(lim, len(b)):
            out.append({"path": f"{path}[{i}]", "type": "added", "to": b[i]})
        return out
    if a != b:
        out.append({"path": path, "type": "changed", "from": a, "to": b})
    return out


def semantic_json_diff(a_text: str, b_text: str) -> dict:
    a_obj = _load_json_loose(a_text)
    b_obj = _load_json_loose(b_text)
    if a_obj is None or b_obj is None:
        return {"is_json": False, "reason": "One or both response bodies are not valid JSON."}
    changes = _semantic_json_changes(a_obj, b_obj)
    summary = {
        "added": sum(1 for c in changes if c["type"] == "added"),
        "removed": sum(1 for c in changes if c["type"] == "removed"),
        "changed": sum(1 for c in changes if c["type"] in {"changed","type_change","list_length"}),
        "total": len(changes),
    }
    pretty_lines = [f"Semantic JSON diff: {summary['total']} changes (added={summary['added']}, removed={summary['removed']}, changed={summary['changed']})", ""]
    for c in changes[:500]:
        ctype = c.get("type")
        path = c.get("path")
        if ctype == "added":
            pretty_lines.append(f"+ {path} = {json.dumps(c.get('to'), ensure_ascii=False)}")
        elif ctype == "removed":
            pretty_lines.append(f"- {path} = {json.dumps(c.get('from'), ensure_ascii=False)}")
        elif ctype == "changed":
            pretty_lines.append(f"~ {path}: {json.dumps(c.get('from'), ensure_ascii=False)} -> {json.dumps(c.get('to'), ensure_ascii=False)}")
        elif ctype == "type_change":
            pretty_lines.append(f"~ {path}: type {c.get('from_type')} -> {c.get('to_type')}")
        elif ctype == "list_length":
            pretty_lines.append(f"~ {path}: list length {c.get('from_len')} -> {c.get('to_len')}")
    return {
        "is_json": True,
        "summary": summary,
        "changes": changes,
        "baseline_pretty": json.dumps(a_obj, ensure_ascii=False, indent=2, sort_keys=True),
        "attacked_pretty": json.dumps(b_obj, ensure_ascii=False, indent=2, sort_keys=True),
        "pretty": "\n".join(pretty_lines),
    }


def replay_diff_requests(
    baseline: ParsedRawRequest,
    attacked: ParsedRawRequest,
    *,
    allow_auth: bool = False,
    timeout_sec: int = 20,
    verify_tls: bool = True,
    tls_cfg: dict | None = None,
    proxy_cfg: dict | None = None,
) -> Dict[str, Any]:
    b = replay_parsed_request(baseline, allow_auth=allow_auth, timeout_sec=timeout_sec, include_full_body=True, verify_tls=verify_tls, tls_cfg=tls_cfg, proxy_cfg=proxy_cfg)
    a = replay_parsed_request(attacked, allow_auth=allow_auth, timeout_sec=timeout_sec, include_full_body=True, verify_tls=verify_tls, tls_cfg=tls_cfg, proxy_cfg=proxy_cfg)
    if not b.get("ok") or not a.get("ok"):
        return {"ok": False, "baseline": b, "attacked": a, "error": "Replay failed for one or both requests."}
    b_body = (((b.get("response") or {}).get("body_full")) or "")
    a_body = (((a.get("response") or {}).get("body_full")) or "")
    json_sem = semantic_json_diff(b_body, a_body)
    return {
        "ok": True,
        "baseline": b,
        "attacked": a,
        "diff": unified_text_diff(b_body, a_body),
        "json_semantic_diff": json_sem,
        "json_diff_pretty": (json_sem.get("pretty") if isinstance(json_sem, dict) else ""),
        "same_status": (b["response"]["status_code"] == a["response"]["status_code"]),
    }


class _IngestHandler(BaseHTTPRequestHandler):
    out_dir: Path = Path("burp_ingest")
    lock = threading.Lock()

    def _json(self, code: int, payload: Dict[str, Any]):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @classmethod
    def _next_file(cls, suffix: str = ".json") -> Path:
        cls.out_dir.mkdir(parents=True, exist_ok=True)
        with cls.lock:
            idx = len(list(cls.out_dir.glob(f"*{suffix}"))) + 1
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            return cls.out_dir / f"burp_capture_{idx:04d}_{ts}{suffix}"

    def do_POST(self):  # noqa: N802
        try:
            path = self.path.rstrip("/")
            if path not in {"/ingest", "/ingest_stream", "/ingest_ws"}:
                return self._json(404, {"error": "Use POST /ingest, /ingest_stream, or /ingest_ws"})

            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            data = json.loads(raw or "{}")

            if path == "/ingest_ws":
                frames = data.get("frames") or data.get("messages") or []
                if isinstance(frames, str):
                    frames = [ln for ln in frames.splitlines() if ln.strip()]
                payload = {
                    "source": "burp_bridge_ws",
                    "note": data.get("note", ""),
                    "target_url": data.get("target_url", ""),
                    "frames": frames,
                    "stream_meta": {"kind": "websocket", "frame_count": len(frames), "frames_preview": frames[:100]},
                }
                out_file = self._next_file()
                out_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                return self._json(200, {"saved": str(out_file), "frame_count": len(frames)})

            raw_req = data.get("raw_request") or data.get("request") or ""
            if not raw_req:
                return self._json(400, {"error": "Missing raw_request field"})
            scheme = data.get("scheme", "https")
            parsed = parse_raw_http_request(raw_req, scheme=scheme)
            inferred = infer_target_from_parsed_request(parsed)

            saved_payload = {
                "source": "burp_bridge_ingest" if path == "/ingest" else "burp_bridge_stream",
                "note": data.get("note", ""),
                "parsed": asdict(parsed),
                "inferred_target": inferred,
            }

            # optional raw response / streaming transcript
            raw_resp = data.get("raw_response") or data.get("response") or data.get("response_text") or ""
            content_type = data.get("response_content_type") or data.get("content_type") or ""
            if raw_resp:
                saved_payload["captured_response_preview"] = str(raw_resp)[:4000]
                saved_payload["stream_meta"] = detect_stream_or_ws_payload(str(raw_resp), str(content_type))

            out_file = self._next_file()
            out_file.write_text(json.dumps(saved_payload, ensure_ascii=False, indent=2), encoding="utf-8")
            return self._json(200, {"saved": str(out_file), "inferred_target": inferred, "stream_meta": saved_payload.get("stream_meta")})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/") == "/health":
            return self._json(200, {"status": "ok"})
        return self._json(404, {"error": "Not found"})

    def log_message(self, fmt: str, *args):
        return


class BurpIngestServerHandle:
    def __init__(self, bind_host: str = "127.0.0.1", port: int = 8765, out_dir: str = "burp_ingest"):
        self.bind_host = bind_host
        self.port = int(port)
        self.out_dir = out_dir
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        _IngestHandler.out_dir = Path(self.out_dir)
        self._server = ThreadingHTTPServer((self.bind_host, self.port), _IngestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="burp_ingest_bridge")
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:
                pass
            try:
                self._server.server_close()
            except Exception:
                pass
        self._server = None
        self._thread = None


def run_burp_ingest_server(bind_host: str = "127.0.0.1", port: int = 8765, out_dir: str = "burp_ingest"):
    handle = BurpIngestServerHandle(bind_host=bind_host, port=port, out_dir=out_dir)
    handle.start()
    try:
        while handle.running:
            threading.Event().wait(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        handle.stop()
