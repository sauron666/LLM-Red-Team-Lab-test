from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class AuthObservation:
    check: str
    status: str  # pass / warn / fail / info
    detail: str
    evidence: Dict[str, Any]


def _b64url_decode(segment: str) -> bytes:
    segment = segment.strip().replace("-", "+").replace("_", "/")
    pad = "=" * ((4 - len(segment) % 4) % 4)
    return base64.b64decode(segment + pad)


def inspect_jwt_token(token: str) -> List[AuthObservation]:
    obs: List[AuthObservation] = []
    if not token:
        return obs
    parts = token.split(".")
    if len(parts) != 3:
        obs.append(AuthObservation(
            check="jwt.structure",
            status="warn",
            detail="Token is not JWT-shaped (not header.payload.signature).",
            evidence={"token_preview": token[:16] + "..."},
        ))
        return obs

    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", "replace"))
    except Exception as e:
        obs.append(AuthObservation("jwt.header_decode", "fail", "Failed to decode JWT header.", {"error": str(e)}))
        return obs

    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", "replace"))
    except Exception as e:
        payload = {}
        obs.append(AuthObservation("jwt.payload_decode", "warn", "Failed to decode JWT payload.", {"error": str(e)}))

    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        obs.append(AuthObservation("jwt.alg", "fail", "JWT header uses insecure or missing alg.", {"alg": header.get("alg")}))
    elif alg.startswith("hs") and payload.get("iss") and payload.get("aud"):
        obs.append(AuthObservation("jwt.alg", "info", "Symmetric JWT algorithm detected; validate key management and issuer trust.", {"alg": header.get("alg")}))
    else:
        obs.append(AuthObservation("jwt.alg", "pass", "JWT algorithm looks non-trivial.", {"alg": header.get("alg")}))

    if "exp" not in payload:
        obs.append(AuthObservation("jwt.exp", "warn", "JWT payload has no exp claim.", {"claims": sorted(payload.keys())}))
    else:
        try:
            exp = int(payload["exp"])
            now = int(time.time())
            if exp < now:
                obs.append(AuthObservation("jwt.exp", "warn", "JWT appears expired.", {"exp": exp, "now": now}))
            elif exp - now > 60 * 60 * 24 * 365:
                obs.append(AuthObservation("jwt.exp", "warn", "JWT expiry is unusually long (>365 days).", {"exp": exp, "ttl_sec": exp - now}))
            else:
                obs.append(AuthObservation("jwt.exp", "pass", "JWT expiry present.", {"exp": exp, "ttl_sec": exp - now}))
        except Exception:
            obs.append(AuthObservation("jwt.exp", "warn", "JWT exp claim is not an integer.", {"exp": payload.get("exp")}))

    for claim in ("aud", "iss", "sub"):
        if claim not in payload:
            obs.append(AuthObservation(f"jwt.claim.{claim}", "info", f"JWT missing optional claim '{claim}'.", {"claims": sorted(payload.keys())}))

    return obs


def _truncate(text: str, limit: int = 600) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def _safe_json(data: Any) -> Any:
    try:
        json.dumps(data)
        return data
    except Exception:
        return str(data)


def _http_headers_only(headers: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        if not isinstance(k, str):
            continue
        if k.startswith("_"):
            continue
        if v is None:
            continue
        out[k] = str(v)
    return out


def _target_auth_profile(target: Dict[str, Any]) -> Dict[str, Any]:
    extra = target.get("extra_headers") or {}
    return dict(extra.get("_auth") or {}) if isinstance(extra, dict) and isinstance(extra.get("_auth"), dict) else {}


def _strip_auth_from_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = dict(headers or {})
    for k in list(out.keys()):
        kl = k.lower()
        if kl in {"authorization", "x-api-key", "api-key", "cookie", "x-csrf-token", "x-xsrf-token", "csrf-token"} or "token" in kl and kl.startswith("x-"):
            out.pop(k, None)
    return out


def build_connector_probe(target: Dict[str, Any]) -> Dict[str, Any]:
    ctype = (target.get("connector_type") or "").lower()
    base_url = target.get("base_url")
    model = target.get("model") or "unknown"
    headers = _http_headers_only(dict(target.get("extra_headers") or {}))

    # Do not include auth/session headers by default in negative tests
    headers = _strip_auth_from_headers(headers)

    if ctype == "openai_compat":
        body = {"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 8}
        method = "POST"
    elif ctype == "gemini":
        # If base_url already contains :generateContent this will work. Otherwise user can override via CLI.
        body = {"contents": [{"parts": [{"text": "ping"}]}]}
        method = "POST"
    elif ctype == "ollama":
        body = {"model": model, "messages": [{"role": "user", "content": "ping"}], "stream": False}
        method = "POST"
    else:
        body = {"ping": "ping"}
        method = "POST"

    return {
        "method": method,
        "url": base_url,
        "headers": headers,
        "json_body": body,
    }


def run_http_auth_negative_tests(
    *,
    url: str,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout_sec: int = 15,
    auth_profile: Optional[Dict[str, Any]] = None,
    verify_tls: bool = True,
    tls_cfg: Optional[Dict[str, Any]] = None,
    proxy_cfg: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Safe negative tests:
    - no Authorization header
    - invalid bearer token
    - malformed bearer header
    - duplicate-ish suspicious header variants (non-destructive)
    """
    headers = _http_headers_only(dict(headers or {}))
    method = method.upper()
    auth_profile = dict(auth_profile or {})
    mode = str(auth_profile.get("mode") or "").lower()

    scenarios = []
    if mode in {"cookie", "session", "sso"}:
        cookie = str(auth_profile.get("cookie") or auth_profile.get("cookie_header") or "").strip()
        session_headers = {str(k): str(v) for k, v in (auth_profile.get("headers") or auth_profile.get("session_headers") or {}).items()} if isinstance((auth_profile.get("headers") or auth_profile.get("session_headers") or {}), dict) else {}
        # Base request intentionally omits auth cookies
        scenarios.append(("missing_cookie", {}))
        if cookie:
            scenarios.append(("invalid_cookie", {"Cookie": "LLM_ATTACK_LAB=invalid"}))
            # Cookie present but strip optional CSRF/session headers
            scenarios.append(("cookie_only_no_csrf", {"Cookie": cookie}))
            if session_headers:
                # Positive-ish control for comparison (still safe, same endpoint)
                hdr = {"Cookie": cookie}
                hdr.update(session_headers)
                scenarios.append(("session_cookie_with_csrf", hdr))
        else:
            scenarios.append(("cookie_placeholder", {"Cookie": "SESSION=placeholder"}))
    else:
        scenarios = [
            ("missing_auth", {}),
            ("invalid_bearer", {"Authorization": "Bearer INVALID.LLM.ATTACK.LAB"}),
            ("malformed_bearer", {"Authorization": "Bearer"}),
            ("wrong_scheme", {"Authorization": "Basic Zm9vOmJhcg=="}),
        ]

    out: Dict[str, Any] = {
        "target_url": url,
        "method": method,
        "results": [],
        "observations": [],
        "summary": {"suspicious": 0, "warnings": 0},
        "auth_profile": {k: ("***" if "token" in str(k).lower() else v) for k, v in auth_profile.items()} if auth_profile else {},
        "network_notes": proxy_notes(proxy_cfg),
    }

    with build_httpx_client(timeout_sec=timeout_sec, follow_redirects=False, verify_override=verify_tls, tls_cfg=tls_cfg, proxy_cfg=proxy_cfg) as client:
        for scenario_name, h in scenarios:
            req_headers = _strip_auth_from_headers(dict(headers))
            req_headers.update(h)
            try:
                resp = client.request(method, url, headers=req_headers, json=json_body)
                item = {
                    "scenario": scenario_name,
                    "status_code": resp.status_code,
                    "headers": {
                        "www-authenticate": resp.headers.get("www-authenticate"),
                        "server": resp.headers.get("server"),
                        "access-control-allow-origin": resp.headers.get("access-control-allow-origin"),
                        "access-control-allow-headers": resp.headers.get("access-control-allow-headers"),
                    },
                    "body_excerpt": _truncate(resp.text, 400),
                }
                out["results"].append(item)

                if resp.status_code < 300 and scenario_name in ("missing_auth", "invalid_bearer", "malformed_bearer", "missing_cookie", "invalid_cookie", "cookie_only_no_csrf"):
                    out["observations"].append(asdict(AuthObservation(
                        check=f"http.auth.{scenario_name}",
                        status="fail",
                        detail=f"Endpoint returned success ({resp.status_code}) for negative auth scenario '{scenario_name}'.",
                        evidence=item,
                    )))
                    out["summary"]["suspicious"] += 1
                elif resp.status_code >= 500 and scenario_name in ("malformed_bearer", "cookie_only_no_csrf"):
                    out["observations"].append(asdict(AuthObservation(
                        check="http.auth.malformed_bearer_handling",
                        status="warn",
                        detail=f"Server returned {resp.status_code} for malformed auth header (possible brittle auth parsing).",
                        evidence=item,
                    )))
                    out["summary"]["warnings"] += 1
                elif resp.status_code in (401, 403):
                    status = "pass"
                    detail = f"Negative auth scenario '{scenario_name}' correctly blocked ({resp.status_code})."
                    if resp.status_code == 401 and not resp.headers.get("www-authenticate"):
                        status = "info"
                        detail += " WWW-Authenticate header not present."
                    out["observations"].append(asdict(AuthObservation(
                        check=f"http.auth.{scenario_name}",
                        status=status,
                        detail=detail,
                        evidence={"status_code": resp.status_code, "www-authenticate": resp.headers.get("www-authenticate")},
                    )))
                else:
                    out["observations"].append(asdict(AuthObservation(
                        check=f"http.auth.{scenario_name}",
                        status="info",
                        detail=f"Received status {resp.status_code} for scenario '{scenario_name}'. Review manually.",
                        evidence={"status_code": resp.status_code},
                    )))
            except Exception as e:
                out["results"].append({"scenario": scenario_name, "error": str(e)})
                out["observations"].append(asdict(AuthObservation(
                    check=f"http.auth.{scenario_name}",
                    status="warn",
                    detail=f"Request failed during auth check: {e}",
                    evidence={"error": str(e)},
                )))
                out["summary"]["warnings"] += 1

    return _safe_json(out)


def run_target_auth_audit(target: Dict[str, Any], override_json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    probe = build_connector_probe(target)
    if override_json_body is not None:
        probe["json_body"] = override_json_body

    auth_profile = _target_auth_profile(target)
    tls_cfg = target.get("extra_headers", {}).get("_tls") if isinstance(target.get("extra_headers", {}), dict) else {}
    verify_tls = True
    if isinstance(tls_cfg, dict):
        if tls_cfg.get("insecure") is True:
            verify_tls = False
        elif "verify" in tls_cfg:
            verify_tls = bool(tls_cfg.get("verify"))
        elif "verify_tls" in tls_cfg:
            verify_tls = bool(tls_cfg.get("verify_tls"))
    result = run_http_auth_negative_tests(
        url=probe["url"],
        method=probe["method"],
        headers=probe["headers"],
        json_body=probe["json_body"],
        timeout_sec=int(target.get("timeout_sec", 15) or 15),
        auth_profile=auth_profile,
        verify_tls=verify_tls,
    )

    token = target.get("api_key") or ""
    jwt_obs = inspect_jwt_token(token) if isinstance(token, str) and token.count(".") == 2 else []
    result["jwt_token_observations"] = [asdict(x) for x in jwt_obs]
    result["connector_type"] = target.get("connector_type")
    result["model"] = target.get("model")
    return result


def run_cert_pinning_diagnostics(url: str, *, tls_cfg: Optional[Dict[str, Any]] = None, timeout_sec: int = 8) -> Dict[str, Any]:
    return run_cert_pinning_checks(url, tls_cfg=tls_cfg, timeout_sec=timeout_sec)
