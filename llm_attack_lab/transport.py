from __future__ import annotations

import os
import re
import ssl
import socket
import hashlib
from typing import Any, Dict, Optional
from urllib.parse import quote, urlparse

import httpx


TLS_PROFILES = {
    "enterprise": {"verify": True, "insecure": False, "trust_env": True},
    "strict": {"verify": True, "insecure": False, "trust_env": False},
    "insecure": {"verify": False, "insecure": True, "trust_env": False},
}


def normalize_tls_profile_name(value: str | None) -> str:
    v = str(value or "enterprise").strip().lower()
    if v in {"enterprise", "corp", "corporate"}:
        return "enterprise"
    if v in {"strict", "strict-verify"}:
        return "strict"
    if v in {"insecure", "ignore", "ignore_ssl", "unsafe"}:
        return "insecure"
    return "enterprise"


def tls_cfg_from_profile(profile: str | None = None, *, ca_bundle: str = "", pin_host: str = "", pin_sha256: str = "") -> Dict[str, Any]:
    p = normalize_tls_profile_name(profile)
    cfg = {"profile": p, **TLS_PROFILES[p]}
    if ca_bundle:
        cfg["ca_bundle"] = ca_bundle.strip()
    if pin_host:
        cfg["pin_host"] = pin_host.strip()
    if pin_sha256:
        cfg["pin_sha256"] = normalize_fingerprint(pin_sha256)
    return cfg


def normalize_tls_cfg(tls_cfg: Optional[Dict[str, Any]] = None, *, verify_override: Optional[bool] = None) -> Dict[str, Any]:
    raw = dict(tls_cfg or {})
    prof = normalize_tls_profile_name(raw.get("profile") or ("insecure" if raw.get("insecure") or raw.get("verify") is False else "enterprise"))
    cfg = tls_cfg_from_profile(prof, ca_bundle=str(raw.get("ca_bundle") or ""), pin_host=str(raw.get("pin_host") or ""), pin_sha256=str(raw.get("pin_sha256") or ""))
    if verify_override is not None:
        cfg["verify"] = bool(verify_override)
        cfg["insecure"] = not bool(verify_override)
    if raw.get("trust_env") is not None:
        cfg["trust_env"] = bool(raw.get("trust_env"))
    return cfg


def normalize_fingerprint(fp: str | None) -> str:
    s = re.sub(r"[^A-Fa-f0-9]", "", str(fp or "")).upper()
    return s


def fingerprint_hex_colon(fp_hex: str) -> str:
    s = normalize_fingerprint(fp_hex)
    return ":".join(s[i:i+2] for i in range(0, len(s), 2)) if s else ""


def httpx_verify_value(tls_cfg: Optional[Dict[str, Any]] = None, *, verify_override: Optional[bool] = None):
    cfg = normalize_tls_cfg(tls_cfg, verify_override=verify_override)
    if cfg.get("verify") is False:
        return False
    ca = str(cfg.get("ca_bundle") or "").strip()
    if ca:
        return ca
    return True


def _embed_basic_auth_in_proxy_url(proxy_url: str, username: str, password: str) -> str:
    if not proxy_url or "@" in proxy_url.split("://",1)[-1]:
        return proxy_url
    if not username:
        return proxy_url
    if "://" not in proxy_url:
        proxy_url = "http://" + proxy_url
    scheme, rest = proxy_url.split("://", 1)
    user = quote(username, safe="")
    pwd = quote(password or "", safe="")
    return f"{scheme}://{user}:{pwd}@{rest}"


def normalize_proxy_cfg(proxy_cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    raw = dict(proxy_cfg or {})
    mode = str(raw.get("mode") or "none").strip().lower()
    if mode not in {"none", "system", "basic", "custom_url", "ntlm", "cntlm"}:
        mode = "none"
    cfg: Dict[str, Any] = {"mode": mode}
    for k in ("url", "username", "password", "domain", "workstation", "bypass"):
        v = raw.get(k)
        if v is not None and str(v).strip() != "":
            cfg[k] = str(v)
    return cfg


def proxy_url_from_cfg(proxy_cfg: Optional[Dict[str, Any]] = None) -> str | None:
    cfg = normalize_proxy_cfg(proxy_cfg)
    mode = cfg.get("mode")
    if mode in {"none", None}:
        return None
    if mode == "system":
        return None
    url = str(cfg.get("url") or "").strip()
    if not url:
        return None
    if mode == "basic":
        return _embed_basic_auth_in_proxy_url(url, str(cfg.get("username") or ""), str(cfg.get("password") or ""))
    return url


def httpx_client_kwargs(*, timeout_sec: int = 30, follow_redirects: bool = False, tls_cfg: Optional[Dict[str, Any]] = None, proxy_cfg: Optional[Dict[str, Any]] = None, verify_override: Optional[bool] = None) -> Dict[str, Any]:
    tls = normalize_tls_cfg(tls_cfg, verify_override=verify_override)
    proxy = normalize_proxy_cfg(proxy_cfg)
    kwargs: Dict[str, Any] = {
        "timeout": timeout_sec,
        "follow_redirects": bool(follow_redirects),
        "verify": httpx_verify_value(tls),
        "trust_env": bool(tls.get("trust_env", False)),
    }
    purl = proxy_url_from_cfg(proxy)
    if purl:
        kwargs["proxy"] = purl
    if proxy.get("mode") == "system":
        kwargs["trust_env"] = True
    return kwargs


def build_httpx_client(*, timeout_sec: int = 30, follow_redirects: bool = False, tls_cfg: Optional[Dict[str, Any]] = None, proxy_cfg: Optional[Dict[str, Any]] = None, verify_override: Optional[bool] = None) -> httpx.Client:
    return httpx.Client(**httpx_client_kwargs(timeout_sec=timeout_sec, follow_redirects=follow_redirects, tls_cfg=tls_cfg, proxy_cfg=proxy_cfg, verify_override=verify_override))


def playwright_proxy_from_cfg(proxy_cfg: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, str]]:
    cfg = normalize_proxy_cfg(proxy_cfg)
    if cfg.get("mode") in {"none", "system"}:
        return None
    url = str(cfg.get("url") or "").strip()
    if not url:
        return None
    out: Dict[str, str] = {"server": url if "://" in url else f"http://{url}"}
    # For "basic" Playwright supports separate username/password.
    if cfg.get("mode") == "basic":
        if cfg.get("username"):
            out["username"] = str(cfg.get("username"))
        if cfg.get("password"):
            out["password"] = str(cfg.get("password"))
    # NTLM is not natively handled by Playwright proxy auth; users typically chain via CNTLM.
    if cfg.get("bypass"):
        out["bypass"] = str(cfg.get("bypass"))
    return out


def extract_transport_cfg_from_headers(extra_headers: Dict[str, Any] | None) -> tuple[Dict[str, Any], Dict[str, Any]]:
    raw = dict(extra_headers or {})
    tls = normalize_tls_cfg(raw.get("_tls") if isinstance(raw.get("_tls"), dict) else None)
    proxy = normalize_proxy_cfg(raw.get("_proxy") if isinstance(raw.get("_proxy"), dict) else None)
    return tls, proxy


def merge_transport_into_headers(extra_headers: Dict[str, Any] | None, *, tls_cfg: Optional[Dict[str, Any]] = None, proxy_cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = dict(extra_headers or {})
    if tls_cfg is not None:
        out["_tls"] = normalize_tls_cfg(tls_cfg)
    if proxy_cfg is not None:
        out["_proxy"] = normalize_proxy_cfg(proxy_cfg)
    return out


def proxy_notes(proxy_cfg: Optional[Dict[str, Any]] = None) -> list[str]:
    cfg = normalize_proxy_cfg(proxy_cfg)
    mode = cfg.get("mode")
    notes: list[str] = []
    if mode == "ntlm":
        notes.append("NTLM proxy mode selected: use a helper proxy (e.g., CNTLM) or system-integrated proxy URL for full NTLM proxy auth.")
    if mode in {"basic", "custom_url", "cntlm", "ntlm"} and cfg.get("url"):
        notes.append(f"Proxy configured: {cfg.get('url')}")
    if mode == "system":
        notes.append("Using system proxy settings (HTTP(S)_PROXY / OS env).")
    return notes


def _tcp_host_port_for_url(url: str) -> tuple[str, int]:
    pu = urlparse(url)
    host = pu.hostname or ""
    port = pu.port or (443 if (pu.scheme or "https").lower() == "https" else 80)
    if not host:
        raise ValueError("Invalid URL: missing host")
    return host, port


def fetch_server_cert_sha256(url: str, *, timeout_sec: int = 8, server_hostname: str | None = None) -> Dict[str, Any]:
    host, port = _tcp_host_port_for_url(url)
    sni = server_hostname or host
    ctx = ssl.create_default_context()
    # We want the cert even if the chain is private/self-signed.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout_sec) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("No peer certificate received")
            fp = hashlib.sha256(der).hexdigest().upper()
            return {
                "host": host,
                "port": port,
                "server_hostname": sni,
                "sha256_hex": fp,
                "sha256_colon": fingerprint_hex_colon(fp),
                "cipher": ssock.cipher(),
                "version": ssock.version(),
            }


def run_cert_pinning_checks(url: str, *, tls_cfg: Optional[Dict[str, Any]] = None, timeout_sec: int = 8) -> Dict[str, Any]:
    tls = normalize_tls_cfg(tls_cfg)
    cert = fetch_server_cert_sha256(url, timeout_sec=timeout_sec, server_hostname=(tls.get("pin_host") or None))
    expected = normalize_fingerprint(str(tls.get("pin_sha256") or ""))
    observed = normalize_fingerprint(cert.get("sha256_hex") or "")
    checks = []
    checks.append({"name": "tls_profile", "status": "ok", "detail": f"profile={tls.get('profile')} verify={tls.get('verify')}"})
    if tls.get("ca_bundle"):
        checks.append({"name": "ca_bundle", "status": "info", "detail": str(tls.get("ca_bundle"))})
    if expected:
        checks.append({
            "name": "cert_pin_match",
            "status": "pass" if observed == expected else "fail",
            "expected": fingerprint_hex_colon(expected),
            "observed": cert.get("sha256_colon"),
        })
    else:
        checks.append({"name": "cert_pin_match", "status": "info", "detail": "No pin configured (pin_host/pin_sha256 empty)."})
    return {
        "ok": True,
        "url": url,
        "tls": tls,
        "certificate": cert,
        "checks": checks,
        "pin_match": (observed == expected) if expected else None,
    }
