from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse


def _b64maybe(text: str, flag: str | None) -> str:
    if text is None:
        return ""
    if str(flag or "").lower() in {"true", "1", "yes"}:
        try:
            return base64.b64decode(text.encode("utf-8"), validate=False).decode("utf-8", "replace")
        except Exception:
            return text
    return text


def _headers_to_raw(headers: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for h in headers or []:
        k = h.get("name")
        v = h.get("value", "")
        if k:
            out.append(f"{k}: {v}")
    return out


def _har_entry_to_raw(entry: Dict[str, Any]) -> Dict[str, Any]:
    req = entry.get("request") or {}
    resp = entry.get("response") or {}
    method = (req.get("method") or "GET").upper()
    url = req.get("url") or ""
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query

    req_lines = [f"{method} {path} HTTP/1.1"]
    req_headers = list(req.get("headers") or [])
    host = p.netloc
    if host and not any((h.get("name", "").lower() == "host") for h in req_headers):
        req_lines.append(f"Host: {host}")
    req_lines.extend(_headers_to_raw(req_headers))
    body_text = (((req.get("postData") or {}).get("text")) or "")
    req_lines.append("")
    req_lines.append(body_text)
    raw_request = "\n".join(req_lines)

    status = resp.get("status", 0)
    status_text = resp.get("statusText") or ""
    resp_lines = [f"HTTP/1.1 {status} {status_text}".rstrip()]
    resp_lines.extend(_headers_to_raw(list(resp.get("headers") or [])))
    resp_lines.append("")
    content = resp.get("content") or {}
    resp_body = content.get("text") or ""
    if content.get("encoding") == "base64":
        try:
            resp_body = base64.b64decode(resp_body.encode("utf-8"), validate=False).decode("utf-8", "replace")
        except Exception:
            pass
    resp_lines.append(resp_body)
    raw_response = "\n".join(resp_lines)

    ctype = ""
    for h in (resp.get("headers") or []):
        if h.get("name", "").lower() == "content-type":
            ctype = h.get("value", "")
            break

    return {
        "source": "burp_har_import",
        "url": url,
        "raw_request": raw_request,
        "raw_response": raw_response,
        "response_content_type": ctype,
    }


def parse_burp_export(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    suffix = p.suffix.lower()
    text = p.read_text(encoding="utf-8", errors="ignore")
    out: List[Dict[str, Any]] = []

    if suffix in {".xml", ".burp"}:
        root = ET.fromstring(text)
        for item in root.findall(".//item"):
            req_el = item.find("request")
            resp_el = item.find("response")
            url_el = item.find("url")
            cmt_el = item.find("comment")

            raw_req = _b64maybe(req_el.text if req_el is not None else "", req_el.attrib.get("base64") if req_el is not None else None)
            raw_resp = _b64maybe(resp_el.text if resp_el is not None else "", resp_el.attrib.get("base64") if resp_el is not None else None)

            ctype = ""
            for line in raw_resp.replace("\r\n", "\n").split("\n"):
                if line.lower().startswith("content-type:"):
                    ctype = line.split(":", 1)[1].strip()
                    break
                if line.strip() == "":
                    break

            if raw_req.strip():
                out.append(
                    {
                        "source": "burp_xml_import",
                        "url": (url_el.text.strip() if url_el is not None and url_el.text else ""),
                        "note": (cmt_el.text.strip() if cmt_el is not None and cmt_el.text else ""),
                        "raw_request": raw_req,
                        "raw_response": raw_resp,
                        "response_content_type": ctype,
                    }
                )
        return out

    if suffix == ".har":
        obj = json.loads(text)
        entries = (((obj.get("log") or {}).get("entries")) or [])
        for e in entries:
            try:
                out.append(_har_entry_to_raw(e))
            except Exception:
                continue
        return out

    obj = json.loads(text)
    candidates: List[Dict[str, Any]] = []
    if isinstance(obj, list):
        candidates = [x for x in obj if isinstance(x, dict)]
    elif isinstance(obj, dict):
        if isinstance(obj.get("items"), list):
            candidates = [x for x in obj["items"] if isinstance(x, dict)]
        elif isinstance(obj.get("entries"), list):
            candidates = [x for x in obj["entries"] if isinstance(x, dict)]
        elif any(k in obj for k in ("raw_request", "request", "parsed")):
            candidates = [obj]
        elif isinstance((obj.get("log") or {}).get("entries"), list):
            for e in obj["log"]["entries"]:
                try:
                    out.append(_har_entry_to_raw(e))
                except Exception:
                    continue
            return out

    for it in candidates:
        if (it.get("parsed") or {}).get("method"):
            parsed = it.get("parsed") or {}
            req_lines = [f"{parsed.get('method', 'POST')} {parsed.get('path', '/')} {parsed.get('http_version', 'HTTP/1.1')}"]
            for k, v in (parsed.get("headers") or {}).items():
                req_lines.append(f"{k}: {v}")
            req_lines.append("")
            req_lines.append(parsed.get("body", ""))
            raw_req = "\n".join(req_lines)
            out.append(
                {
                    "source": "bridge_capture_json",
                    "url": parsed.get("url", ""),
                    "note": it.get("note", ""),
                    "raw_request": raw_req,
                    "raw_response": it.get("raw_response") or it.get("captured_response_preview") or "",
                    "response_content_type": ((it.get("stream_meta") or {}).get("content_type")) or "",
                }
            )
            continue

        raw_req = it.get("raw_request") or it.get("request") or it.get("request_raw") or ""
        raw_resp = it.get("raw_response") or it.get("response") or it.get("response_text") or ""
        ctype = it.get("response_content_type") or it.get("content_type") or ""

        if isinstance(raw_req, dict):
            req = raw_req
            method = (req.get("method") or "POST").upper()
            url = req.get("url") or ""
            pu = urlparse(url)
            path = pu.path or "/"
            if pu.query:
                path += "?" + pu.query
            lines = [f"{method} {path} HTTP/1.1"]
            if pu.netloc:
                lines.append(f"Host: {pu.netloc}")
            hdrs = req.get("headers") or {}
            if isinstance(hdrs, dict):
                for k, v in hdrs.items():
                    lines.append(f"{k}: {v}")
            elif isinstance(hdrs, list):
                lines.extend(_headers_to_raw(hdrs))
            body = req.get("body") or req.get("content") or ""
            lines.extend(["", str(body)])
            raw_req = "\n".join(lines)

        if raw_req:
            out.append(
                {
                    "source": "json_import",
                    "url": it.get("url", ""),
                    "note": it.get("note", ""),
                    "raw_request": str(raw_req),
                    "raw_response": str(raw_resp),
                    "response_content_type": str(ctype),
                }
            )

    return out
