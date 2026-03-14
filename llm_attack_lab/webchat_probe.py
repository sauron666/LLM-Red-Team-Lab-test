from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse

from .transport import playwright_proxy_from_cfg


def probe_webchat_page(url: str, *, headless: bool = True, cookie_header: str = "", timeout_sec: int = 20, ignore_https_errors: bool = False, proxy_cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Probe a web chat UI and suggest selectors for the Playwright connector.

    Requires playwright + browser install. Only collects DOM metadata and candidate selectors.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as e:
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install") from e

    host = urlparse(url).hostname or "localhost"

    def parse_cookies(header: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for part in (header or "").split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            n, v = part.split("=", 1)
            out.append({"name": n.strip(), "value": v.strip(), "domain": host, "path": "/"})
        return out

    js = r"""
    () => {
      const q = (sel) => Array.from(document.querySelectorAll(sel));
      const visible = (el) => {
        const r = el.getBoundingClientRect();
        const st = window.getComputedStyle(el);
        return r.width > 1 && r.height > 1 && st.visibility !== 'hidden' && st.display !== 'none';
      };
      const cssPath = (el) => {
        if (!el || !el.tagName) return '';
        const parts = [];
        let cur = el;
        let depth = 0;
        while (cur && cur.nodeType === 1 && depth < 4) {
          let p = cur.tagName.toLowerCase();
          if (cur.id) { p += '#' + cur.id; parts.unshift(p); break; }
          if (cur.classList && cur.classList.length) p += '.' + Array.from(cur.classList).slice(0,2).join('.');
          const same = cur.parentElement ? Array.from(cur.parentElement.children).filter(x => x.tagName === cur.tagName) : [];
          if (same.length > 1 && cur.parentElement) p += `:nth-of-type(${same.indexOf(cur)+1})`;
          parts.unshift(p);
          cur = cur.parentElement;
          depth += 1;
        }
        return parts.join(' > ');
      };

      const textareas = q('textarea, [contenteditable="true"], input[type="text"], input:not([type])')
        .filter(visible)
        .slice(0, 20)
        .map(el => ({
          tag: el.tagName.toLowerCase(),
          placeholder: el.getAttribute('placeholder') || '',
          ariaLabel: el.getAttribute('aria-label') || '',
          selector: cssPath(el)
        }));

      const buttons = q('button, [role="button"]')
        .filter(visible)
        .slice(0, 50)
        .map(el => ({
          text: (el.innerText || '').trim().slice(0,80),
          ariaLabel: el.getAttribute('aria-label') || '',
          selector: cssPath(el)
        }));

      const msgCandidates = q('[data-message-author-role], .assistant, .ai-message, .bot-message, .message, article, [role="article"]')
        .filter(visible)
        .slice(0, 80)
        .map(el => ({
          role: el.getAttribute('data-message-author-role') || '',
          classes: el.className || '',
          text: (el.innerText || '').trim().slice(0,120),
          selector: cssPath(el)
        }));

      return {
        title: document.title,
        textareas,
        buttons,
        msgCandidates,
        bodyPreview: (document.body && document.body.innerText ? document.body.innerText.slice(0, 400) : '')
      };
    }
    """

    with sync_playwright() as p:
        launch_kwargs = {"headless": headless}
        pw_proxy = playwright_proxy_from_cfg(proxy_cfg)
        if pw_proxy:
            launch_kwargs["proxy"] = pw_proxy
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context(ignore_https_errors=bool(ignore_https_errors))
        try:
            if cookie_header:
                try:
                    context.add_cookies(parse_cookies(cookie_header))
                except Exception:
                    pass
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_sec * 1000)
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass
            data = page.evaluate(js)
        finally:
            try:
                context.close()
            finally:
                browser.close()

    # Heuristic selector picks
    input_selector = "textarea"
    if data.get("textareas"):
        input_selector = data["textareas"][0].get("selector") or "textarea"
    send_selector = None
    for b in data.get("buttons") or []:
        txt = (b.get("text") or "").lower()
        aria = (b.get("ariaLabel") or "").lower()
        if any(k in txt for k in ["send", "submit", "ask", "чат", "изпрати"]) or any(k in aria for k in ["send", "submit", "chat"]):
            send_selector = b.get("selector")
            break
    response_selector = None
    for m in data.get("msgCandidates") or []:
        role = (m.get("role") or "").lower()
        cls = (m.get("classes") or "").lower()
        if role == "assistant" or any(k in cls for k in ["assistant", "bot", "ai-message"]):
            response_selector = m.get("selector")
            break
    response_selector = response_selector or ".assistant, [data-message-author-role='assistant'], .ai-message, .bot-message"

    return {
        "ok": True,
        "url": url,
        "title": data.get("title"),
        "suggested_webchat_config": {
            "input_selector": input_selector,
            "send_selector": send_selector or "",
            "response_selector": response_selector,
            "ready_selector": "body",
            "headless": headless,
            "submit_via_enter": False if send_selector else True,
        },
        "candidates": {
            "inputs": data.get("textareas") or [],
            "buttons": data.get("buttons") or [],
            "messages": data.get("msgCandidates") or [],
        },
        "body_preview": data.get("bodyPreview") or "",
    }
