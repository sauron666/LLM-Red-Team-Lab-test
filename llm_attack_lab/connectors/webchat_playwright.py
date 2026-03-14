from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import urlparse

from .base import BaseConnector, ConnectorError
from ..transport import playwright_proxy_from_cfg


class WebChatPlaywrightConnector(BaseConnector):
    """Generic browser-automation connector for web chat UIs (no official API).

    Configuration is passed via target.extra_headers JSON using a reserved `_webchat` object.
    Example:
      {
        "_webchat": {
          "input_selector": "textarea",
          "send_selector": "button[type='submit']",
          "response_selector": ".assistant, [data-message-author-role='assistant']",
          "ready_selector": "body",
          "headless": true
        }
      }
    """

    def _load_playwright(self):
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
            return sync_playwright
        except Exception as e:  # pragma: no cover - runtime dependency path
            raise ConnectorError(
                "Playwright is not installed. Install dependencies and run `playwright install chromium`. "
                f"Original error: {e}"
            )

    def _webchat_cfg(self) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}
        raw = self.extra_headers or {}
        if isinstance(raw.get("_webchat"), dict):
            cfg.update(raw.get("_webchat") or {})
        # Backward-compatible flat x-webchat-* keys
        for k, v in raw.items():
            if not isinstance(k, str):
                continue
            if k.lower().startswith("x-webchat-"):
                key = k[10:].replace("-", "_")
                cfg[key] = v

        # Merge generic auth/session/SSO config
        auth = self._auth_cfg()
        mode = str(auth.get("mode") or "").lower()
        if mode in {"cookie", "session", "sso"}:
            cookie_header = str(auth.get("cookie") or auth.get("cookie_header") or "").strip()
            if cookie_header and not cfg.get("cookie_header"):
                cfg["cookie_header"] = cookie_header
            if isinstance(auth.get("cookies"), list) and not cfg.get("cookies"):
                cfg["cookies"] = auth.get("cookies")
            if isinstance(auth.get("local_storage"), dict) and not cfg.get("local_storage"):
                cfg["local_storage"] = auth.get("local_storage")
        return cfg

    def _browser_headers(self) -> Dict[str, str]:
        out = self.build_headers({}, default_api_key_header=None)
        # Cookies are handled via Playwright cookie jar
        out.pop("Cookie", None)
        for k in list(out.keys()):
            if k.lower().startswith("x-webchat-"):
                out.pop(k, None)
        return out

    def _parse_cookie_header(self, cookie_header: str) -> List[Dict[str, Any]]:
        cookies: List[Dict[str, Any]] = []
        host = urlparse(self.base_url).hostname or "localhost"
        for part in cookie_header.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            cookies.append({"name": name.strip(), "value": value.strip(), "domain": host, "path": "/"})
        return cookies

    def _compose_message(self, system_prompt: str, user_prompt: str, cfg: Dict[str, Any]) -> str:
        if cfg.get("append_system_prompt", True):
            return f"[SYSTEM]\n{system_prompt}\n\n[USER]\n{user_prompt}"
        return user_prompt

    def _set_input_text(self, page, selector: str, text: str) -> None:
        loc = page.locator(selector).first
        loc.wait_for(state="visible", timeout=5000)
        # Try normal fill first
        try:
            loc.fill(text)
            return
        except Exception:
            pass
        # contenteditable fallback
        try:
            page.eval_on_selector(
                selector,
                """
                (el, value) => {
                  el.focus();
                  if (el.isContentEditable) {
                    el.innerText = value;
                  } else {
                    el.value = value;
                  }
                  el.dispatchEvent(new Event('input', { bubbles: true }));
                  el.dispatchEvent(new Event('change', { bubbles: true }));
                }
                """,
                text,
            )
            return
        except Exception as e:
            raise ConnectorError(f"Failed to set input text using selector `{selector}`: {e}")

    def _submit(self, page, selector: str, cfg: Dict[str, Any]) -> None:
        send_selector = str(cfg.get("send_selector") or "").strip()
        if send_selector:
            page.locator(send_selector).first.click(timeout=5000)
            return
        key = str(cfg.get("submit_key") or ("Enter" if cfg.get("submit_via_enter", True) else "Control+Enter"))
        page.locator(selector).first.press(key)

    def _wait_and_extract_response(self, page, cfg: Dict[str, Any], baseline_count: int) -> str:
        response_selector = str(
            cfg.get("response_selector")
            or ".assistant, [data-message-author-role='assistant'], .ai-message, .bot-message"
        )
        timeout_ms = int(cfg.get("response_timeout_ms") or (self.timeout_sec * 1000))
        settle_ms = int(cfg.get("response_settle_ms") or 1200)
        poll_ms = int(cfg.get("poll_ms") or 350)

        loc = page.locator(response_selector)
        deadline = time.time() + (timeout_ms / 1000.0)
        last_text = ""
        stable_for_ms = 0
        started = False

        while time.time() < deadline:
            try:
                count = loc.count()
            except Exception:
                count = 0

            if count > baseline_count:
                started = True
                try:
                    txt = (loc.nth(count - 1).inner_text(timeout=2000) or "").strip()
                except Exception:
                    txt = ""
            elif count > 0 and baseline_count == 0:
                # Some UIs replace content in-place rather than appending; use the last visible assistant block
                try:
                    txt = (loc.nth(count - 1).inner_text(timeout=2000) or "").strip()
                    started = started or bool(txt)
                except Exception:
                    txt = ""
            else:
                txt = ""

            if txt:
                if txt == last_text:
                    stable_for_ms += poll_ms
                else:
                    last_text = txt
                    stable_for_ms = 0
                if stable_for_ms >= settle_ms and started:
                    return txt

            time.sleep(max(0.05, poll_ms / 1000.0))

        if last_text:
            return last_text
        raise ConnectorError(
            "Timed out waiting for a response in the web chat UI. Check `_webchat.response_selector` and send/input selectors."
        )

    def _open_context(self, p, cfg: Dict[str, Any]):
        headless = bool(cfg.get("headless", True))
        browser_name = str(cfg.get("browser") or "chromium").lower()
        launcher = getattr(p, browser_name, None) or p.chromium
        launch_kwargs: Dict[str, Any] = {"headless": headless}
        pw_proxy = playwright_proxy_from_cfg(self._proxy_cfg())
        if pw_proxy:
            launch_kwargs["proxy"] = pw_proxy
        browser = launcher.launch(**launch_kwargs)

        context_kwargs: Dict[str, Any] = {}
        user_agent = cfg.get("user_agent")
        if user_agent:
            context_kwargs["user_agent"] = str(user_agent)
        browser_headers = self._browser_headers()
        if browser_headers:
            context_kwargs["extra_http_headers"] = browser_headers
        context_kwargs["ignore_https_errors"] = bool(cfg.get("ignore_https_errors", self.playwright_ignore_https_errors()))

        context = browser.new_context(**context_kwargs)

        cookie_header = cfg.get("cookie_header")
        if cookie_header:
            try:
                context.add_cookies(self._parse_cookie_header(str(cookie_header)))
            except Exception:
                pass
        if isinstance(cfg.get("cookies"), list):
            try:
                context.add_cookies(cfg.get("cookies"))
            except Exception:
                pass
        if isinstance(cfg.get("local_storage"), dict):
            local_storage = cfg.get("local_storage")
            context.add_init_script(
                """
                (entries) => {
                  for (const [k, v] of Object.entries(entries)) {
                    window.localStorage.setItem(k, String(v));
                  }
                }
                """,
                local_storage,
            )
        page = context.new_page()
        return browser, context, page

    def test_connection(self) -> str:
        sync_playwright = self._load_playwright()
        cfg = self._webchat_cfg()
        with sync_playwright() as p:
            browser, context, page = self._open_context(p, cfg)
            try:
                page.goto(self.base_url, wait_until="domcontentloaded", timeout=self.timeout_sec * 1000)
                if cfg.get("wait_network_idle"):
                    try:
                        page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass
                ready = str(cfg.get("ready_selector") or "body")
                page.locator(ready).first.wait_for(state="attached", timeout=5000)
                title = page.title() or self.base_url
                return f"OK_WEBCHAT_PAGE_REACHABLE: {title}"
            except Exception as e:
                raise ConnectorError(f"WebChat (Playwright) test failed: {e}")
            finally:
                try:
                    context.close()
                finally:
                    browser.close()

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        sync_playwright = self._load_playwright()
        cfg = self._webchat_cfg()
        input_selector = str(cfg.get("input_selector") or "textarea")
        message = self._compose_message(system_prompt, user_prompt, cfg)

        with sync_playwright() as p:
            browser, context, page = self._open_context(p, cfg)
            try:
                page.goto(self.base_url, wait_until="domcontentloaded", timeout=self.timeout_sec * 1000)
                if cfg.get("wait_network_idle"):
                    try:
                        page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass
                ready_selector = str(cfg.get("ready_selector") or "body")
                page.locator(ready_selector).first.wait_for(state="attached", timeout=10000)

                response_selector = str(
                    cfg.get("response_selector")
                    or ".assistant, [data-message-author-role='assistant'], .ai-message, .bot-message"
                )
                try:
                    baseline_count = page.locator(response_selector).count()
                except Exception:
                    baseline_count = 0

                self._set_input_text(page, input_selector, message)
                self._submit(page, input_selector, cfg)
                return self._wait_and_extract_response(page, cfg, baseline_count)
            except ConnectorError:
                raise
            except Exception as e:
                raise ConnectorError(f"WebChat (Playwright) connector failed: {e}")
            finally:
                try:
                    context.close()
                finally:
                    browser.close()
