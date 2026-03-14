# LLM Attack Lab GUI – Quick Tutorial (EN)

## Core flow
1. Add a **Target** (API, internal HTTP JSON, or Web UI).
2. Configure **Auth / SSO / Cookies** and **Network/TLS** (Enterprise / Strict / Insecure).
3. Run attacks and review **outcome-aware severities** (refusals are not auto-critical).
4. Export HTML / PDF / JSON / SARIF reports.

## Internal chat-router tips
- If the pasted URL already contains `/session/<uuid>/message`, avoid duplicating the path in `_http_connector.path`.
- Prefer **HAR → Target Wizard** to auto-learn request body fields, headers, cookies, and response paths.
- Add CSRF/custom `x-*` headers where required.
- Use **Enterprise TLS + CA bundle** for internal PKI.
- For NTLM corporate proxies, a local **CNTLM** helper is often the easiest path.

## Included connectors (API + no API)
- OpenAI-compatible / Azure / Gemini / Anthropic / OpenRouter / Groq / Mistral / xAI / Hugging Face / Together / Fireworks
- Local: Ollama, LM Studio, vLLM, llama.cpp, LocalAI, LiteLLM proxy
- Web UI (Playwright, no API)
- Custom HTTP JSON / Internal Chat Router

## Research attack pack
`plugins/research_attack_pack_2026.py` adds safe, public-research-inspired regression probes:
- typoglycemia / unicode obfuscation prompt-injection probes
- markdown/HTML comment smuggling probes
- tool registry (MCP-style) poisoning probes
- cross-tenant memory canary checks
- citation spoof / hallucination probes
