## v7

- Added `custom_http_json` generic connector for internal/custom REST chat APIs (JSON and SSE support).
- Added `internal_chat_router` connector template for `/chat-router/.../session/.../message` patterns.
- Improved Burp import detection for unknown chat/BFF endpoints; now auto-generates `_http_connector` body template, prompt field, session path param, and auth hints.
- Added offline `fingerprint-endpoint` CLI command to infer connector/auth config from URL + sample request.
- Added `webchat-probe` CLI command (Playwright) to auto-suggest selectors for web chat UI onboarding.
- Added extra run profiles for internal chat-router APIs and SSO webchat apps.

# Changelog

## v3.0.0
- Added JWT/Auth testing module (negative auth checks + JWT claim sanity)
- Added Burp Bridge (raw request parse, replay, target import, ingest server)
- Added Docker Compose demo and Dockerfile for headless usage
- Added sample targets, RAG docs, tool schemas, Burp raw request, JWT samples
- Added GitHub-ready repo structure: workflows, templates, docs, SECURITY, CONTRIBUTING, ROADMAP

## v2.x
- GUI + CLI scanning
- Baseline compare
- SARIF export
- Dashboard heatmap + attack tree
- RAG hooks
- Agent/tool validation
