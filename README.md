# LLM Attack Lab

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-green)
![GUI](https://img.shields.io/badge/GUI-PySide6-purple)
![Reports](https://img.shields.io/badge/reports-HTML%20%7C%20PDF%20%7C%20JSON%20%7C%20SARIF-orange)

**AI Red Team / Security Research** – идея „Burp Suite for LLMs“.
Работи на **Windows/Linux** (PySide6 GUI) и има **headless CLI** за CI/CD.

## Какво има вътре

### Core (Enterprise + Bug Bounty)
- GUI за проекти / targets / runs / findings / dashboard
- Конектори:
  - OpenAI-compatible API (generic)
  - Gemini (REST)
  - Ollama (local)
  - Anthropic Claude
  - Azure OpenAI
  - OpenRouter / Groq / Mistral / xAI / Hugging Face Router / Together / Fireworks
  - Local OpenAI-compatible servers: LM Studio / vLLM / llama.cpp / text-generation-webui
  - **Web Chat (Playwright, no API)** for chatbot UIs (browser automation)
- Attack library (OWASP LLM Top 10 inspired)
- Plugin система (attack + evaluator plugins)
- SQLite база за runs/findings
- Risk scoring engine + summary

### Разширения (v3 portfolio pack)
- **Headless CLI runner** (CI/CD friendly)
- **Baseline compare** между два run-а (regressions / fixes)
- **SARIF export**
- **Dashboard tab**: severity heatmap + attack tree + trend notes
- **RAG Retrieval Hooks** (local docs JSON)
- **Agent / Tool Calling Validation**
- **JWT/Auth Testing module** (negative auth checks + JWT claim sanity checks)
- **Burp Bridge**
  - parse raw HTTP requests from Burp
  - infer target config automatically
  - safe replay (auth stripped by default)
  - local ingest bridge for Burp extender stub
  - streaming/SSE capture parsing (`/ingest_stream`)
  - WebSocket transcript ingest (`/ingest_ws`)
  - replay diff viewer (baseline vs attacked)
- **Preset profiles**: Enterprise API / Bug Bounty API / RAG app / Agent app
- **Cyber dark theme** (improved GUI readability)
- **Docker Compose demo** (headless + Ollama)
- **GitHub-ready repo structure** (.github workflows, templates, docs, ROADMAP, SECURITY, CONTRIBUTING)
- **Sample targets + demo datasets**

---

## Инсталация

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux: source .venv/bin/activate
pip install -r requirements.txt
# For Web Chat (Playwright) connector only:
playwright install chromium
```

## Стартиране (GUI)

```bash
python main.py
```

Tutorial (BG): `docs/TUTORIAL_BG.md`
Tutorial (EN): `docs/TUTORIAL_EN.md`


## Стартиране (CLI)

```bash
python main_cli.py --help
```

## Burp Bridge ingest server (локално)

```bash
python main_cli.py burp-serve --host 127.0.0.1 --port 8765
```

---

## CLI примери

### 1) List projects / targets
```bash
python main_cli.py list-projects
python main_cli.py list-targets --project-id 1
```

### 2) Scan (enterprise mode)
```bash
python main_cli.py scan   --project-id 1   --target-id 2   --mode enterprise   --intensity 2   --tool-schema-validation   --export html,json,sarif
```

### 3) Scan с RAG retrieval hook (local docs)
```bash
python main_cli.py scan   --project-id 1   --target-id 2   --mode bug_bounty   --retrieval-docs-json "$(cat samples/rag_docs_safe_vs_poison.json)"   --tool-schema-validation   --export html,pdf,json,sarif
```

### 4) Baseline compare
```bash
python main_cli.py compare --baseline-run-id 10 --candidate-run-id 11
```

### 5) JWT/Auth endpoint checks
```bash
python main_cli.py auth-check   --url https://api.example.com/v1/chat/completions   --body-json '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}'
```

или върху saved target:
```bash
python main_cli.py auth-check --target-id 2 --output auth_report.json
```

### 6) Burp Bridge: parse / replay / import target
```bash
python main_cli.py burp-parse --raw samples/burp/openai_chat_raw.txt --infer-target
python main_cli.py burp-replay --raw samples/burp/openai_chat_raw.txt
python main_cli.py burp-create-target --project-id 1 --raw samples/burp/openai_chat_raw.txt
```

---

## Docker Compose demo (headless)

```bash
docker compose -f docker-compose.demo.yml up -d ollama
# pull model once:
docker compose -f docker-compose.demo.yml exec ollama ollama pull llama3.2:3b
# run a CLI command in the lab container:
docker compose -f docker-compose.demo.yml run --rm attack-lab python main_cli.py --help
```

> Забележка: GUI е desktop приложение. Docker setup е за **headless demo/CI**, не за GUI.

---

## Demo data / samples

- `samples/targets.sample.json` – примерни target конфигурации
- `samples/rag_docs_safe_vs_poison.json` – trusted/untrusted RAG docs
- `samples/tool_schema_*.json` – tool schemas за agent validation
- `samples/burp/openai_chat_raw.txt` – примерен raw request (Burp style)
- `samples/jwt/sample_tokens.json` – dummy JWT примери за auth tester

---

## Burp Bridge (интеграция)

В `integrations/burp/` има:
- `burp_extender_stub.py` – Jython stub (PoC), който изпраща raw request към локалния bridge
- `README.md` – как да го вържеш към Burp

Bridge endpoints:
- `POST /ingest` с JSON `{ "raw_request": "...", "note": "..." }`
- `POST /ingest_stream` (raw request + optional raw response for SSE parsing)
- `POST /ingest_ws` (WebSocket transcript / frames)
- `GET /health`

Съхранение: `burp_ingest/*.json`

---

## Портфолио идея (как да го покажеш на интервю)

1. **Ollama local demo** (без външен API key)
2. **Baseline compare** (преди/след guardrails)
3. **SARIF export** към pipeline
4. **RAG poisoning simulation** (trusted vs untrusted docs)
5. **Tool-call schema validation** (agent safety)
6. **JWT/Auth checks** за LLM gateway endpoint
7. **Burp → LLM Attack Lab bridge** (import/replay workflow)

Това позиционира проекта много добре за:
- AI Security Researcher
- LLM Red Teamer
- Product Security (GenAI)
- AppSec / AI Platform Security

---

## Legal / safe use

- For **authorized testing only**
- Safe presets are enabled by default
- Burp replay strips auth headers by default
- Never use against targets without permission


## Outcome-aware severity triage (false-positive reduction)

Severity is assigned **by outcome**, not only by payload category. The evaluator now records:
- `status`: `blocked | vulnerable | inconclusive | review | passed`
- `evidence_type`: primary evidence signal (e.g. `secret_pattern`, `tool_call_abuse`)

This prevents false **High/Critical** findings when the model correctly refuses (e.g. "I can't share internal information").


## New in v7 (custom internal APIs + webchat onboarding)

- **Custom HTTP JSON connector** (`custom_http_json`) for internal/BFF chat APIs (JSON + SSE)
- **Internal Chat Router template** (`internal_chat_router`) for `/chat-router/.../session/.../message` style endpoints
- **Offline endpoint fingerprinting**
  - `python main_cli.py fingerprint-endpoint --url ...`
- **Playwright selector probe** for no-API web chats
  - `python main_cli.py webchat-probe --url ...`
- Better Burp import inference for unknown chat routers (auto-generates `_http_connector` body template + auth hints)


## New in v9 (research + internal diagnostics)

- Improved **Custom HTTP JSON** diagnostics (HTTP/TLS/proxy/auth hints, better internal chat-router troubleshooting)
- Expanded evaluator signals for **session tokens / internal endpoints / reasoning leaks**
- New plugin: **`plugins/research_attack_pack_2026.py`** (safe public-research-inspired regression probes)
- Updated tutorials (BG + EN) with enterprise proxy/TLS/HAR onboarding guidance
