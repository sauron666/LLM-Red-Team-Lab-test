# Demo Walkthrough (10 minutes)

## 1) Local model setup (Ollama)
- `ollama serve`
- `ollama pull llama3.2:3b`

## 2) Create target
- GUI: add Ollama target (`http://127.0.0.1:11434/api/chat`)
- or CLI using `--create-target`

## 3) Run baseline scan
- Enterprise mode, intensity 1, safe mode on

## 4) Add guardrail / change prompt config
- Run candidate scan
- Use baseline compare to show regression/fix view

## 5) RAG poisoning demo
- Load `samples/rag_docs_safe_vs_poison.json`
- Show findings and recommendations

## 6) Agent safety demo
- Enable tool schema validation
- Show tool_hijack findings

## 7) JWT/Auth demo
- `main_cli.py auth-check --target-id <id>`

## 8) Burp bridge demo
- Parse `samples/burp/openai_chat_raw.txt`
- Replay safely (auth stripped)
- Optional ingest server + Burp stub
