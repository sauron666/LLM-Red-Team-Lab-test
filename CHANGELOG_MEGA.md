# LLM Attack Lab — MEGA Edition (2026-03)

## Statistics
- **Main window**: 3,800+ lines (was 2,380)
- **Attack library**: 120+ attacks total (was ~45)
- **Evaluators**: 504 lines (was 390)
- **New plugin**: 1,371 lines (`genai_attacks_2025_2026.py`)
- **Report template**: 200+ lines dark cyberpunk HTML

## 🆕 New Tabs
- **🔀 Fuzzer Tab** — 16 mutation strategies, generates hundreds of payload variants
- **🏹 Multi-Target Tab** — run same attack against 5 models simultaneously

## 🎯 Attack Coverage (120+ attacks)

### MCP (Model Context Protocol) — NEW 2025
- Tool Description Prompt Injection
- Malicious Server Response Hijack
- Resource URI Path Traversal
- Prompt Sampling Request Hijack

### Computer Use / Browser Agents
- Screen Content Hidden Text Injection
- Clipboard Content Injection
- QR Code Encoded Injection

### Agentic Frameworks (LangChain/AutoGPT/CrewAI/AutoGen)
- LangChain Tool Output Injection
- AutoGen Speaker Selection Confusion
- CrewAI Task Description Injection
- Persistent Memory Poisoning (MemGPT, ChatGPT Memory)
- Plan-and-Execute Framework Hijack

### RAG / Retrieval Pipeline (2025)
- Embedding Space Collision Attack
- Knowledge Base Backdoor Trigger
- Metadata Filter Access Control Bypass
- Cross-Tenant Data Leakage

### Fine-Tuning & Supply Chain
- Sleeper Agent / Backdoor Activation (Anthropic 2024 research)
- Malicious LoRA Adapter Probe
- Prompt Template Library Injection

### Multimodal Attack Vectors (2024-2025)
- Vision Adversarial Patch Instruction Embed
- Malicious Instructions in Charts/Graphs
- Audio Transcription Prompt Injection (Dolphin Attack variant)
- PDF Hidden Layer Injection
- Code Screenshot Instruction Injection

### Auth / OAuth / Identity (2025)
- OAuth Scope Escalation via Prompt
- Bearer Token Extraction via Context Window
- SAML Assertion Forgery Prompt

### OWASP LLM Top 10 2025 (Complete Coverage)
- LLM01:2025 — Prompt Injection (Advanced Multi-Modal)
- LLM02:2025 — Sensitive Information Disclosure
- LLM03:2025 — Supply Chain Vulnerabilities
- LLM04:2025 — Data and Model Poisoning
- LLM05:2025 — Improper Output Handling (XSS/SQLi/RCE)
- LLM06:2025 — Excessive Agency
- LLM07:2025 — System Prompt Leakage (advanced)
- LLM08:2025 — Vector and Embedding Weaknesses
- LLM09:2025 — Misinformation
- LLM10:2025 — Unbounded Consumption

### Guardrail Bypass (2025)
- Virtual Context Switch
- Leetspeak / Token Smuggling
- Prompt Continuation / Fill-in-the-Middle
- Nested Translation Obfuscation
- Structured Output Format Escape (JSON mode bypass)

### Code Generation / IDE Agents
- Malicious Dependency Suggestion (typosquatting)
- Subtle Backdoor Injection Request
- Injection via Code Comment/Docstring

### Emerging 2025-2026 Research Vectors
- Crescendo Multi-Turn Jailbreak (Microsoft Research 2024)
- Search Result Prompt Injection (SEO Poisoning)
- Email/Document Indirect Injection (Bing/Outlook attack)
- LLM Self-Reflection Bypass
- Model Extraction / Distillation Attack
- JSON API Field Prompt Injection
- Constitutional AI Principle Conflict Exploitation
- Prompt Injection via Markdown Table Cell

## 🔀 Fuzzer — 16 Mutation Strategies
1. Token Substitution
2. Base64 Encoding
3. Leetspeak Substitution
4. Unicode Homoglyph Substitution
5. Reverse Text
6. Language Rotation
7. Character Insertion (zero-width)
8. Sentence Fragmentation
9. Role/Context Prefix
10. Markdown Obfuscation
11. JSON Escape
12. XML/CDATA Wrapping
13. Prompt Completion Attack
14. Hypothetical Framing
15. Authority Claim Injection
16. Adversarial Suffix Append (GCG-style)

## 📊 Report
- Dark cyberpunk HTML theme matching the app
- 6 metric cards
- Color-coded severity rows
- Risk score bar per finding
- Interactive heatmap table
- Zero-Day badge on relevant findings
