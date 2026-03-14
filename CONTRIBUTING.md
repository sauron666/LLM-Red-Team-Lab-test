# Contributing

Thanks for contributing to LLM Attack Lab.

## Rules
- Authorized testing only
- Keep payloads safe by default
- No real secrets in commits, samples, screenshots, or issues
- Document new attacks/evaluators with clear rationale and evidence fields

## Development setup
```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python main.py
```

## Pull request checklist
- [ ] Code compiles (`python -m compileall .`)
- [ ] README/docs updated (if behavior changed)
- [ ] No secrets/API keys
- [ ] New features include safe defaults
- [ ] Added/updated sample files if relevant

## Plugin contributions
Plugins are welcome (attacks/evaluators). Keep them in `plugins/` and expose:
- `get_attack_plugins()`
- `get_evaluator_plugins()`
