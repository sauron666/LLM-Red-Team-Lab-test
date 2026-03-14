from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple


SUSPICIOUS_MODULES = {
    "os",
    "subprocess",
    "socket",
    "requests",
    "urllib",
    "pickle",
    "shelve",
    "sqlite3",
    "ftplib",
    "telnetlib",
    "paramiko",
    "cryptography",
}

SUSPICIOUS_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "pickle.loads",
    "pickle.load",
    "eval",
    "exec",
    "compile",
    "__import__",
    "socket.socket",
    "urllib.request.urlopen",
}

INJECTION_PHRASES = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "system prompt",
    "developer message",
    "reveal hidden",
    "print the system",
    "do anything now",
    "bypass",
    "disable safeguards",
]


@dataclass
class ScanHit:
    file: str
    line: int
    kind: str
    detail: str


class _ASTScanner(ast.NodeVisitor):
    def __init__(self, file: str):
        self.file = file
        self.hits: List[ScanHit] = []

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name.split(".")[0] in SUSPICIOUS_MODULES:
                self.hits.append(ScanHit(self.file, node.lineno, "import", alias.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        mod = (node.module or "").split(".")[0]
        if mod in SUSPICIOUS_MODULES:
            self.hits.append(ScanHit(self.file, node.lineno, "import", node.module or mod))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        call = self._call_string(node)
        if call in SUSPICIOUS_CALLS:
            self.hits.append(ScanHit(self.file, node.lineno, "call", call))
        else:
            # best-effort: module.attr
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
                if mod in SUSPICIOUS_MODULES:
                    self.hits.append(ScanHit(self.file, node.lineno, "call", f"{mod}.{node.func.attr}"))
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile", "__import__"}:
                self.hits.append(ScanHit(self.file, node.lineno, "call", node.func.id))
        self.generic_visit(node)

    def _call_string(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""


def scan_python_directory(directory: str | Path) -> List[ScanHit]:
    """Defensive static analysis: scan Python 'skills' or plugins for risky imports/calls."""
    root = Path(directory)
    hits: List[ScanHit] = []
    for path in root.rglob("*.py"):
        try:
            src = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(path))
        except SyntaxError as e:
            hits.append(ScanHit(str(path), 0, "syntax_error", str(e)))
            continue
        s = _ASTScanner(str(path))
        s.visit(tree)
        hits.extend(s.hits)
    return hits


def scan_text_for_prompt_injection(text: str) -> List[str]:
    t = (text or "").lower()
    found: List[str] = []
    for phrase in INJECTION_PHRASES:
        if phrase in t:
            found.append(phrase)
    return found


def scan_dockerfile(dockerfile_path: str | Path) -> List[ScanHit]:
    """Defensive scan: detect likely prompt-injection style instructions embedded in Docker labels/comments."""
    p = Path(dockerfile_path)
    hits: List[ScanHit] = []
    if not p.exists():
        return hits
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    for i, ln in enumerate(lines, start=1):
        if "label" in ln.lower() or "#" in ln:
            phrases = scan_text_for_prompt_injection(ln)
            for ph in phrases:
                hits.append(ScanHit(str(p), i, "prompt_injection_phrase", ph))
    return hits


def scan_json_metadata(path: str | Path) -> List[ScanHit]:
    """Defensive scan: scan arbitrary JSON metadata (e.g., tool schemas, manifests, RAG docs) for injection phrases."""
    p = Path(path)
    hits: List[ScanHit] = []
    if not p.exists():
        return hits
    try:
        obj = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        return [ScanHit(str(p), 0, "json_error", str(e))]

    def _walk(o: Any, prefix: str = ""):
        if isinstance(o, dict):
            for k, v in o.items():
                _walk(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(o, list):
            for idx, v in enumerate(o):
                _walk(v, f"{prefix}[{idx}]")
        elif isinstance(o, str):
            phrases = scan_text_for_prompt_injection(o)
            for ph in phrases:
                hits.append(ScanHit(str(p), 0, "prompt_injection_phrase", f"{ph} @ {prefix}"))

    _walk(obj)
    return hits


def hits_to_dict(hits: List[ScanHit]) -> List[Dict[str, Any]]:
    return [{"file": h.file, "line": h.line, "kind": h.kind, "detail": h.detail} for h in hits]
