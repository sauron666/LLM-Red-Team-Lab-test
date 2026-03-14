from __future__ import annotations

import importlib.util
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Tuple, Any

from .models import AttackCase


@dataclass
class PluginInfo:
    name: str
    path: str
    loaded: bool
    error: str = ""
    attacks_added: int = 0
    evaluators_added: int = 0


class PluginManager:
    def __init__(self, plugin_dir: Path):
        self.plugin_dir = Path(plugin_dir)
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        self.plugin_infos: List[PluginInfo] = []
        self.attack_plugins: List[AttackCase] = []
        self.evaluator_plugins: Dict[str, Callable] = {}

    def load(self) -> None:
        self.plugin_infos.clear()
        self.attack_plugins.clear()
        self.evaluator_plugins.clear()

        for pyfile in sorted(self.plugin_dir.glob("*.py")):
            info = PluginInfo(name=pyfile.stem, path=str(pyfile), loaded=False)
            try:
                spec = importlib.util.spec_from_file_location(pyfile.stem, pyfile)
                if not spec or not spec.loader:
                    raise RuntimeError("Could not create import spec")
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore

                if not hasattr(mod, "register"):
                    raise RuntimeError("Plugin missing register()")
                reg = mod.register()
                attacks = reg.get("attacks", []) or []
                evaluators = reg.get("evaluators", []) or []

                for a in attacks:
                    if not isinstance(a, AttackCase):
                        raise TypeError(f"Plugin attack is not AttackCase: {a!r}")
                    self.attack_plugins.append(a)

                for ev in evaluators:
                    ev_name = getattr(ev, "__name__", f"{pyfile.stem}_evaluator_{len(self.evaluator_plugins)+1}")
                    self.evaluator_plugins[ev_name] = ev

                info.loaded = True
                info.attacks_added = len(attacks)
                info.evaluators_added = len(evaluators)
            except Exception as e:
                info.error = f"{e}\n{traceback.format_exc(limit=2)}"
            self.plugin_infos.append(info)

    def list_plugin_rows(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": p.name,
                "path": p.path,
                "loaded": p.loaded,
                "attacks_added": p.attacks_added,
                "evaluators_added": p.evaluators_added,
                "error": p.error,
            }
            for p in self.plugin_infos
        ]
