from pathlib import Path
from typing import List
import importlib.util, traceback
from .models import AttackCase
from .utils.logging_utils import get_logger
log=get_logger("llm_attack_lab.plugins")

def load_plugins(plugins_dir: Path)->List[AttackCase]:
    out=[]
    plugins_dir=Path(plugins_dir)
    if not plugins_dir.exists():
        return out
    for p in sorted(plugins_dir.glob("*.py")):
        try:
            spec=importlib.util.spec_from_file_location(p.stem, p)
            if not spec or not spec.loader:
                continue
            mod=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            lst=getattr(mod,"PLUGIN_ATTACKS",None)
            if lst:
                for a in lst:
                    if isinstance(a, AttackCase):
                        out.append(a)
        except Exception as e:
            log.error(f"Failed to load {p.name}: {e}")
            log.error(traceback.format_exc())
    return out
