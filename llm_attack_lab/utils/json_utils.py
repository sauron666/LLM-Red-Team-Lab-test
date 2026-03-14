import json
from typing import Any, Tuple
def pretty_json(obj: Any)->str:
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(obj)
def parse_json(text: str)->Tuple[bool, Any, str]:
    try:
        return True, json.loads(text), ""
    except Exception as e:
        return False, None, str(e)
