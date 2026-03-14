from __future__ import annotations

from typing import Any, Dict, List, Tuple

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def build_heatmap(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    categories = sorted({f.get("category", "unknown") for f in findings})
    matrix = {cat: {sev: 0 for sev in SEVERITIES} for cat in categories}
    for f in findings:
        cat = f.get("category", "unknown")
        sev = str(f.get("severity", "info")).lower()
        if cat not in matrix:
            matrix[cat] = {s: 0 for s in SEVERITIES}
        if sev not in matrix[cat]:
            sev = "info"
        matrix[cat][sev] += 1
    return {"categories": categories, "severities": SEVERITIES, "matrix": matrix}


def build_attack_tree(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    tree: Dict[str, Any] = {}
    for f in findings:
        cat = f.get("category", "unknown")
        attack = f.get("attack_title", f.get("attack_id", "attack"))
        sev = f.get("severity", "info")
        node = tree.setdefault(cat, {"count": 0, "attacks": {}})
        node["count"] += 1
        an = node["attacks"].setdefault(attack, {"count": 0, "severities": {}})
        an["count"] += 1
        an["severities"][sev] = an["severities"].get(sev, 0) + 1
    return tree
