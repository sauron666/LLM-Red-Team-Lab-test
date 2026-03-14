from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .db import LabDB


def _normalize_findings(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        # Key by attack_id + top triggered rules for stable comparison.
        trig = sorted(((f.get("transcript") or {}).get("triggered_rules") or []))
        key = f"{f.get('attack_id')}|{'/'.join(trig[:5])}"
        out[key] = f
    return out


def compare_runs(db: LabDB, baseline_run_id: int, candidate_run_id: int) -> Dict[str, Any]:
    base_run = db.get_run(baseline_run_id)
    cand_run = db.get_run(candidate_run_id)
    base_findings = db.list_findings(run_id=baseline_run_id)
    cand_findings = db.list_findings(run_id=candidate_run_id)

    base_idx = _normalize_findings(base_findings)
    cand_idx = _normalize_findings(cand_findings)

    new_keys = sorted(set(cand_idx) - set(base_idx))
    fixed_keys = sorted(set(base_idx) - set(cand_idx))
    common_keys = sorted(set(base_idx) & set(cand_idx))

    regressed = []
    improved = []
    unchanged = []
    for k in common_keys:
        b = base_idx[k]
        c = cand_idx[k]
        b_score, c_score = int(b.get("risk_score", 0)), int(c.get("risk_score", 0))
        delta = c_score - b_score
        row = {
            "key": k,
            "attack_title": c.get("attack_title") or b.get("attack_title"),
            "category": c.get("category") or b.get("category"),
            "baseline_score": b_score,
            "candidate_score": c_score,
            "delta": delta,
            "baseline_severity": b.get("severity"),
            "candidate_severity": c.get("severity"),
        }
        if delta > 0:
            regressed.append(row)
        elif delta < 0:
            improved.append(row)
        else:
            unchanged.append(row)

    baseline_risk = int((base_run.get("summary") or {}).get("overall_risk", 0))
    candidate_risk = int((cand_run.get("summary") or {}).get("overall_risk", 0))
    overall_delta = candidate_risk - baseline_risk

    return {
        "baseline_run_id": baseline_run_id,
        "candidate_run_id": candidate_run_id,
        "baseline_overall_risk": baseline_risk,
        "candidate_overall_risk": candidate_risk,
        "overall_delta": overall_delta,
        "summary": {
            "new_findings": len(new_keys),
            "fixed_findings": len(fixed_keys),
            "regressed_common": len(regressed),
            "improved_common": len(improved),
            "unchanged_common": len(unchanged),
        },
        "new_findings": [cand_idx[k] for k in new_keys],
        "fixed_findings": [base_idx[k] for k in fixed_keys],
        "regressed": regressed,
        "improved": improved,
        "unchanged": unchanged,
    }
