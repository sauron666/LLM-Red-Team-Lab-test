from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .attacks import generate_attack_variants
from .connectors import build_connector
from .db import LabDB
from .evaluators import evaluate_builtin, recommendation_for_category, triage_outcome, evaluate_with_llm_judge
from .models import AttackCase, RunConfig
from .scoring import aggregate_run_risk, score_finding
from .rag_hooks import RetrievalHookEngine
from .agent_validation import validate_tool_schema_response


class AttackRunner:
    def __init__(self, db: LabDB, attack_registry: Dict[str, AttackCase], plugin_evaluators: Optional[Dict[str, Callable]] = None):
        self.db = db
        self.attack_registry = attack_registry
        self.plugin_evaluators = plugin_evaluators or {}
        
        # Automatically enable LLM-as-a-judge if explicitly requested by environment 
        import os
        if os.environ.get("USE_LLM_JUDGE") == "1":
            self.plugin_evaluators["llm_judge"] = evaluate_with_llm_judge

    def run(
        self,
        cfg: RunConfig,
        log: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> int:
        def _log(msg: str):
            if log:
                log(msg)

        target = self.db.get_target(cfg.target_id)
        connector = build_connector(target)
        retrieval_engine = RetrievalHookEngine(cfg.retrieval_docs) if cfg.retrieval_hook_enabled else None

        run_id = self.db.create_run(
            project_id=cfg.project_id,
            target_id=cfg.target_id,
            mode=cfg.mode.value,
            safe_mode=cfg.safe_mode,
            intensity=cfg.intensity,
            status="running",
        )
        _log(f"[RUN {run_id}] Target={target['name']} Connector={target['connector_type']} Model={target['model']}")
        selected = [self.attack_registry[aid] for aid in cfg.selected_attack_ids if aid in self.attack_registry]
        expanded = generate_attack_variants(selected, cfg.intensity, cfg.safe_mode)
        _log(f"[RUN {run_id}] Selected attacks={len(selected)} Expanded variants={len(expanded)} (intensity={cfg.intensity})")
        if retrieval_engine:
            _log(f"[RUN {run_id}] RAG Retrieval Hook enabled with {len(cfg.retrieval_docs)} local docs")
        if cfg.tool_schema_validation:
            _log(f"[RUN {run_id}] Agent/Tool schema validation enabled")

        try:
            for idx, attack in enumerate(expanded, start=1):
                if should_stop and should_stop():
                    _log(f"[RUN {run_id}] Stop requested.")
                    raise KeyboardInterrupt("Stopped by user")

                user_prompt = attack.render_prompt(_dict_to_targetproxy(target))
                retrieval_meta = {"enabled": False}
                if retrieval_engine and (cfg.retrieval_apply_all or attack.metadata.get("requires_retrieval_hook") or attack.category in {"rag_poisoning", "hallucination"}):
                    user_prompt, retrieval_meta = retrieval_engine.apply(attack, user_prompt)

                _log(f"[{idx}/{len(expanded)}] Executing: {attack.title}")

                try:
                    response = connector.chat(attack.system_prompt, user_prompt)
                    _log(f"  ↳ Response len={len(response)}")
                except Exception as e:
                    response = f"[CONNECTOR_ERROR] {e}"
                    _log(f"  ↳ Connector error: {e}")

                if response.startswith("[CONNECTOR_ERROR]"):
                    _log("  ↳ Skipping evaluation due to connector error")
                    continue

                triggered, evidence = evaluate_builtin(attack, response)
                evidence["retrieval_hook"] = retrieval_meta

                # Built-in agent/tool schema validation (v2)
                tool_rules: List[str] = []
                tool_evidence: Dict[str, object] = {}
                if cfg.tool_schema_validation:
                    tool_rules, tool_evidence = validate_tool_schema_response(attack, response, cfg.tool_schema)
                    if tool_rules:
                        evidence["tool_schema_validation"] = tool_evidence

                # Plugin evaluators
                plugin_hits: List[str] = []
                plugin_evidence: Dict[str, object] = {}
                for name, fn in self.plugin_evaluators.items():
                    try:
                        ev_triggered, ev_evidence = fn(attack, response)
                        if ev_triggered:
                            plugin_hits.extend([f"{name}:{r}" for r in ev_triggered])
                            if ev_evidence:
                                plugin_evidence[name] = ev_evidence
                    except Exception as e:
                        plugin_evidence[name] = {"error": str(e)}

                all_rules = triggered + [f"tool_schema:{r}" for r in tool_rules] + plugin_hits
                confidence = 1
                if all_rules:
                    if triggered:
                        confidence += 1
                    if tool_rules or plugin_hits:
                        confidence += 1
                    confidence = min(confidence, 3)

                if all_rules:
                    triage = triage_outcome(attack, response, all_rules, evidence)
                    risk_score, severity = score_finding(attack.category, all_rules, confidence, triage)
                    recommendation = recommendation_for_category(attack.category)
                    evidence_payload = {**evidence, "plugin_evidence": plugin_evidence, "triage": triage}
                    self.db.add_finding(
                        run_id=run_id,
                        attack_id=attack.attack_id,
                        attack_title=attack.title,
                        category=attack.category,
                        status=str(triage.get("status", "inconclusive")),
                        evidence_type=str(triage.get("evidence_type", "general_signal")),
                        severity=severity,
                        confidence=confidence,
                        risk_score=risk_score,
                        recommendation=recommendation,
                        evidence=evidence_payload,
                        transcript={
                            "system_prompt": attack.system_prompt,
                            "user_prompt": user_prompt,
                            "response": response,
                            "triggered_rules": all_rules,
                        },
                    )
                    _log(f"  ↳ Finding: status={triage.get('status')} {severity.upper()} score={risk_score} rules={', '.join(all_rules)}")
                else:
                    _log("  ↳ No finding (pass)")

            findings = self.db.list_findings(run_id=run_id)
            summary = aggregate_run_risk(findings)
            summary.update(
                {
                    "findings_count": len(findings),
                    "passed_variants": max(0, len(expanded) - len(findings)),
                    "expanded_variants": len(expanded),
                    "selected_attacks": len(selected),
                    "run_config": {
                        "mode": cfg.mode.value,
                        "safe_mode": cfg.safe_mode,
                        "intensity": cfg.intensity,
                        "retrieval_hook_enabled": cfg.retrieval_hook_enabled,
                        "retrieval_docs": len(cfg.retrieval_docs),
                        "retrieval_apply_all": cfg.retrieval_apply_all,
                        "tool_schema_validation": cfg.tool_schema_validation,
                    },
                }
            )
            self.db.finish_run(run_id, "completed", summary)
            _log(f"[RUN {run_id}] Completed. Findings={len(findings)} Overall risk={summary['overall_risk']} ({summary['severity']})")
            return run_id
        except KeyboardInterrupt:
            findings = self.db.list_findings(run_id=run_id)
            summary = aggregate_run_risk(findings)
            summary.update({"status": "stopped"})
            self.db.finish_run(run_id, "stopped", summary)
            _log(f"[RUN {run_id}] Stopped by user.")
            return run_id
        except Exception as e:
            findings = self.db.list_findings(run_id=run_id)
            summary = aggregate_run_risk(findings)
            summary.update({"error": str(e)})
            self.db.finish_run(run_id, "failed", summary)
            _log(f"[RUN {run_id}] Failed: {e}")
            return run_id


def _dict_to_targetproxy(target: Dict):
    class _T:
        def __init__(self, d):
            self.id = d.get("id")
            self.project_id = d.get("project_id")
            self.name = d.get("name")
            self.connector_type = d.get("connector_type")
            self.base_url = d.get("base_url")
            self.model = d.get("model")
    return _T(target)
