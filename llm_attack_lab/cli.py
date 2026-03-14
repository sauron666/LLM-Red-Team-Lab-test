from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

from .attacks import get_builtin_attacks
from .auth_tester import run_http_auth_negative_tests, run_target_auth_audit
from .baseline import compare_runs
from .burp_bridge import (
    infer_target_from_parsed_request,
    parse_raw_http_request,
    replay_parsed_request,
    replay_diff_requests,
    run_burp_ingest_server,
)
from .db import LabDB
from .burp_export_parser import parse_burp_export
from .connectors import list_connector_types
from .fingerprinting import fingerprint_endpoint
from .webchat_probe import probe_webchat_page
from .models import RunConfig, RunMode
from .plugin_manager import PluginManager
from .reporter import export_run_report
from .runner import AttackRunner


def _load_db() -> LabDB:
    data_dir = Path.home() / ".llm_attack_lab"
    data_dir.mkdir(parents=True, exist_ok=True)
    return LabDB(data_dir / "lab.db")


def _load_registry(plugin_dir: Path) -> tuple[Dict, Dict]:
    pm = PluginManager(plugin_dir)
    pm.load()
    registry = {a.attack_id: a for a in get_builtin_attacks()}
    for a in pm.attack_plugins:
        registry[a.attack_id] = a
    return registry, pm.evaluator_plugins


def _parse_json_arg(value: str, default):
    if not value:
        return default
    return json.loads(value)


def cmd_list_projects(args):
    db = _load_db()
    for p in db.list_projects():
        print(f"#{p['id']}: {p['name']}")


def cmd_list_targets(args):
    db = _load_db()
    targets = db.list_targets(project_id=args.project_id)
    for t in targets:
        print(f"#{t['id']} | project={t['project_id']} | {t['name']} | {t['connector_type']} | {t['model']}")


def cmd_scan(args):
    db = _load_db()
    registry, plugin_evals = _load_registry(Path(args.plugins_dir))

    # Optional quick-create project/target for CI
    project_id = args.project_id
    target_id = args.target_id
    if args.create_project and not project_id:
        project_id = db.create_project(args.create_project)
        print(f"Created project #{project_id}: {args.create_project}")
    if args.create_target and not target_id:
        if not project_id:
            raise SystemExit("--create-target requires --project-id or --create-project")
        target_spec = _parse_json_arg(args.create_target, {})
        target_id = db.create_target(
            project_id=project_id,
            name=target_spec.get("name", "CI Target"),
            connector_type=target_spec["connector_type"],
            base_url=target_spec["base_url"],
            model=target_spec["model"],
            api_key=target_spec.get("api_key", ""),
            extra_headers=target_spec.get("extra_headers", {}),
            timeout_sec=int(target_spec.get("timeout_sec", 30)),
        )
        print(f"Created target #{target_id}")

    if not project_id or not target_id:
        raise SystemExit("Provide --project-id and --target-id (or use --create-project/--create-target)")

    if args.pre_auth_check:
        t = db.get_target(int(target_id))
        print("Running auth pre-check...")
        auth_res = run_target_auth_audit(t)
        print(json.dumps(auth_res, ensure_ascii=False, indent=2))

    if args.burp_raw:
        parsed = parse_raw_http_request(Path(args.burp_raw).read_text(encoding="utf-8"), scheme=args.burp_scheme)
        print("Parsed Burp raw request:")
        print(json.dumps({"parsed": parsed.__dict__, "inferred_target": infer_target_from_parsed_request(parsed)}, ensure_ascii=False, indent=2))

    selected = []
    if args.attack_ids:
        selected = [a.strip() for a in args.attack_ids.split(",") if a.strip()]
    elif args.categories:
        wanted = {c.strip() for c in args.categories.split(",") if c.strip()}
        selected = [aid for aid, a in registry.items() if a.category in wanted]
    else:
        selected = list(registry.keys())

    mode = RunMode(args.mode)
    retrieval_docs = _parse_json_arg(args.retrieval_docs_json, []) if args.retrieval_docs_json else []
    tool_schema = _parse_json_arg(args.tool_schema_json, {}) if args.tool_schema_json else {}
    cfg = RunConfig(
        project_id=int(project_id),
        target_id=int(target_id),
        mode=mode,
        safe_mode=not args.no_safe_mode,
        intensity=int(args.intensity),
        selected_attack_ids=selected,
        selected_plugin_evaluators=list(plugin_evals.keys()),
        retrieval_hook_enabled=bool(retrieval_docs),
        retrieval_docs=retrieval_docs,
        retrieval_apply_all=args.retrieval_apply_all,
        tool_schema_validation=args.tool_schema_validation,
        tool_schema=tool_schema,
    )
    runner = AttackRunner(db, registry, plugin_evals)
    run_id = runner.run(cfg, log=lambda m: print(m))
    print(f"RUN_ID={run_id}")

    if args.export:
        out = export_run_report(db, run_id, Path.home()/'.llm_attack_lab'/'reports', [x.strip() for x in args.export.split(',') if x.strip()])
        for k, v in out.items():
            print(f"{k.upper()}={v}")


def cmd_export(args):
    db = _load_db()
    formats = [x.strip() for x in args.formats.split(",") if x.strip()]
    out = export_run_report(db, args.run_id, Path.home()/'.llm_attack_lab'/'reports', formats)
    print(json.dumps(out, ensure_ascii=False, indent=2))


def cmd_compare(args):
    db = _load_db()
    diff = compare_runs(db, args.baseline_run_id, args.candidate_run_id)
    if args.as_json:
        print(json.dumps(diff, ensure_ascii=False, indent=2))
        return
    print(f"Baseline #{diff['baseline_run_id']} risk={diff['baseline_overall_risk']} | Candidate #{diff['candidate_run_id']} risk={diff['candidate_overall_risk']} | Δ={diff['overall_delta']}")
    s = diff['summary']
    print(f"New={s['new_findings']} Fixed={s['fixed_findings']} Regressed={s['regressed_common']} Improved={s['improved_common']} Unchanged={s['unchanged_common']}")
    if diff['regressed']:
        print('Regressed:')
        for r in diff['regressed'][:20]:
            print(f" - {r['attack_title']} ({r['category']}): {r['baseline_score']} -> {r['candidate_score']} (+{r['delta']})")
    if diff['new_findings']:
        print('New findings:')
        for f in diff['new_findings'][:20]:
            print(f" - {f['attack_title']} ({f['category']}) risk={f['risk_score']} {f['severity']}")


def cmd_auth_check(args):
    if args.target_id:
        db = _load_db()
        target = db.get_target(args.target_id)
        result = run_target_auth_audit(target, override_json_body=_parse_json_arg(args.body_json, None))
    else:
        headers = _parse_json_arg(args.headers_json, {}) if args.headers_json else {}
        result = run_http_auth_negative_tests(
            url=args.url,
            method=args.method,
            headers=headers,
            json_body=_parse_json_arg(args.body_json, None),
            timeout_sec=args.timeout,
        )
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(payload, encoding='utf-8')
        print(f"Saved auth report: {args.output}")
    print(payload)


def cmd_burp_parse(args):
    raw = Path(args.raw).read_text(encoding='utf-8')
    parsed = parse_raw_http_request(raw, scheme=args.scheme)
    data = {'parsed': parsed.__dict__}
    if args.infer_target:
        data['inferred_target'] = infer_target_from_parsed_request(parsed)
    txt = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(txt, encoding='utf-8')
        print(f"Saved: {args.output}")
    print(txt)


def cmd_burp_replay(args):
    raw = Path(args.raw).read_text(encoding='utf-8')
    parsed = parse_raw_http_request(raw, scheme=args.scheme)
    res = replay_parsed_request(parsed, allow_auth=args.allow_auth, timeout_sec=args.timeout)
    txt = json.dumps(res, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(txt, encoding='utf-8')
        print(f"Saved: {args.output}")
    print(txt)


def cmd_burp_create_target(args):
    db = _load_db()
    raw = Path(args.raw).read_text(encoding='utf-8')
    parsed = parse_raw_http_request(raw, scheme=args.scheme)
    target = infer_target_from_parsed_request(parsed)
    name = args.name or target['name']
    tid = db.create_target(
        project_id=args.project_id,
        name=name,
        connector_type=target['connector_type'],
        base_url=target['base_url'],
        model=target['model'],
        api_key=target.get('api_key', ''),
        extra_headers=target.get('extra_headers', {}),
        timeout_sec=int(target.get('timeout_sec', 30)),
    )
    print(json.dumps({'created_target_id': tid, 'target': target}, ensure_ascii=False, indent=2))


def cmd_burp_serve(args):
    print(f"Starting Burp ingest bridge on http://{args.host}:{args.port} (POST /ingest, GET /health)")
    print(f"Captures will be stored in: {args.out_dir}")
    run_burp_ingest_server(bind_host=args.host, port=args.port, out_dir=args.out_dir)


def cmd_burp_parse_export(args):
    items = parse_burp_export(args.path)
    payload = {"count": len(items)}
    if args.full:
        payload["items"] = items
    else:
        payload["items"] = [{
            "source": x.get("source", ""),
            "url": x.get("url", ""),
            "note": x.get("note", ""),
            "request_preview": str(x.get("raw_request", ""))[:300],
            "response_content_type": x.get("response_content_type", ""),
        } for x in items[:200]]
    txt = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(txt, encoding='utf-8')
        print(f"Saved: {args.output}")
    print(txt)


def cmd_burp_replay_diff(args):
    raw_b = Path(args.baseline).read_text(encoding='utf-8', errors='ignore')
    raw_a = Path(args.attacked).read_text(encoding='utf-8', errors='ignore')
    pb = parse_raw_http_request(raw_b, scheme=args.scheme)
    pa = parse_raw_http_request(raw_a, scheme=args.scheme)
    res = replay_diff_requests(pb, pa, allow_auth=args.allow_auth, timeout_sec=args.timeout)
    if args.output:
        Path(args.output).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f"Saved replay diff to {args.output}")
    else:
        print(json.dumps(res, ensure_ascii=False, indent=2))


def cmd_list_connectors(args):
    print(json.dumps({'connectors': list_connector_types()}, ensure_ascii=False, indent=2))




def cmd_fingerprint_endpoint(args):
    headers = _parse_json_arg(args.headers_json, {}) if args.headers_json else {}
    body = None
    if args.body_file:
        body = Path(args.body_file).read_text(encoding='utf-8', errors='ignore')
    elif args.body_json:
        # Preserve exact JSON formatting if possible
        bj = _parse_json_arg(args.body_json, {})
        body = json.dumps(bj, ensure_ascii=False)
    result = fingerprint_endpoint(args.url, method=args.method, headers=headers, body=body)
    txt = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(txt, encoding='utf-8')
        print(f"Saved: {args.output}")
    print(txt)


def cmd_webchat_probe(args):
    cookie_header = ''
    if args.cookie_header:
        cookie_header = args.cookie_header
    elif args.headers_json:
        hdrs = _parse_json_arg(args.headers_json, {})
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if str(k).lower() == 'cookie':
                    cookie_header = str(v)
                    break
    res = probe_webchat_page(args.url, headless=not args.show_browser, cookie_header=cookie_header, timeout_sec=args.timeout)
    txt = json.dumps(res, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(txt, encoding='utf-8')
        print(f"Saved: {args.output}")
    print(txt)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='llm-attack-lab', description='Headless CLI for LLM Attack Lab')
    sub = p.add_subparsers(dest='cmd', required=True)

    sp = sub.add_parser('list-projects')
    sp.set_defaults(func=cmd_list_projects)

    st = sub.add_parser('list-targets')
    st.add_argument('--project-id', type=int)
    st.set_defaults(func=cmd_list_targets)

    ss = sub.add_parser('scan', help='Run a scan headlessly (CI/CD friendly)')
    ss.add_argument('--project-id', type=int)
    ss.add_argument('--target-id', type=int)
    ss.add_argument('--create-project', help='Create project if needed')
    ss.add_argument('--create-target', help='JSON target spec to create target')
    ss.add_argument('--mode', choices=['enterprise', 'bug_bounty'], default='enterprise')
    ss.add_argument('--intensity', type=int, choices=[1, 2, 3], default=2)
    ss.add_argument('--no-safe-mode', action='store_true')
    ss.add_argument('--attack-ids', help='Comma-separated attack IDs')
    ss.add_argument('--categories', help='Comma-separated categories')
    ss.add_argument('--plugins-dir', default='plugins')
    ss.add_argument('--retrieval-docs-json', help='JSON array of local retrieval docs for RAG testing')
    ss.add_argument('--retrieval-apply-all', action='store_true', help='Apply retrieval hook to all attacks')
    ss.add_argument('--tool-schema-validation', action='store_true')
    ss.add_argument('--tool-schema-json', help='Schema override JSON for tool-call validation')
    ss.add_argument('--burp-raw', help='Optional raw HTTP request file exported from Burp (preview/infer before scan)')
    ss.add_argument('--burp-scheme', default='https', help='Scheme for relative Burp raw requests')
    ss.add_argument('--pre-auth-check', action='store_true', help='Run JWT/Auth negative tests before scan')
    ss.add_argument('--export', help='Comma-separated formats: html,pdf,json,sarif')
    ss.set_defaults(func=cmd_scan)

    se = sub.add_parser('export')
    se.add_argument('--run-id', type=int, required=True)
    se.add_argument('--formats', default='html,pdf,json,sarif')
    se.set_defaults(func=cmd_export)

    sc = sub.add_parser('compare', help='Baseline compare between two runs')
    sc.add_argument('--baseline-run-id', type=int, required=True)
    sc.add_argument('--candidate-run-id', type=int, required=True)
    sc.add_argument('--as-json', action='store_true')
    sc.set_defaults(func=cmd_compare)

    sa = sub.add_parser('auth-check', help='JWT/Auth negative tests for an LLM endpoint or saved target')
    group = sa.add_mutually_exclusive_group(required=True)
    group.add_argument('--target-id', type=int, help='Saved target ID from local DB')
    group.add_argument('--url', help='Direct endpoint URL')
    sa.add_argument('--method', default='POST')
    sa.add_argument('--headers-json', help='Extra headers JSON')
    sa.add_argument('--body-json', help='JSON request body')
    sa.add_argument('--timeout', type=int, default=15)
    sa.add_argument('--output', help='Save JSON result')
    sa.set_defaults(func=cmd_auth_check)

    sbp = sub.add_parser('burp-parse', help='Parse Burp raw HTTP request and infer target')
    sbp.add_argument('--raw', required=True, help='Path to raw request text')
    sbp.add_argument('--scheme', default='https')
    sbp.add_argument('--infer-target', action='store_true')
    sbp.add_argument('--output')
    sbp.set_defaults(func=cmd_burp_parse)

    sbl = sub.add_parser('list-connectors', help='List built-in connector templates')
    sbl.set_defaults(func=cmd_list_connectors)

    sbrd = sub.add_parser('burp-replay-diff', help='Replay baseline vs attacked requests and show unified diff')
    sbrd.add_argument('--baseline', required=True)
    sbrd.add_argument('--attacked', required=True)
    sbrd.add_argument('--scheme', default='https')
    sbrd.add_argument('--allow-auth', action='store_true')
    sbrd.add_argument('--timeout', type=int, default=20)
    sbrd.add_argument('--output')
    sbrd.set_defaults(func=cmd_burp_replay_diff)

    sbr = sub.add_parser('burp-replay', help='Replay Burp raw HTTP request safely (auth stripped by default)')
    sbr.add_argument('--raw', required=True)
    sbr.add_argument('--scheme', default='https')
    sbr.add_argument('--allow-auth', action='store_true', help='Replay with original Authorization header')
    sbr.add_argument('--timeout', type=int, default=20)
    sbr.add_argument('--output')
    sbr.set_defaults(func=cmd_burp_replay)

    sbt = sub.add_parser('burp-create-target', help='Create a saved target from Burp raw HTTP request')
    sbt.add_argument('--project-id', type=int, required=True)
    sbt.add_argument('--raw', required=True)
    sbt.add_argument('--scheme', default='https')
    sbt.add_argument('--name', help='Override target name')
    sbt.set_defaults(func=cmd_burp_create_target)

    sbx = sub.add_parser('burp-parse-export', help='Parse Burp XML/JSON/HAR export into normalized request items')
    sbx.add_argument('--path', required=True)
    sbx.add_argument('--full', action='store_true')
    sbx.add_argument('--output')
    sbx.set_defaults(func=cmd_burp_parse_export)

    sbs = sub.add_parser('burp-serve', help='Run local ingest bridge for Burp extension stub')
    sbs.add_argument('--host', default='127.0.0.1')
    sbs.add_argument('--port', type=int, default=8765)
    sbs.add_argument('--out-dir', default='burp_ingest')
    sbs.set_defaults(func=cmd_burp_serve)


    sfp = sub.add_parser('fingerprint-endpoint', help='Offline connector/auth fingerprinting for unknown LLM/chat endpoints')
    sfp.add_argument('--url', required=True)
    sfp.add_argument('--method', default='POST')
    sfp.add_argument('--headers-json', help='Headers JSON (include Cookie/Authorization if applicable)')
    sfp.add_argument('--body-json', help='Example request body JSON')
    sfp.add_argument('--body-file', help='Example raw body file')
    sfp.add_argument('--output')
    sfp.set_defaults(func=cmd_fingerprint_endpoint)

    swp = sub.add_parser('webchat-probe', help='Probe a chat web UI and suggest Playwright selectors')
    swp.add_argument('--url', required=True)
    swp.add_argument('--headers-json', help='Optional headers JSON (Cookie can be read from here)')
    swp.add_argument('--cookie-header', help='Cookie header string (session/SSO)')
    swp.add_argument('--timeout', type=int, default=20)
    swp.add_argument('--show-browser', action='store_true', help='Run Playwright headed for debugging')
    swp.add_argument('--output')
    swp.set_defaults(func=cmd_webchat_probe)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
