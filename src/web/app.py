"""
QRSE-X Web Dashboard — Flask 应用入口。

启动方式:
    python -m src.web.app            # 默认 127.0.0.1:5000
    python -m src.web.app --port 8080
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
)

from src.utils.ql_template_library import QLTemplateLibrary, _ALL_TEMPLATES
from src.utils.rule_memory import RuleMemory
from src.utils.vuln_catalog import VULN_CATALOG
from src.web.scan_manager import ScanManager

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_RESULTS_DIR = _PROJECT_ROOT / "data" / "results"
_RULE_MEMORY_DIR = str(_PROJECT_ROOT / "data" / "rule_memory")

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "qrse-x-dev-key")

scan_manager = ScanManager()


# ---------------------------------------------------------------------------
# 页面路由
# ---------------------------------------------------------------------------

@app.route("/")
def page_dashboard():
    return render_template("dashboard.html")


@app.route("/scan")
def page_scan():
    return render_template("scan.html")


@app.route("/results/<path:filename>")
def page_result_detail(filename: str):
    return render_template("results.html", filename=filename)


@app.route("/templates")
def page_templates():
    return render_template("templates.html")


@app.route("/memory")
def page_memory():
    return render_template("memory.html")


# ---------------------------------------------------------------------------
# API — 扫描
# ---------------------------------------------------------------------------

@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    payload = request.get_json(force=True)
    task_id = scan_manager.start_scan(payload)
    return jsonify({"task_id": task_id})


@app.route("/api/scan/stream/<task_id>")
def api_scan_stream(task_id: str):
    def _generate():
        q = scan_manager.get_event_queue(task_id)
        if q is None:
            yield f"event: error\ndata: {json.dumps({'message': 'task not found'})}\n\n"
            return
        while True:
            evt = q.get()
            if evt is None:
                break
            yield f"event: {evt['event']}\ndata: {json.dumps(evt['data'], ensure_ascii=False)}\n\n"

    return Response(_generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/status/<task_id>")
def api_scan_status(task_id: str):
    status = scan_manager.get_status(task_id)
    if status is None:
        return jsonify({"error": "task not found"}), 404
    return jsonify(status)


# ---------------------------------------------------------------------------
# API — 历史结果
# ---------------------------------------------------------------------------

@app.route("/api/results")
def api_results_list():
    results: list[dict[str, Any]] = []
    if _RESULTS_DIR.exists():
        for f in sorted(_RESULTS_DIR.glob("*_report.json"), reverse=True):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                meta = data.get("meta", {})
                runs = data.get("runs", [])
                total_vulns = sum(
                    r.get("stats", {}).get("vulnerable", 0) for r in runs
                )
                results.append({
                    "filename": f.name,
                    "generated_at": meta.get("generated_at", ""),
                    "language": meta.get("language", ""),
                    "total_runs": meta.get("total_runs", len(runs)),
                    "total_vulnerabilities": total_vulns,
                    "vuln_types": [r.get("vuln_type", "") for r in runs],
                })
            except Exception:
                pass
    return jsonify(results)


@app.route("/api/results/<path:filename>")
def api_result_detail(filename: str):
    fpath = _RESULTS_DIR / filename
    if not fpath.exists():
        return jsonify({"error": "not found"}), 404
    return jsonify(json.loads(fpath.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# API — 黄金模板库
# ---------------------------------------------------------------------------

@app.route("/api/templates")
def api_templates():
    templates = []
    for t in _ALL_TEMPLATES:
        templates.append({
            "key": t.key,
            "language": t.language,
            "vuln_type": t.vuln_type,
            "name": t.vuln_type,
            "description": t.description,
            "ql_code": t.code,
            "cwe": "",
        })
    return jsonify({"templates": templates})


@app.route("/api/templates/test", methods=["POST"])
def api_templates_test():
    payload = request.get_json(force=True)
    lang = payload.get("language", "")
    kw = payload.get("keyword", "")
    if not lang or not kw:
        return jsonify({"matched": False, "reason": "missing params"})
    tmpl = QLTemplateLibrary.find(lang, kw)
    if tmpl:
        return jsonify({
            "matched": True,
            "template": {
                "key": tmpl.key,
                "vuln_type": tmpl.vuln_type,
                "description": tmpl.description,
                "ql_code": tmpl.code,
                "cwe": "",
            },
        })
    return jsonify({"matched": False, "reason": "no template matched"})


# ---------------------------------------------------------------------------
# API — 规则记忆库
# ---------------------------------------------------------------------------

def _get_memory() -> RuleMemory:
    return RuleMemory(memory_dir=_RULE_MEMORY_DIR)


@app.route("/api/memory")
def api_memory_list():
    mem = _get_memory()
    records = []
    for rec in mem._records.values():
        records.append(asdict(rec))
    records.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    trust_stats = mem.get_trust_stats()
    return jsonify({
        "total": mem.count(),
        "backend": mem.get_backend_name(),
        "records": records,
        "trust_stats": trust_stats,
    })


@app.route("/api/memory/search", methods=["POST"])
def api_memory_search():
    payload = request.get_json(force=True)
    query = payload.get("query", "")
    lang = payload.get("language", "")
    top_k = int(payload.get("top_k", 5))
    if not query:
        return jsonify({"results": []})
    mem = _get_memory()
    hits = mem.search(language=lang or "java", vuln_type=query, top_k=top_k)
    results = []
    for rec, score in hits:
        d = asdict(rec)
        d["score"] = round(score, 4)
        results.append(d)
    return jsonify({"results": results})


@app.route("/api/memory/<rule_id>/code")
def api_memory_code(rule_id: str):
    mem = _get_memory()
    rec = mem._records.get(rule_id)
    if not rec:
        return jsonify({"error": "not found"}), 404
    try:
        code = mem.load_query_code(rec)
        return jsonify({"ql_code": code})
    except FileNotFoundError:
        return jsonify({"error": "ql file missing"}), 404


@app.route("/api/memory/export")
def api_memory_export():
    mem = _get_memory()
    tmp = Path(tempfile.mkdtemp()) / "rule_memory_bundle.zip"
    mem.export_bundle(str(tmp))
    return send_file(str(tmp), as_attachment=True, download_name="rule_memory_bundle.zip")


@app.route("/api/memory/import", methods=["POST"])
def api_memory_import():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400
    f = request.files["file"]
    tmp = Path(tempfile.mkdtemp()) / f.filename
    f.save(str(tmp))
    mem = _get_memory()
    merge = request.form.get("merge", "true").lower() == "true"
    imported = mem.import_bundle(str(tmp), merge=merge)
    return jsonify({"imported": imported})


@app.route("/api/memory/clear", methods=["POST"])
def api_memory_clear():
    import shutil
    mem_dir = Path(_RULE_MEMORY_DIR)
    if mem_dir.exists():
        shutil.rmtree(mem_dir)
    return jsonify({"status": "cleared"})


@app.route("/api/memory/<rule_id>/verify", methods=["POST"])
def api_memory_verify(rule_id: str):
    payload = request.get_json(force=True)
    mem = _get_memory()
    ok = mem.verify(
        rule_id,
        verified_by=payload.get("verified_by", "web_ui"),
        promote_to=payload.get("promote_to", "verified"),
    )
    if not ok:
        return jsonify({"error": "record not found"}), 404
    return jsonify({"status": "verified", "rule_id": rule_id})


@app.route("/api/memory/<rule_id>/quarantine", methods=["POST"])
def api_memory_quarantine(rule_id: str):
    payload = request.get_json(force=True)
    mem = _get_memory()
    ok = mem.quarantine(rule_id, reason=payload.get("reason", "web_ui"))
    if not ok:
        return jsonify({"error": "record not found"}), 404
    return jsonify({"status": "quarantined", "rule_id": rule_id})


@app.route("/api/memory/integrity", methods=["GET"])
def api_memory_integrity():
    mem = _get_memory()
    result = mem.verify_all_integrity()
    return jsonify(result)


@app.route("/api/memory/trust-stats", methods=["GET"])
def api_memory_trust_stats():
    mem = _get_memory()
    return jsonify(mem.get_trust_stats())


# ---------------------------------------------------------------------------
# API — 系统
# ---------------------------------------------------------------------------

@app.route("/api/system/health")
def api_system_health():
    import subprocess
    codeql_version = "unknown"
    try:
        r = subprocess.run(
            ["codeql", "version"], capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            codeql_version = r.stdout.strip().splitlines()[0]
    except Exception:
        pass

    mem = _get_memory()
    return jsonify({
        "codeql_version": codeql_version,
        "template_count": len(_ALL_TEMPLATES),
        "memory_count": mem.count(),
        "memory_backend": mem.get_backend_name(),
        "languages": ["java", "python", "javascript", "go", "csharp", "cpp"],
    })


@app.route("/api/vuln-catalog")
def api_vuln_catalog():
    entries = []
    for e in VULN_CATALOG:
        entries.append({
            "name": e.name,
            "cwe": e.cwe,
            "cwe_desc": e.cwe_desc,
            "category": e.category,
            "keywords": list(e.keywords),
        })
    return jsonify(entries)


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="QRSE-X Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    logger.info("QRSE-X Dashboard starting at http://%s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
