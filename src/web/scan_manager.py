"""
后台扫描任务管理器。

职责：
  - 在后台线程中运行 Coordinator Pipeline
  - 通过 queue.Queue 实时推送 SSE 事件到前端
  - 拦截 logging 日志转发为 SSE 消息
"""

from __future__ import annotations

import json
import logging
import queue
import shutil
import threading
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class _QueueLogHandler(logging.Handler):
    """将日志消息转发到 SSE 事件队列。"""

    def __init__(self, q: queue.Queue):
        super().__init__(level=logging.INFO)
        self._q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._q.put({
                "event": "log",
                "data": {
                    "level": record.levelname.lower(),
                    "message": self.format(record),
                    "timestamp": datetime.now().isoformat(),
                    "logger": record.name,
                },
            })
        except Exception:
            pass


class ScanTask:
    """单次扫描任务的状态容器。"""

    def __init__(self, task_id: str, config: dict):
        self.task_id = task_id
        self.config = config
        self.event_queue: queue.Queue = queue.Queue()
        self.status = "pending"
        self.result_file: Optional[str] = None
        self.error: Optional[str] = None
        self.started_at = datetime.now().isoformat()


class ScanManager:
    """管理多个扫描任务的生命周期。"""

    def __init__(self):
        self._tasks: dict[str, ScanTask] = {}
        self._lock = threading.Lock()

    def start_scan(self, config: dict) -> str:
        task_id = uuid.uuid4().hex[:12]
        task = ScanTask(task_id, config)
        with self._lock:
            self._tasks[task_id] = task
        t = threading.Thread(target=self._run_scan, args=(task,), daemon=True)
        t.start()
        return task_id

    def get_event_queue(self, task_id: str) -> Optional[queue.Queue]:
        task = self._tasks.get(task_id)
        return task.event_queue if task else None

    def get_status(self, task_id: str) -> Optional[dict]:
        task = self._tasks.get(task_id)
        if not task:
            return None
        return {
            "task_id": task.task_id,
            "status": task.status,
            "result_file": task.result_file,
            "error": task.error,
            "started_at": task.started_at,
        }

    def _push(self, task: ScanTask, event: str, data: dict):
        task.event_queue.put({"event": event, "data": data})

    def _run_scan(self, task: ScanTask):
        handler = _QueueLogHandler(task.event_queue)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)

        try:
            task.status = "running"
            cfg = task.config
            language = cfg.get("language", "java")
            vuln_types = cfg.get("vuln_types", [])
            if not vuln_types:
                vuln_types = [cfg.get("vuln_type", "sql injection")]

            from src.orchestrator.coordinator import Coordinator, PipelineConfig

            base_config = PipelineConfig(
                language=language,
                vuln_type=vuln_types[0],
                source_dir=cfg.get("source_dir"),
                github_url=cfg.get("github_url"),
                sink_hints=cfg.get("sink_hints"),
                max_retries=int(cfg.get("max_retries", 3)),
                enable_agent_r=cfg.get("enable_agent_r", True),
                enable_agent_t=cfg.get("enable_agent_t", False),
                enable_agent_s=cfg.get("enable_agent_s", True),
                enable_agent_e=cfg.get("enable_agent_e", True),
                agent_e_host=cfg.get("agent_e_host"),
                enable_rule_memory=cfg.get("enable_rule_memory", True),
                build_mode="none" if cfg.get("no_build") else "",
                agent_r_min_confidence=float(cfg.get("min_confidence", 0.5)),
                prompt_preset="generic" if cfg.get("force_generic_prompt") else cfg.get("prompt_preset", ""),
                agent_r_context_lines=int(cfg.get("agent_r_context_lines", 30)),
                enable_code_browser=cfg.get("enable_code_browser", True),
            )

            self._push(task, "phase_start", {"phase": "pipeline", "total": len(vuln_types)})

            if len(vuln_types) > 1:
                states = Coordinator.run_parallel(
                    base_config=base_config,
                    vuln_types=vuln_types,
                    max_workers=int(cfg.get("parallel_workers", 3)),
                )
            else:
                coord = Coordinator(config=base_config)
                states = [coord.run()]

            # 推送审查摘要
            total_v = sum(len(s.vulnerable_findings) for s in states)
            self._push(task, "intermediate", {
                "type": "review_summary",
                "vulnerable": total_v,
                "total_findings": sum(
                    len(s.review_results) for s in states if s.review_results
                ),
            })

            # 导出报告
            from src.utils.result_exporter import export_json
            results_dir = _PROJECT_ROOT / "data" / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            report_name = f"web_{task.task_id}_report.json"
            report_path = str(results_dir / report_name)
            export_json(states, report_path, language=language)

            task.result_file = report_name
            task.status = "completed"
            self._push(task, "complete", {
                "status": "success",
                "result_file": report_name,
            })

        except Exception as exc:
            task.status = "error"
            task.error = str(exc)
            self._push(task, "error", {"message": str(exc)})
            logger.exception("Scan task %s failed", task.task_id)
        finally:
            root_logger.removeHandler(handler)
            task.event_queue.put(None)


# ---------------------------------------------------------------------------
# 消融实验套件
# ---------------------------------------------------------------------------

_ABLATION_VARIANTS = [
    {"name": "full",              "label": "Full QRSE-X",       "enable_code_browser": True,  "prompt_preset": "",        "skip_agent_r": False},
    {"name": "no_agent_r",        "label": "w/o Agent-R",       "enable_code_browser": True,  "prompt_preset": "",        "skip_agent_r": True},
    {"name": "no_codebrowser",    "label": "w/o CodeBrowser",   "enable_code_browser": False, "prompt_preset": "",        "skip_agent_r": False},
    {"name": "no_rag",            "label": "w/o RAG",           "enable_code_browser": True,  "prompt_preset": "",        "skip_agent_r": "copy_full"},
    {"name": "no_prompt_tuning",  "label": "w/o Prompt Tuning", "enable_code_browser": True,  "prompt_preset": "generic", "skip_agent_r": False},
]


class AblationSuite:
    """一键消融实验的状态容器。"""

    def __init__(self, suite_id: str, config: dict):
        self.suite_id = suite_id
        self.config = config
        self.event_queue: queue.Queue = queue.Queue()
        self.status = "pending"
        self.started_at = datetime.now().isoformat()
        self.tasks: list[dict] = []
        for v in _ABLATION_VARIANTS:
            self.tasks.append({
                "name": v["name"],
                "label": v["label"],
                "status": "pending",
                "output_sarif": "",
                "score_file": "",
                "score": None,
                "error": None,
            })

    def to_dict(self) -> dict:
        return {
            "suite_id": self.suite_id,
            "status": self.status,
            "started_at": self.started_at,
            "tasks": self.tasks,
        }


def _patch_scan_manager():
    """给 ScanManager 追加消融实验方法（避免重写整个类）。"""

    _orig_init = ScanManager.__init__

    def _new_init(self):
        _orig_init(self)
        self._ablation_suites: dict[str, AblationSuite] = {}

    ScanManager.__init__ = _new_init

    def start_ablation(self, config: dict) -> str:
        suite_id = "abl_" + uuid.uuid4().hex[:10]
        suite = AblationSuite(suite_id, config)
        with self._lock:
            self._ablation_suites[suite_id] = suite
        t = threading.Thread(target=self._run_ablation, args=(suite,), daemon=True)
        t.start()
        return suite_id

    def get_ablation_suite(self, suite_id: str) -> Optional[AblationSuite]:
        return self._ablation_suites.get(suite_id)

    def _push_abl(self, suite: AblationSuite, event: str, data: dict):
        suite.event_queue.put({"event": event, "data": data})

    def _run_ablation(self, suite: AblationSuite):
        handler = _QueueLogHandler(suite.event_queue)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)

        try:
            suite.status = "running"
            cfg = suite.config
            base_sarif = str(_PROJECT_ROOT / cfg["base_sarif"])
            repo_dir = str(_PROJECT_ROOT / cfg["repo_dir"])
            expected_csv = str(_PROJECT_ROOT / cfg.get(
                "expected_csv",
                "data/benchmark/BenchmarkJava/expectedresults-1.2.csv",
            ))
            language = cfg.get("language", "java")
            benchmark_type = cfg.get("benchmark_type", "owasp")
            workers = int(cfg.get("workers", 4))
            batch = int(cfg.get("batch", 10))

            results_dir = _PROJECT_ROOT / "data" / "results"
            results_dir.mkdir(parents=True, exist_ok=True)

            from src.agents.agent_r import AgentR, VulnStatus
            from scripts.score_benchmark import (
                parse_expected_csv, parse_sarif_findings, compute_score, save_json,
            )

            expected = parse_expected_csv(expected_csv, benchmark_type=benchmark_type)
            full_output_sarif = ""

            for idx, variant in enumerate(_ABLATION_VARIANTS):
                task = suite.tasks[idx]
                task_name = variant["name"]
                task["status"] = "running"
                self._push_abl(suite, "task_update", {"index": idx, "status": "running", "label": task["label"]})
                logger.info("[Ablation] ===== %s (%s) =====", task["label"], task_name)

                output_sarif = str(results_dir / f"ablation_{suite.suite_id}_{task_name}.sarif")
                _prefix = {"owasp": "benchmark", "juliet": "juliet",
                           "cvebench": "cvebench", "custom": "custom"}.get(benchmark_type, "benchmark")
                score_file = str(results_dir / f"{_prefix}_score_ablation_{task_name}.json")

                try:
                    if variant["skip_agent_r"] is True:
                        shutil.copy2(base_sarif, output_sarif)
                        logger.info("[Ablation] %s: 跳过 Agent-R，直接使用原始 SARIF", task_name)

                    elif variant["skip_agent_r"] == "copy_full":
                        if full_output_sarif and Path(full_output_sarif).exists():
                            shutil.copy2(full_output_sarif, output_sarif)
                            logger.info("[Ablation] %s: 复用 Full 的 Agent-R 结果", task_name)
                        else:
                            shutil.copy2(base_sarif, output_sarif)
                            logger.info("[Ablation] %s: Full 未完成，退化为原始 SARIF", task_name)

                    else:
                        # 需要跑 Agent-R（full / no_codebrowser / no_prompt_tuning）
                        agent_r = AgentR(enable_code_browser=variant["enable_code_browser"])
                        results = agent_r.review(
                            sarif_path=base_sarif,
                            repo_root=repo_dir,
                            language=language,
                            parallel_workers=workers,
                            batch_size=batch,
                            prompt_preset=variant["prompt_preset"],
                        )

                        keep_locs: set[tuple[str, int]] = set()
                        for r in results:
                            if r.status != VulnStatus.SAFE:
                                keep_locs.add((r.finding.file_uri, r.finding.start_line))

                        raw = json.loads(Path(base_sarif).read_text(encoding="utf-8"))
                        out = json.loads(json.dumps(raw))
                        for run in out.get("runs", []):
                            orig = run.get("results", [])
                            run["results"] = [
                                res for res in orig
                                if _sarif_loc(res) in keep_locs
                            ]
                        Path(output_sarif).write_text(
                            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8",
                        )
                        kept = sum(len(r.get("results", [])) for r in out.get("runs", []))
                        logger.info("[Ablation] %s: Agent-R 完成，保留 %d 条", task_name, kept)

                    # 记录 full 的输出路径供 no_rag 复用
                    if task_name == "full":
                        full_output_sarif = output_sarif

                    findings = parse_sarif_findings(output_sarif, benchmark_type=benchmark_type)
                    seen: set[tuple[str, str]] = set()
                    deduped = [f for f in findings if (f.test_name, f.category) not in seen and not seen.add((f.test_name, f.category))]
                    score = compute_score(expected, deduped)
                    score.sarif_files = 1
                    save_json(score, score_file, benchmark_type=benchmark_type)

                    task["output_sarif"] = output_sarif
                    task["score_file"] = score_file
                    task["score"] = {
                        "tp": score.overall_tp, "fp": score.overall_fp,
                        "tn": score.overall_tn, "fn": score.overall_fn,
                        "precision": round(score.overall_precision, 4),
                        "recall": round(score.overall_recall, 4),
                        "f1": round(score.overall_f1, 4),
                        "fpr": round(score.overall_fpr, 4),
                        "youden": round(score.overall_youden, 4),
                    }
                    task["status"] = "completed"
                    logger.info(
                        "[Ablation] %s 评分: F1=%.3f  Youden=%+.3f  TP=%d FP=%d",
                        task_name, score.overall_f1, score.overall_youden,
                        score.overall_tp, score.overall_fp,
                    )
                    self._push_abl(suite, "task_update", {
                        "index": idx, "status": "completed",
                        "label": task["label"], "score": task["score"],
                    })

                except Exception as exc:
                    task["status"] = "error"
                    task["error"] = str(exc)
                    logger.exception("[Ablation] %s 失败: %s", task_name, exc)
                    self._push_abl(suite, "task_update", {
                        "index": idx, "status": "error",
                        "label": task["label"], "error": str(exc),
                    })

            suite.status = "completed"
            self._push_abl(suite, "complete", {"status": "success"})
            logger.info("[Ablation] ===== 全部消融实验完成 =====")

        except Exception as exc:
            suite.status = "error"
            logger.exception("[Ablation] Suite 失败: %s", exc)
            self._push_abl(suite, "error", {"message": str(exc)})
        finally:
            root_logger.removeHandler(handler)
            suite.event_queue.put(None)

    ScanManager.start_ablation = start_ablation
    ScanManager.get_ablation_suite = get_ablation_suite
    ScanManager._push_abl = _push_abl
    ScanManager._run_ablation = _run_ablation


def _sarif_loc(res: dict) -> tuple[str, int]:
    """从 SARIF result 中提取 (uri, line)。"""
    locs = res.get("locations", [])
    if not locs:
        return ("", 0)
    pl = locs[0].get("physicalLocation", {})
    uri = pl.get("artifactLocation", {}).get("uri", "")
    line = pl.get("region", {}).get("startLine", 0)
    return (uri, line)


_patch_scan_manager()
