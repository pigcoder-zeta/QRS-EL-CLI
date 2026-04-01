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
                enable_agent_s=cfg.get("enable_agent_s", True),
                enable_agent_e=cfg.get("enable_agent_e", True),
                agent_e_host=cfg.get("agent_e_host"),
                enable_rule_memory=cfg.get("enable_rule_memory", True),
                build_mode="none" if cfg.get("no_build") else "",
                agent_r_min_confidence=float(cfg.get("min_confidence", 0.5)),
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
