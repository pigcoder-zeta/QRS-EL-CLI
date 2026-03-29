"""
扫描历史记录模块。

每次 Pipeline 执行后自动将摘要写入 data/scan_history.json，
支持查询历史、对比趋势、断点续扫等场景。

文件格式（JSON Lines 兼容的 JSON Array）：
[
  {
    "run_id": "20260323_142301_a1b2c3",
    "timestamp": "2026-03-23T14:23:01+00:00",
    "language": "java",
    "vuln_types": ["Spring EL Injection"],
    "source": "https://github.com/WebGoat/WebGoat",
    "commit_hash": "abc1234",
    "status": "success",
    "phases_completed": ["clone_repo", "create_database", ...],
    "db_from_cache": false,
    "total_findings": 3,
    "vulnerable": 2,
    "poc_generated": 2,
    "sarif_path": "data/results/results_xxx.sarif",
    "query_path": "data/queries/java/xxx.ql",
    "duration_hint": "（运行时长由调用方填充）"
  },
  ...
]
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.orchestrator.coordinator import PipelineState

logger = logging.getLogger(__name__)

_HISTORY_FILENAME = "scan_history.json"
_MAX_HISTORY_ENTRIES = 500   # 超过此数量时滚动删除最旧条目


class ScanHistory:
    """
    扫描历史记录管理器。

    Args:
        history_dir: 历史文件所在目录（默认 data/）。
    """

    def __init__(self, history_dir: str = "data") -> None:
        self.history_path = Path(history_dir) / _HISTORY_FILENAME
        self._entries: list[dict[str, Any]] = []
        self._load()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self.history_path.exists():
            return
        try:
            with open(self.history_path, encoding="utf-8") as fh:
                self._entries = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            logger.warning("扫描历史文件损坏，重置: %s", exc)
            self._entries = []

    def _save(self) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        # 滚动：保留最新 N 条
        if len(self._entries) > _MAX_HISTORY_ENTRIES:
            self._entries = self._entries[-_MAX_HISTORY_ENTRIES:]
        with open(self.history_path, "w", encoding="utf-8") as fh:
            json.dump(self._entries, fh, ensure_ascii=False, indent=2)

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    def record(
        self,
        states: "list[PipelineState]",
        language: str,
        source: str = "",
        elapsed_seconds: float = 0.0,
    ) -> None:
        """
        将本次扫描的所有 PipelineState 写入历史记录。

        Args:
            states: Pipeline 执行结果列表。
            language: 目标语言。
            source: 源码来源（URL 或本地路径）。
            elapsed_seconds: 本次扫描总耗时（秒），0 表示未知。
        """
        ts = datetime.now(timezone.utc).isoformat()
        for state in states:
            entry: dict[str, Any] = {
                "run_id":          state.run_id,
                "timestamp":       ts,
                "language":        language,
                "vuln_type":       state.vuln_type,
                "source":          source,
                "commit_hash":     state.commit_hash,
                "status":          "failed" if state.error else "success",
                "error":           state.error,
                "phases_completed": state.completed_phases,
                "db_from_cache":   state.db_from_cache,
                "total_findings":  len(state.review_results),
                "vulnerable":      len(state.vulnerable_findings),
                "poc_generated":   len(state.poc_results),
                "sarif_path":      state.sarif_path,
                "query_path":      state.query_path,
                "elapsed_seconds": round(elapsed_seconds, 1),
            }
            self._entries.append(entry)

        self._save()
        logger.info(
            "[ScanHistory] 已记录 %d 条扫描结果到 %s",
            len(states), self.history_path,
        )

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def recent(self, n: int = 10) -> list[dict[str, Any]]:
        """返回最近 n 条历史记录（时间倒序）。"""
        return list(reversed(self._entries[-n:]))

    def stats(self) -> dict[str, Any]:
        """返回历史统计摘要。"""
        if not self._entries:
            return {"total_runs": 0}

        total = len(self._entries)
        success = sum(1 for e in self._entries if e.get("status") == "success")
        total_vuln = sum(e.get("vulnerable", 0) for e in self._entries)
        cache_hits = sum(1 for e in self._entries if e.get("db_from_cache"))
        lang_counts: dict[str, int] = {}
        for e in self._entries:
            lang = e.get("language", "unknown")
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        return {
            "total_runs": total,
            "success_runs": success,
            "failed_runs": total - success,
            "total_vulnerabilities_found": total_vuln,
            "db_cache_hits": cache_hits,
            "languages": lang_counts,
            "history_file": str(self.history_path),
        }

    def count(self) -> int:
        return len(self._entries)
