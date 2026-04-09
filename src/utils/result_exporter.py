"""
结果导出模块：将 Pipeline 执行结果序列化为 JSON 报告。

输出文件可被：
  - 下游 CI/CD 系统消费（按 findings.[] 条目告警）
  - 安全平台批量导入
  - 前端渲染扫描报告（Phase 7 Web UI 预留）

JSON schema 概览：
{
  "meta": {
    "generated_at": "ISO8601",
    "tool": "Argus",
    "version": "2.4.0",
    "language": "java",
    "total_runs": N,
    "total_vulnerabilities": N
  },
  "runs": [
    {
      "run_id": "...",
      "vuln_type": "Spring EL Injection",
      "status": "success" | "failed",
      "error": null | "...",
      "source_dir": "...",
      "db_path": "...",
      "db_from_cache": false,
      "query_path": "...",
      "sarif_path": "...",
      "completed_phases": [...],
      "findings": [
        {
          "status": "vulnerable" | "safe" | "uncertain",
          "confidence": 0.85,
          "engine_detected": "Spring EL",
          "reasoning": "...",
          "sink_method": "...",
          "file": "...",
          "line": 42,
          "message": "...",
          "poc": { ... } | null
        }
      ]
    }
  ]
}
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

_TOOL_NAME = "Argus"
_TOOL_VERSION = "2.4.0"


# ---------------------------------------------------------------------------
# 序列化辅助
# ---------------------------------------------------------------------------


def _serialize_finding(review_result: Any, poc_result: Any = None) -> dict:
    """将单条 ReviewResult（+ 可选 PoCResult）转换为字典。"""
    f = review_result.finding
    poc_dict = None
    if poc_result is not None:
        poc_dict = {
            "payloads": poc_result.payloads,
            "http_trigger": poc_result.http_trigger,
            "expected_output": poc_result.expected_output,
            "severity": poc_result.severity,
        }
    return {
        "status": review_result.status.value,
        "confidence": round(review_result.confidence, 4),
        "engine_detected": review_result.engine_detected,
        "reasoning": review_result.reasoning,
        "sink_method": review_result.sink_method,
        "file": f.file_uri,
        "line": f.start_line,
        "rule_id": f.rule_id,
        "message": f.message,
        "code_context": f.code_context,
        "poc": poc_dict,
    }


def _serialize_state(state: "PipelineState") -> dict:
    """将单个 PipelineState 转换为字典。"""
    # 构建 file_uri → PoCResult 映射，用于关联 finding 与 poc
    poc_map: dict[tuple, Any] = {}
    for poc in state.poc_results:
        # poc.file_location 格式为 "file_uri:line"
        key = poc.file_location
        poc_map[key] = poc

    findings = []
    for review in state.review_results:
        file_uri = review.finding.file_uri
        line = review.finding.start_line
        poc_key = f"{file_uri}:{line}"
        poc = poc_map.get(poc_key)
        findings.append(_serialize_finding(review, poc))

    return {
        "run_id": state.run_id,
        "vuln_type": state.vuln_type,
        "status": "failed" if state.error else "success",
        "error": state.error,
        "source_dir": state.source_dir,
        "db_path": state.db_path,
        "db_from_cache": state.db_from_cache,
        "commit_hash": state.commit_hash,
        "build_command": state.build_command,
        "query_path": state.query_path,
        "sarif_path": state.sarif_path,
        "completed_phases": state.completed_phases,
        "findings": findings,
        "stats": {
            "total_findings": len(state.review_results),
            "vulnerable": len(state.vulnerable_findings),
            "safe": sum(
                1 for r in state.review_results
                if r.status.value == "safe"
            ),
            "uncertain": sum(
                1 for r in state.review_results
                if r.status.value == "uncertain"
            ),
            "poc_generated": len(state.poc_results),
        },
    }


# ---------------------------------------------------------------------------
# 主导出函数
# ---------------------------------------------------------------------------


def export_json(
    states: "list[PipelineState]",
    output_path: str,
    language: str = "",
    codebase_type: str = "",
) -> str:
    """
    将一个或多个 PipelineState 导出为 JSON 报告文件。

    Args:
        states: Pipeline 执行结果列表（单次或并行扫描均支持）。
        output_path: 输出文件路径（自动创建父目录）。
        language: 扫描目标语言（填入 meta 字段）。

    Returns:
        实际写入的文件路径字符串。

    Raises:
        OSError: 写入文件失败时抛出。
    """
    total_vuln = sum(len(s.vulnerable_findings) for s in states)
    meta: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": _TOOL_NAME,
        "version": _TOOL_VERSION,
        "language": language,
        "total_runs": len(states),
        "total_vulnerabilities": total_vuln,
    }
    if codebase_type:
        meta["codebase_type"] = codebase_type
    report = {
        "meta": meta,
        "runs": [_serialize_state(s) for s in states],
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    logger.info(
        "[ResultExporter] JSON 报告已写入: %s （%d 条发现，%d 处确认漏洞）",
        out, sum(len(s.review_results) for s in states), total_vuln,
    )
    return str(out)


def export_summary_text(states: "list[PipelineState]") -> str:
    """
    生成纯文本格式的摘要（不依赖 rich），可用于邮件或日志告警。

    Args:
        states: Pipeline 执行结果列表。

    Returns:
        格式化的文本摘要字符串。
    """
    lines: list[str] = [
        "=" * 60,
        f"  Argus 扫描摘要  ({datetime.now().strftime('%Y-%m-%d %H:%M')})",
        "=" * 60,
    ]
    for state in states:
        lines.append(f"\n  漏洞类型: {state.vuln_type}")
        if state.error:
            lines.append(f"  状态: 失败 - {state.error}")
            continue
        lines.append(f"  状态: 成功")
        lines.append(f"  SARIF: {state.sarif_path}")
        lines.append(f"  发现总计: {len(state.review_results)} 条")
        vuln_cnt = len(state.vulnerable_findings)
        lines.append(f"  确认漏洞: {vuln_cnt} 处")
        for r in state.vulnerable_findings:
            lines.append(
                f"    - {r.finding.file_uri}:{r.finding.start_line}"
                f"  ({r.engine_detected}, {r.confidence:.0%})"
            )

    total_vuln = sum(len(s.vulnerable_findings) for s in states)
    lines += [
        "",
        f"  总计确认漏洞: {total_vuln} 处",
        "=" * 60,
    ]
    return "\n".join(lines)
