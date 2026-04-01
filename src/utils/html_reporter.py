"""
HTML 扫描报告生成器。

生成一份自包含（无外部依赖）的 HTML 报告，包含：
- 扫描总览（语言、时间、发现统计）
- 每种漏洞类型的发现列表（颜色区分风险等级）
- Agent-R 审查结论与置信度
- Agent-S PoC 详细信息（Payload、HTTP 触发步骤）
- 原始 SARIF 路径链接

报告使用纯 HTML+CSS+内联 JS，无需网络连接即可在浏览器中正常显示。
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.orchestrator.coordinator import PipelineState

_TOOL_VERSION = "0.5.0"


# ---------------------------------------------------------------------------
# CSS 样式（内联，无外部依赖）
# ---------------------------------------------------------------------------

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f1117; color: #e2e8f0; line-height: 1.6;
}
.container { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
header {
    background: linear-gradient(135deg, #1a1f2e 0%, #161b27 100%);
    border-bottom: 1px solid #2d3748; padding: 24px 0; margin-bottom: 32px;
}
header .container { display: flex; align-items: center; gap: 16px; }
.logo { font-size: 28px; font-weight: 800; color: #63b3ed; letter-spacing: -1px; }
.logo span { color: #fc8181; }
.meta { font-size: 13px; color: #718096; margin-top: 4px; }
.stats-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px; margin-bottom: 32px;
}
.stat-card {
    background: #1a1f2e; border: 1px solid #2d3748; border-radius: 8px;
    padding: 16px; text-align: center;
}
.stat-card .number { font-size: 36px; font-weight: 700; }
.stat-card .label { font-size: 12px; color: #718096; margin-top: 4px; }
.red { color: #fc8181; } .yellow { color: #f6e05e; }
.green { color: #68d391; } .blue { color: #63b3ed; } .purple { color: #b794f4; }
.run-block { margin-bottom: 40px; }
.run-header {
    background: #1a1f2e; border: 1px solid #2d3748; border-radius: 8px 8px 0 0;
    padding: 16px 20px; display: flex; align-items: center; gap: 12px;
}
.run-title { font-size: 18px; font-weight: 600; }
.badge {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 12px; font-weight: 600;
}
.badge-vuln { background: #742a2a; color: #fc8181; }
.badge-safe { background: #1c4532; color: #68d391; }
.badge-uncertain { background: #744210; color: #f6e05e; }
.badge-success { background: #1c4532; color: #68d391; }
.badge-failed  { background: #742a2a; color: #fc8181; }
.run-meta {
    background: #161b27; border-left: 1px solid #2d3748;
    border-right: 1px solid #2d3748; padding: 12px 20px;
    font-size: 13px; color: #718096;
}
.run-meta span { color: #a0aec0; margin-right: 24px; }
.findings-table {
    width: 100%; border-collapse: collapse;
    background: #161b27; border: 1px solid #2d3748;
    border-radius: 0 0 8px 8px; overflow: hidden;
}
.findings-table th {
    background: #1a1f2e; padding: 10px 14px; text-align: left;
    font-size: 12px; text-transform: uppercase; color: #718096;
    border-bottom: 1px solid #2d3748;
}
.findings-table td {
    padding: 12px 14px; border-bottom: 1px solid #1a1f2e;
    font-size: 13px; vertical-align: top;
}
.findings-table tr:last-child td { border-bottom: none; }
.findings-table tr:hover td { background: #1a1f2e; }
.conf-bar-bg {
    background: #2d3748; border-radius: 4px; height: 6px;
    width: 80px; margin-top: 4px;
}
.conf-bar { height: 6px; border-radius: 4px; }
.reasoning { font-size: 12px; color: #718096; margin-top: 4px; }
.poc-block {
    background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; margin-top: 8px; padding: 12px;
}
.poc-block .poc-title { font-size: 11px; color: #8b949e; margin-bottom: 8px; }
.payload {
    font-family: 'SFMono-Regular', Consolas, monospace;
    font-size: 12px; color: #e6edf3; background: #161b22;
    border-radius: 4px; padding: 8px 12px; overflow-x: auto; margin-bottom: 4px;
}
.http-trigger {
    font-size: 12px; color: #8b949e;
}
.http-trigger .method { color: #79c0ff; font-weight: 600; }
.http-trigger .path { color: #7ee787; }
.no-findings {
    padding: 32px; text-align: center; color: #4a5568; font-size: 14px;
    background: #161b27; border: 1px solid #2d3748; border-radius: 0 0 8px 8px;
}
footer {
    margin-top: 48px; padding: 24px 0;
    border-top: 1px solid #2d3748; text-align: center;
    font-size: 12px; color: #4a5568;
}
details summary { cursor: pointer; user-select: none; }
details summary::-webkit-details-marker { color: #63b3ed; }
"""

# ---------------------------------------------------------------------------
# HTML 生成辅助
# ---------------------------------------------------------------------------

def _e(text: str) -> str:
    """HTML 转义。"""
    return html.escape(str(text))


def _confidence_bar(conf: float) -> str:
    pct = int(conf * 100)
    if conf >= 0.8:
        color = "#68d391"
    elif conf >= 0.6:
        color = "#f6e05e"
    else:
        color = "#fc8181"
    return (
        f'<div class="conf-bar-bg">'
        f'<div class="conf-bar" style="width:{pct}%;background:{color}"></div></div>'
    )


def _status_badge(status: str) -> str:
    cls = {
        "vulnerable": "badge-vuln",
        "safe":       "badge-safe",
        "uncertain":  "badge-uncertain",
    }.get(status, "badge-uncertain")
    label = {"vulnerable": "漏洞", "safe": "安全", "uncertain": "可疑"}.get(status, status)
    return f'<span class="badge {cls}">{label}</span>'


def _severity_color(sev: str) -> str:
    return {"critical": "#fc8181", "high": "#f6e05e", "medium": "#68d391"}.get(sev, "#718096")


def _render_poc(poc) -> str:
    payloads_html = "".join(
        f'<div class="payload">{_e(p)}</div>' for p in poc.payloads[:3]
    )
    trigger = poc.http_trigger or {}
    trigger_html = ""
    if trigger:
        method = trigger.get("method", "")
        path = trigger.get("path", "")
        param = trigger.get("param", "")
        example = trigger.get("example", "")
        trigger_html = (
            f'<div class="http-trigger">'
            f'<span class="method">{_e(method)}</span> '
            f'<span class="path">{_e(path)}</span>  param=<b>{_e(param)}</b>'
            + (f'<div class="payload">{_e(example)}</div>' if example else "")
            + "</div>"
        )
    return (
        f'<div class="poc-block">'
        f'<div class="poc-title">PoC — {_e(poc.engine)} '
        f'<span style="color:{_severity_color(poc.severity)}">{_e(poc.severity.upper())}</span>'
        f'  预期回显: {_e(poc.expected_output[:60])}</div>'
        + payloads_html
        + trigger_html
        + "</div>"
    )


def _render_findings(state: "PipelineState", poc_map: dict) -> str:
    if not state.review_results:
        return '<div class="no-findings">无发现（CodeQL 扫描结果为空，或 Agent-R 已禁用）</div>'

    rows = ""
    for i, r in enumerate(state.review_results, 1):
        poc = poc_map.get(f"{r.finding.file_uri}:{r.finding.start_line}")
        poc_html = _render_poc(poc) if poc else ""
        rows += f"""
        <tr>
          <td style="width:40px;color:#718096">{i}</td>
          <td>{_status_badge(r.status.value)}</td>
          <td>
            {int(r.confidence * 100)}%
            {_confidence_bar(r.confidence)}
          </td>
          <td><b>{_e(r.engine_detected)}</b></td>
          <td>
            <code style="font-size:12px;color:#79c0ff">{_e(r.finding.file_uri)}</code>
            <span style="color:#718096">:{r.finding.start_line}</span>
            <div class="reasoning">{_e(r.reasoning)}</div>
            {poc_html}
          </td>
        </tr>"""

    return f"""
    <table class="findings-table">
      <thead>
        <tr>
          <th>#</th><th>状态</th><th>置信度</th><th>引擎</th><th>位置 / 推理 / PoC</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>"""


def _render_run(state: "PipelineState") -> str:
    poc_map = {poc.file_location: poc for poc in state.poc_results}

    status_badge = (
        '<span class="badge badge-failed">失败</span>'
        if state.error
        else '<span class="badge badge-success">成功</span>'
    )
    cache_tag = " · 数据库缓存命中" if state.db_from_cache else ""
    vuln_cnt = len(state.vulnerable_findings)

    meta = (
        f'<span>run_id: {_e(state.run_id)}</span>'
        f'<span>阶段: {_e(", ".join(state.completed_phases))}{_e(cache_tag)}</span>'
        f'<span>发现: {len(state.review_results)} 条 · 确认漏洞: {vuln_cnt} 处 · PoC: {len(state.poc_results)} 份</span>'
    )
    if state.query_path:
        meta += f'<span>查询: {_e(state.query_path)}</span>'
    if state.sarif_path:
        meta += f'<span>SARIF: {_e(state.sarif_path)}</span>'
    if state.error:
        meta += f'<span style="color:#fc8181">错误: {_e(state.error)}</span>'

    findings_html = (
        f'<div class="no-findings" style="color:#fc8181">{_e(state.error)}</div>'
        if state.error
        else _render_findings(state, poc_map)
    )

    return f"""
    <div class="run-block">
      <div class="run-header">
        {status_badge}
        <div class="run-title">{_e(state.vuln_type or "未知漏洞类型")}</div>
        {'<span class="badge badge-vuln">⚠ ' + str(vuln_cnt) + ' 处确认漏洞</span>' if vuln_cnt > 0 else ''}
      </div>
      <div class="run-meta">{meta}</div>
      {findings_html}
    </div>"""


# ---------------------------------------------------------------------------
# 主导出函数
# ---------------------------------------------------------------------------


def export_html(
    states: "list[PipelineState]",
    output_path: str,
    language: str = "",
    title: str = "QRSE-X 扫描报告",
) -> str:
    """
    将扫描结果导出为自包含 HTML 报告。

    Args:
        states: Pipeline 执行结果列表。
        output_path: 输出文件路径（自动创建父目录）。
        language: 目标语言（显示在报告头部）。
        title: 报告标题。

    Returns:
        实际写入的文件路径字符串。
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_vuln = sum(len(s.vulnerable_findings) for s in states)
    total_find = sum(len(s.review_results) for s in states)
    total_poc  = sum(len(s.poc_results) for s in states)
    failed     = sum(1 for s in states if s.error)

    # 统计卡片
    stats_html = f"""
    <div class="stats-grid">
      <div class="stat-card">
        <div class="number blue">{len(states)}</div>
        <div class="label">扫描任务</div>
      </div>
      <div class="stat-card">
        <div class="number yellow">{total_find}</div>
        <div class="label">CodeQL 发现</div>
      </div>
      <div class="stat-card">
        <div class="number red">{total_vuln}</div>
        <div class="label">确认漏洞</div>
      </div>
      <div class="stat-card">
        <div class="number purple">{total_poc}</div>
        <div class="label">PoC 报告</div>
      </div>
      <div class="stat-card">
        <div class="number {'red' if failed else 'green'}">{failed}</div>
        <div class="label">失败任务</div>
      </div>
    </div>"""

    runs_html = "\n".join(_render_run(s) for s in states)

    page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_e(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
<header>
  <div class="container">
    <div>
      <div class="logo">QRS<span>-EL</span></div>
      <div class="meta">
        语言: {_e(language or "未知")} &nbsp;·&nbsp;
        生成时间: {now} &nbsp;·&nbsp;
        版本: {_TOOL_VERSION}
      </div>
    </div>
  </div>
</header>
<div class="container">
  {stats_html}
  {runs_html}
</div>
<footer>
  <div class="container">
    Generated by QRSE-X v{_TOOL_VERSION} · {now}
  </div>
</footer>
</body>
</html>"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")

    import logging
    logging.getLogger(__name__).info(
        "[HTMLReporter] 报告已生成: %s (%d 条发现, %d 处漏洞)",
        out, total_find, total_vuln,
    )
    return str(out)
