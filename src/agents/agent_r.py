"""
Agent-R：语义审查与误报过滤。

工作流：
1. 解析 SARIF 文件，提取每条发现的文件路径、行号与消息。
2. 读取对应源文件的代码上下文（发现行前后各 N 行）。
3. 将「数据流描述 + 源码片段」发送给 LLM，判断是否为真实漏洞。
4. 返回带置信度与推理说明的 ReviewResult 列表。

EL 注入专有审查维度：
- Spring 环境是否使用了 SimpleEvaluationContext（安全）vs StandardEvaluationContext（危险）。
- 输入路径上是否存在正则白名单或黑名单净化。
- 用户输入是否被完整执行，还是作为字面量安全拼接。
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

# 源码上下文窗口：发现行前后各取 N 行
_CONTEXT_LINES: int = 15

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


class VulnStatus(str, Enum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    UNCERTAIN = "uncertain"


@dataclass
class SarifFinding:
    """从 SARIF 文件解析出的单条发现。"""

    rule_id: str
    message: str
    file_uri: str           # 相对于仓库根目录的文件路径
    start_line: int
    code_context: str = ""  # 填充后的源码上下文片段


@dataclass
class ReviewResult:
    """Agent-R 对单条发现的研判输出。"""

    finding: SarifFinding
    status: VulnStatus
    confidence: float       # [0.0, 1.0]
    engine_detected: str    # 识别出的 EL 引擎，如 "Spring EL"
    reasoning: str          # LLM 的推理说明
    sink_method: str = ""   # 触发告警的 Sink 方法


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_R_JAVA = """\
你是一位专注于 Java 表达式注入漏洞（SpEL / OGNL / MVEL）的安全研究员。
你将收到一段 CodeQL 静态扫描发现，以及对应的 Java 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

审查维度（Java EL 注入专有）：
1. **执行上下文**：使用的是 StandardEvaluationContext（危险）还是 SimpleEvaluationContext（安全）？
2. **净化器**：输入在进入 Sink 之前是否经过了正则白名单、黑名单过滤或类型校验？
3. **执行逻辑**：用户输入是被完整求值执行，还是仅作为字符串字面量使用（如日志、显示）？
4. **权限控制**：该接口是否需要高权限才能访问？高权限不等于安全，但影响风险等级。

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "Spring EL" | "OGNL" | "MVEL" | "Unknown",
  "reasoning": "简洁的中文推理说明（2-4句话）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_PYTHON = """\
你是一位专注于 Python 服务端模板注入漏洞（SSTI：Jinja2 / Mako）的安全研究员。
你将收到一段 CodeQL 静态扫描发现，以及对应的 Python 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

审查维度（Python SSTI 专有）：
1. **模板内容来源**：用户输入是否被直接用作模板字符串？还是仅作为模板渲染的数据变量（安全）？
2. **沙箱配置**：Jinja2 Environment 是否启用了沙箱模式（SandboxedEnvironment）？
3. **净化器**：输入是否经过 escape() 转义或 Markup() 包裹？
4. **执行链**：是 from_string(user_input) 直接传入，还是先 render()，链路是否完整触达 Sink？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "Jinja2" | "Mako" | "Unknown",
  "reasoning": "简洁的中文推理说明（2-4句话）",
  "sink_method": "被调用的危险方法全名（如 jinja2.Environment.from_string）"
}
"""

_SYSTEM_PROMPT_R_GENERIC = """\
你是一位专注于注入类漏洞的安全研究员。
你将收到一段 CodeQL 静态扫描发现，以及对应的源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

审查维度：
1. **净化器**：输入进入 Sink 之前是否有验证/过滤？
2. **执行逻辑**：用户输入是否真正被求值执行？
3. **数据流**：Source → Sink 的数据流路径是否完整且可触达？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "Unknown",
  "reasoning": "简洁的中文推理说明（2-4句话）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPTS_R: dict[str, str] = {
    "java":   _SYSTEM_PROMPT_R_JAVA,
    "python": _SYSTEM_PROMPT_R_PYTHON,
}

# 兼容旧引用
_SYSTEM_PROMPT_R = _SYSTEM_PROMPT_R_JAVA


def _get_review_system_prompt(language: str) -> str:
    """按语言返回对应的审查系统提示。"""
    return _SYSTEM_PROMPTS_R.get(language.lower(), _SYSTEM_PROMPT_R_GENERIC)


def _get_code_block_lang(language: str) -> str:
    """返回 markdown 代码块对应的语言标签。"""
    return {"java": "java", "python": "python", "javascript": "js"}.get(
        language.lower(), ""
    )


_REVIEW_TEMPLATE = """\
【CodeQL 发现】
- 规则 ID : {rule_id}
- 文件    : {file_uri}
- 行号    : {start_line}
- 消息    : {message}

【源码上下文（第 {start_line} 行附近）】
```{code_lang}
{code_context}
```

请按要求输出 JSON 格式的研判结论。
"""


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _parse_sarif(sarif_path: str) -> list[SarifFinding]:
    """
    解析 SARIF 文件，提取每条发现的关键信息。

    Args:
        sarif_path: SARIF 文件路径。

    Returns:
        SarifFinding 列表。
    """
    path = Path(sarif_path)
    if not path.exists():
        raise FileNotFoundError(f"SARIF 文件不存在: {sarif_path}")

    with path.open(encoding="utf-8") as f:
        sarif: dict[str, Any] = json.load(f)

    findings: list[SarifFinding] = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")

            locs = result.get("locations", [])
            if not locs:
                continue
            pl = locs[0].get("physicalLocation", {})
            uri = pl.get("artifactLocation", {}).get("uri", "")
            line = pl.get("region", {}).get("startLine", 0)

            findings.append(SarifFinding(
                rule_id=rule_id,
                message=message,
                file_uri=uri,
                start_line=line,
            ))

    logger.info("SARIF 解析完成，共 %d 条发现。", len(findings))
    return findings


def _load_code_context(
    repo_root: str,
    file_uri: str,
    center_line: int,
    window: int = _CONTEXT_LINES,
) -> str:
    """
    从仓库本地路径读取发现行附近的源码片段。

    Args:
        repo_root: 仓库根目录的本地路径。
        file_uri: SARIF 中的相对文件路径。
        center_line: 发现所在行号（1-indexed）。
        window: 前后各取的行数。

    Returns:
        带行号前缀的源码上下文字符串。
    """
    # SARIF uri 可能含 file:// 前缀
    clean_uri = file_uri.removeprefix("file://").lstrip("/")
    file_path = Path(repo_root) / clean_uri

    if not file_path.exists():
        return f"（无法读取源文件: {file_path}）"

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"（读取源文件失败: {exc}）"

    start = max(0, center_line - window - 1)
    end = min(len(lines), center_line + window)
    snippet = lines[start:end]

    # 带行号前缀，方便 LLM 定位
    numbered = [
        f"{start + i + 1:4d} | {line}"
        for i, line in enumerate(snippet)
    ]
    return "\n".join(numbered)


def _parse_llm_json(raw: str) -> dict[str, Any]:
    """
    从 LLM 原始输出中提取 JSON 对象，容忍 markdown 代码块包裹。

    Args:
        raw: LLM 原始响应字符串。

    Returns:
        解析后的字典。

    Raises:
        ValueError: JSON 解析失败时抛出。
    """
    # 去除可能存在的 ```json ... ``` 包裹
    text = raw.strip()
    if "```" in text:
        import re
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM 返回的 JSON 无效: {exc}\n原始内容:\n{raw}") from exc


# ---------------------------------------------------------------------------
# Agent-R 主类
# ---------------------------------------------------------------------------


class AgentR:
    """
    漏洞语义审查 Agent。

    对 CodeQL 的每条发现执行 LLM 语义分析，过滤误报，
    输出带置信度评分的研判结论列表。

    Args:
        llm: LangChain LLM 实例；默认使用环境变量中的 ChatOpenAI。
        context_lines: 源码上下文窗口大小（前后各取 N 行）。
    """

    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        context_lines: int = _CONTEXT_LINES,
    ) -> None:
        import os
        self.llm: ChatOpenAI = llm or ChatOpenAI(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
            temperature=0.1,   # 审查任务需要高确定性，使用更低温度
            base_url=os.environ.get("OPENAI_BASE_URL") or None,
        )
        self.context_lines = context_lines
        self._parser = StrOutputParser()

    def _invoke_llm(
        self,
        finding: SarifFinding,
        language: str = "java",
    ) -> dict[str, Any]:
        """
        调用 LLM 对单条发现进行语义审查。

        Args:
            finding: 待审查的 SARIF 发现。
            language: 目标语言，用于选择对应的系统提示和代码块语法高亮。
        """
        code_lang = _get_code_block_lang(language)
        human_msg = _REVIEW_TEMPLATE.format(
            rule_id=finding.rule_id,
            file_uri=finding.file_uri,
            start_line=finding.start_line,
            message=finding.message,
            code_context=finding.code_context or "（源码上下文不可用）",
            code_lang=code_lang,
        )
        sys_prompt = _get_review_system_prompt(language)
        chain = self.llm | self._parser
        raw = chain.invoke([
            SystemMessage(content=sys_prompt),
            HumanMessage(content=human_msg),
        ])
        return _parse_llm_json(raw)

    def review(
        self,
        sarif_path: str,
        repo_root: str,
        language: str = "java",
    ) -> list[ReviewResult]:
        """
        审查 CodeQL SARIF 扫描结果，返回带研判结论的列表。

        Args:
            sarif_path: SARIF 文件路径。
            repo_root: 仓库本地根目录（用于读取源码上下文）。

        Returns:
            ReviewResult 列表，每条对应一个 CodeQL 发现。
        """
        findings = _parse_sarif(sarif_path)
        if not findings:
            logger.info("SARIF 中无发现，Agent-R 跳过审查。")
            return []

        results: list[ReviewResult] = []

        for idx, finding in enumerate(findings, 1):
            logger.info(
                "[Agent-R] 审查发现 %d/%d: %s:%d",
                idx, len(findings),
                finding.file_uri, finding.start_line,
            )

            # 读取源码上下文
            finding.code_context = _load_code_context(
                repo_root=repo_root,
                file_uri=finding.file_uri,
                center_line=finding.start_line,
                window=self.context_lines,
            )

            # LLM 语义审查（传入语言，使用对应的提示词）
            try:
                verdict = self._invoke_llm(finding, language=language)
            except (ValueError, Exception) as exc:  # noqa: BLE001
                logger.warning(
                    "[Agent-R] 发现 %d 审查失败（LLM 异常），标记为 UNCERTAIN: %s", idx, exc
                )
                verdict = {
                    "status": "uncertain",
                    "confidence": 0.0,
                    "engine_detected": "Unknown",
                    "reasoning": f"LLM 审查异常: {exc}",
                    "sink_method": "",
                }

            status = VulnStatus(verdict.get("status", "uncertain"))
            result = ReviewResult(
                finding=finding,
                status=status,
                confidence=float(verdict.get("confidence", 0.0)),
                engine_detected=verdict.get("engine_detected", "Unknown"),
                reasoning=verdict.get("reasoning", ""),
                sink_method=verdict.get("sink_method", ""),
            )
            results.append(result)

            logger.info(
                "[Agent-R] 结论: %s (置信度: %.0f%%) | %s",
                status.value.upper(),
                result.confidence * 100,
                result.reasoning[:80],
            )

        vulnerable = sum(1 for r in results if r.status == VulnStatus.VULNERABLE)
        logger.info(
            "[Agent-R] 审查完成 | 共 %d 条 | 真实漏洞: %d | 安全/不确定: %d",
            len(results), vulnerable, len(results) - vulnerable,
        )
        return results
