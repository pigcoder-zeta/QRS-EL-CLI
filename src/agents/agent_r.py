"""
Agent-R：语义审查与误报过滤。

工作流：
1. 解析 SARIF 文件，提取每条发现的文件路径、行号与消息。
2. 读取对应源文件的代码上下文（发现行前后各 N 行）。
3. 将「数据流描述 + 源码片段」发送给 LLM，判断是否为真实漏洞。
4. 返回带置信度与推理说明的 ReviewResult 列表。

通用审查维度：
- 数据是否真正来自用户可控输入（HTTP 参数、Header、Cookie、Body）？
- 到达 Sink 之前是否经过了有效的净化、参数化或白名单校验？
- 漏洞是否处于可达的代码路径（非测试代码、非废弃接口）？
- 实际利用复杂度（前置条件、认证要求、利用稳定性）？
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
你是一位资深 Java 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、路径穿越、SSRF、反序列化、表达式注入、XSS、XXE 等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 Java 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（HTTP参数/Header/Cookie/Body/上传文件）？
2. **净化器**：在进入 Sink 之前是否经过了参数化、白名单过滤、正则校验或类型转换？
3. **漏洞类型专属**：
   - SQL注入：是否使用 PreparedStatement / 参数绑定？
   - 命令注入：参数是否通过 Runtime.exec(String[]) 隔离？
   - 路径穿越：是否调用了 getCanonicalPath() + 前缀校验？
   - SSRF：目标 URL 是否经过白名单或协议过滤？
   - 表达式注入：是否使用了安全上下文（SimpleEvaluationContext）？
   - 反序列化：是否使用了过滤型 ObjectInputStream？
4. **可达性**：该代码路径是否在生产环境中可触达（非测试代码/废弃接口）？
5. **权限**：接口是否需要特定权限（影响风险等级，但不代表安全）？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 Spring EL / JDBC / Runtime / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_PYTHON = """\
你是一位资深 Python 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、模板注入SSTI、路径穿越、反序列化、开放重定向等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 Python 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（Flask request.args/form/json、Django request.GET/POST 等）？
2. **净化器**：是否经过了参数化查询、shlex.quote()、os.path.realpath() 校验、escape() 或白名单过滤？
3. **漏洞类型专属**：
   - SQL注入：是否使用了参数绑定（%s占位符 + 元组参数）而非字符串拼接？
   - 命令注入：是否使用了 subprocess 的列表形式（非 shell=True 的字符串）？
   - SSTI：用户输入是用作模板字符串还是仅作为渲染变量（变量安全，字符串危险）？
   - 路径穿越：是否调用了 os.path.realpath() + 路径前缀校验？
   - 反序列化：pickle.loads 的数据是否来自可信源？
4. **可达性**：代码是否处于可触达的请求处理路径中？
5. **框架特性**：Django ORM / SQLAlchemy 的 ORM 查询通常安全，raw()/execute() 需关注。

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 Jinja2 / SQLite3 / subprocess / pickle / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_JAVASCRIPT = """\
你是一位资深 JavaScript/TypeScript 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、XSS、路径穿越、SSRF、原型链污染、不安全反序列化等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 JavaScript/TypeScript 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（Express req.query/body/params、Koa ctx.request 等）？
2. **净化器**：是否经过了参数化查询、validator/sanitize-html 库、path.resolve() + 前缀校验？
3. **漏洞类型专属**：
   - SQL注入：是否使用了参数化（mysql2 ? 占位符、knex 绑定、Sequelize ORM）？
   - 命令注入：是否使用了 execFile（数组参数）而非 exec（字符串拼接）？
   - XSS：输出是否经过 DOMPurify / escape-html / 模板引擎自动转义？
   - 路径穿越：是否调用了 path.resolve() + startsWith() 前缀校验？
   - SSRF：URL 是否经过白名单过滤？
   - 原型链污染：merge/extend 是否对 __proto__ / constructor 做了过滤？
4. **可达性**：代码路径是否可触达（非测试代码/中间件是否拦截）？
5. **框架特性**：Express / Koa / NestJS 中间件链是否引入了安全防护？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 child_process / mysql / express / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_GO = """\
你是一位资深 Go 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、路径穿越、SSRF、不安全反序列化等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 Go 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（http.Request FormValue/URL.Query/Body、gin c.Query 等）？
2. **净化器**：是否经过了参数化查询、filepath.Clean() + 前缀校验、html.EscapeString()？
3. **漏洞类型专属**：
   - SQL注入：是否使用了 database/sql 的 ? 占位符参数绑定？
   - 命令注入：是否使用了 exec.Command 的参数数组形式（非 bash -c 字符串）？
   - 路径穿越：是否调用了 filepath.Clean() + strings.HasPrefix() 校验？
   - SSRF：URL 是否经过白名单或 IP 过滤？
4. **可达性**：Handler 是否注册在路由中？中间件是否有鉴权拦截？
5. **Go 特性**：强类型转换是否天然阻止了注入（如 strconv.Atoi）？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或包名（如 database/sql / os/exec / net/http / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_CSHARP = """\
你是一位资深 C# 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、路径穿越、SSRF、XSS、不安全反序列化等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 C# 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（ASP.NET Request.Query/Form/Body、[FromQuery]/[FromBody] 参数）？
2. **净化器**：是否经过了参数化查询、Path.GetFullPath() + 前缀校验、HtmlEncoder.Encode()？
3. **漏洞类型专属**：
   - SQL注入：是否使用了 SqlParameter 参数化 / Entity Framework LINQ 查询？
   - 命令注入：ProcessStartInfo.Arguments 是否拼接了用户输入？
   - 路径穿越：是否调用了 Path.GetFullPath() + StartsWith() 校验？
   - SSRF：HttpClient URL 是否经过白名单过滤？
   - 反序列化：BinaryFormatter / JavaScriptSerializer 是否接受了不可信输入？
4. **可达性**：Controller Action 是否可从外部触达？[Authorize] 属性影响？
5. **框架特性**：ASP.NET Core 模型绑定 / Anti-Forgery Token / CORS 策略是否减轻风险？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 SqlCommand / Process / HttpClient / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_CPP = """\
你是一位资深 C/C++ 安全研究员，擅长审查各类漏洞（命令注入、缓冲区溢出、格式化字符串、路径穿越、整数溢出、Use-After-Free 等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 C/C++ 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（argv、getenv、fgets/scanf/read、网络 recv 等）？
2. **净化器**：是否经过了输入长度校验、白名单过滤、整数范围检查、路径规范化？
3. **漏洞类型专属**：
   - 命令注入：是否使用了 system()/popen() 拼接字符串？可否用 execvp 数组参数替代？
   - 缓冲区溢出：目标缓冲区大小是否足够？是否使用了 strncpy/snprintf 等安全版本？
   - 格式化字符串：printf 系列是否直接使用了用户输入作为格式串？
   - 路径穿越：fopen/open 的路径是否经过 realpath() + 前缀校验？
   - 整数溢出：算术运算结果是否用于内存分配或数组索引？
4. **可达性**：该代码路径是否在实际运行中可触达？
5. **编译器防护**：是否开启了 ASLR/Stack Canary/FORTIFY_SOURCE 等缓解措施？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型（如 system() / fopen / printf / memcpy / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险函数全名"
}
"""

_SYSTEM_PROMPT_R_GENERIC = """\
你是一位资深安全研究员，擅长审查各类 Web 应用安全漏洞。
你将收到一段 CodeQL 静态扫描发现，以及对应的源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正来自外部可控渠道（HTTP请求、配置输入等）？
2. **净化器**：进入 Sink 之前是否经过有效的验证、过滤、参数化或编码处理？
3. **数据流完整性**：Source → Sink 的路径在代码中是否真实存在且可触达？
4. **可利用性**：触发该漏洞需要哪些前置条件？是否需要特定权限或配置？
5. **误报信号**：常见误报包括：输入已经是常量/枚举值、已使用安全API包装、仅用于日志记录等。

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型（如 SQL Injection / Command Injection / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPTS_R: dict[str, str] = {
    "java":       _SYSTEM_PROMPT_R_JAVA,
    "python":     _SYSTEM_PROMPT_R_PYTHON,
    "javascript": _SYSTEM_PROMPT_R_JAVASCRIPT,
    "go":         _SYSTEM_PROMPT_R_GO,
    "csharp":     _SYSTEM_PROMPT_R_CSHARP,
    "cpp":        _SYSTEM_PROMPT_R_CPP,
}

# 兼容旧引用
_SYSTEM_PROMPT_R = _SYSTEM_PROMPT_R_JAVA


def _get_review_system_prompt(language: str) -> str:
    """按语言返回对应的审查系统提示。"""
    return _SYSTEM_PROMPTS_R.get(language.lower(), _SYSTEM_PROMPT_R_GENERIC)


def _get_code_block_lang(language: str) -> str:
    """返回 markdown 代码块对应的语言标签。"""
    return {
        "java": "java", "python": "python", "javascript": "js",
        "go": "go", "csharp": "csharp", "cpp": "cpp",
    }.get(language.lower(), "")


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
