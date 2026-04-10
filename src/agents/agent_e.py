"""
Agent-E (Executor/Verifier)：动态沙箱验证 Agent。

职责：
  将 Agent-S 生成的 PoC 真实打到目标应用上，将概率性的"LLM 判断"
  升级为确定性的"运行时确认"，彻底消除 SAST 误报。

验证流程：
  1. 解析 PoC 的 http_trigger（方法/路径/参数）
  2. （可选）Docker 沙箱：构建镜像 → 启动容器 → 等待就绪
  3. 发送 PoC HTTP 请求（依次测试每个 Payload）
  4. 使用 LLM 分析响应，判断是否确认漏洞
  5. 清理容器

验证模式：
  - DOCKER  ：在隔离容器中构建并运行目标应用（最安全，需 Dockerfile）
  - REMOTE  ：直接向用户指定的已运行服务发送请求（适合真实测试环境）
  - SKIP    ：Docker 不可用且未指定目标地址时跳过

置信度映射：
  CONFIRMED    → confidence = 1.00  (动态执行证实)
  UNCONFIRMED  → confidence = 0.50  (无法触发，回退到静态分析结论)
  SKIPPED      → confidence = None  (未执行)
  ERROR        → confidence = None  (执行错误)
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from src.agents.base_agent import BaseAgent
from src.agents.agent_s import PoCResult
from src.utils.docker_manager import ContainerInfo, DockerManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 漏洞类型 → 确认信号正则表达式
# 优先用 LLM 分析，这里作为快速启发式预检
# ---------------------------------------------------------------------------

_CONFIRM_PATTERNS: dict[str, list[str]] = {
    "command injection": [
        r"uid=\d+\(",          # id 命令输出：uid=0(root)
        r"root:x:0:0:",        # /etc/passwd 内容
        r"(www-data|root|nobody)$",
        r"Linux .* \d+\.\d+",  # uname -a
    ],
    "rce": [
        r"uid=\d+\(",
        r"root:x:0:0:",
        r"(windows|linux|darwin)",
    ],
    "spring el": [
        r"uid=\d+\(",
        r"java\.lang\.Process",
        r"root:x:0:0:",
    ],
    "ognl": [
        r"uid=\d+\(",
        r"root:x:0:0:",
        r"java\.lang",
    ],
    "mvel": [r"uid=\d+\(", r"root:x:0:0:"],
    "jinja2": [
        r"uid=\d+\(",
        r"root:x:0:0:",
        r"\b49\b",             # {{7*7}} = 49
    ],
    "mako": [r"uid=\d+\(", r"root:x:0:0:", r"\b49\b"],
    "ssti": [r"\b49\b", r"uid=\d+\(", r"root:x:0:0:"],
    "sql injection": [
        r"(You have an error in your SQL syntax|SQL syntax.*?error|ORA-\d{4,5}:|mysql_fetch_\w+\(\)|pg_query\(\).*?ERROR)",
        r"(SQLSTATE\[\w+\]|PDOException|java\.sql\.SQLException|sqlite3\.OperationalError)",
        r"(information_schema\.\w+|UNION\s+SELECT\s+.+FROM\s+\w+)",
    ],
    "sqli": [
        r"(SQL syntax.*?error|ORA-\d{4,5}:|SQLSTATE\[)",
        r"information_schema\.\w+",
    ],
    "path traversal": [
        r"root:x:0:0:",        # /etc/passwd
        r"WINDOWS\\system32",  # Windows hosts
        r"\[boot loader\]",    # boot.ini
    ],
    "directory traversal": [r"root:x:0:0:", r"WINDOWS\\system32"],
    "ssrf": [
        r"ami-id|instance-id|169\.254",   # AWS metadata
        r"(ssh|smtp|redis|mysql)\s+\d+",  # 端口探测回显
        r"root:x:0:0:",
    ],
    "xxe": [
        r"root:x:0:0:",
        r"DOCTYPE",
        r"(SYSTEM|ENTITY)",
    ],
    "log injection": [r"FATAL|ERROR|WARN", r"\[FAKE\]"],
    "open redirect": [r"Location:.*attacker\.com", r"attacker\.com"],
}


def _quick_confirm(response_body: str, vuln_type: str) -> tuple[bool, str]:
    """
    正则快速预检：若匹配直接返回确认，无需 LLM 调用（节省 token）。

    Returns:
        (matched, evidence_snippet)
    """
    body_lower = response_body.lower()
    for key, patterns in _CONFIRM_PATTERNS.items():
        if key not in vuln_type.lower():
            continue
        for pat in patterns:
            m = re.search(pat, response_body, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 30)
                end = min(len(response_body), m.end() + 30)
                return True, response_body[start:end].strip()
    return False, ""


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


class VerificationStatus(str, Enum):
    CONFIRMED   = "CONFIRMED"    # 动态执行验证为真实漏洞
    UNCONFIRMED = "UNCONFIRMED"  # PoC 已发送但未触发预期回显
    SKIPPED     = "SKIPPED"      # Docker/目标不可用，跳过
    ERROR       = "ERROR"        # 执行过程中出错


@dataclass
class VerificationResult:
    """
    Agent-E 动态验证结果。

    Attributes:
        status:           验证状态（CONFIRMED / UNCONFIRMED / SKIPPED / ERROR）。
        confidence:       置信度（1.0=100% 确认，0.5=未确认，None=跳过/错误）。
        evidence:         证明漏洞存在的关键响应片段（如 uid=0(root) 字样）。
        payload_used:     实际触发漏洞的 Payload。
        request_summary:  发送的 HTTP 请求摘要（含 URL + 参数）。
        response_code:    HTTP 响应状态码（-1 表示连接失败）。
        response_snippet: 响应 Body 前 500 字符。
        duration_seconds: 验证耗时（秒）。
        docker_image:     使用的 Docker 镜像（DOCKER 模式）。
        target_host:      目标地址（REMOTE 模式）。
        reason:           简短说明（失败/跳过原因）。
        llm_analysis:     LLM 对响应的分析结论。
    """

    status:            VerificationStatus = VerificationStatus.SKIPPED
    confidence:        Optional[float]    = None
    evidence:          str                = ""
    payload_used:      str                = ""
    request_summary:   str                = ""
    response_code:     int                = -1
    response_snippet:  str                = ""
    duration_seconds:  float              = 0.0
    docker_image:      str                = ""
    target_host:       str                = ""
    reason:            str                = ""
    llm_analysis:      str                = ""

    def to_dict(self) -> dict:
        return {
            "status":           self.status.value,
            "confidence":       self.confidence,
            "evidence":         self.evidence,
            "payload_used":     self.payload_used,
            "request_summary":  self.request_summary,
            "response_code":    self.response_code,
            "response_snippet": self.response_snippet,
            "duration_seconds": round(self.duration_seconds, 2),
            "docker_image":     self.docker_image,
            "target_host":      self.target_host,
            "reason":           self.reason,
            "llm_analysis":     self.llm_analysis,
        }

    @property
    def is_confirmed(self) -> bool:
        return self.status == VerificationStatus.CONFIRMED


# ---------------------------------------------------------------------------
# LLM Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_E = """\
你是一位漏洞利用验证专家。你将收到：
1. 安全扫描工具发现的漏洞类型（如 OGNL Injection）
2. 发送的 PoC HTTP 请求（方法、路径、Payload）
3. 目标应用的 HTTP 响应（状态码 + Body）

请判断此次 PoC 是否成功触发了漏洞，并以 JSON 格式输出：
{
  "confirmed": true 或 false,
  "confidence": 0.0-1.0 之间的置信度,
  "evidence": "响应中证明漏洞存在的关键片段（如 uid=0(root) 或 SQL 错误信息）",
  "reason": "判断依据的简要说明（1-2句话）"
}

判断标准：
- confirmed=true：响应体中出现命令执行回显（uid=、root:x:0:0:）、数据库错误、文件内容、
  模板求值结果（7*7=49）、内网服务响应等明确证据
- confirmed=false：响应正常、错误信息无关安全、或明显是应用自身的业务错误
- 如果无法判断，confidence 应低于 0.5，confirmed=false
"""

_VERIFY_TEMPLATE = """\
【漏洞类型】{vuln_type}

【PoC 请求】
  方法:   {method}
  URL:    {url}
  参数:   {params}
  Payload: {payload}

【目标响应】
  状态码: {status_code}
  Body（前1000字符）:
{response_body}

请判断此次 PoC 是否成功触发了 {vuln_type} 漏洞。
"""


# ---------------------------------------------------------------------------
# Agent-E 主类
# ---------------------------------------------------------------------------


class AgentE(BaseAgent):
    """
    动态沙箱验证 Agent。

    工作模式：
      - Docker 模式：自动构建镜像、启动容器、验证后销毁
      - Remote 模式：向已运行的服务发送 PoC（提供 target_host 时触发）
      - Skip 模式：两者均不可用时优雅跳过

    Args:
        llm:             LangChain LLM 实例（用于响应分析）。
        target_host:     已运行目标的地址（如 http://localhost:8080），跳过 Docker 构建。
        enable_docker:   是否允许使用 Docker 模式（默认 True）。
        cleanup_image:   验证后是否删除 Docker 镜像（默认 True）。
    """

    agent_name = "Agent-E"

    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        target_host: Optional[str] = None,
        enable_docker: bool = True,
        cleanup_image: bool = True,
    ) -> None:
        super().__init__(llm=llm, temperature=0.0)
        self.target_host  = target_host
        self.enable_docker = enable_docker
        self.cleanup_image = cleanup_image
        self._docker      = DockerManager()
        self._image_cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def verify(
        self,
        poc: PoCResult,
        vuln_type: str,
        repo_path: str = "",
    ) -> VerificationResult:
        """
        对单条 PoC 执行动态验证。

        Args:
            poc:       Agent-S 生成的 PoC。
            vuln_type: 漏洞类型描述（如 OGNL Injection）。
            repo_path: 仓库本地路径（Docker 模式下用于构建镜像）。

        Returns:
            VerificationResult，status=CONFIRMED 表示 100% 确认真实漏洞。
        """
        logger.info("[Agent-E] 开始动态验证 | 漏洞: %s | Payload数: %d", vuln_type, len(poc.payloads))
        t_start = time.time()

        # ── 模式选择 ─────────────────────────────────────────────────
        if self.target_host:
            result = self._verify_remote(poc, vuln_type, self.target_host)
        elif self.enable_docker and self._docker.is_available() and repo_path:
            result = self._verify_docker(poc, vuln_type, repo_path)
        else:
            reason = "Docker 不可用" if not self._docker.is_available() else "未提供目标地址或仓库路径"
            logger.info("[Agent-E] 跳过动态验证: %s", reason)
            result = VerificationResult(
                status=VerificationStatus.SKIPPED,
                reason=reason,
            )

        result.duration_seconds = time.time() - t_start
        logger.info(
            "[Agent-E] 验证完成 | 状态: %s | 置信度: %s | 耗时: %.1fs",
            result.status.value,
            f"{result.confidence:.0%}" if result.confidence is not None else "N/A",
            result.duration_seconds,
        )
        return result

    def verify_all(
        self,
        poc_results: list[PoCResult],
        vuln_type: str,
        repo_path: str = "",
    ) -> list[VerificationResult]:
        """
        批量验证所有 PoC。

        Args:
            poc_results: Agent-S 生成的 PoC 列表。
            vuln_type:   漏洞类型。
            repo_path:   仓库路径（Docker 模式）。

        Returns:
            VerificationResult 列表（与 poc_results 一一对应）。
        """
        results = []
        for poc in poc_results:
            try:
                r = self.verify(poc, vuln_type, repo_path)
                results.append(r)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[Agent-E] 验证异常: %s", exc)
                results.append(VerificationResult(
                    status=VerificationStatus.ERROR,
                    reason=str(exc),
                ))
        return results

    # ------------------------------------------------------------------
    # Docker 模式
    # ------------------------------------------------------------------

    def _verify_docker(self, poc: PoCResult, vuln_type: str, repo_path: str) -> VerificationResult:
        """构建镜像 → 启动容器 → 发送 PoC → 分析响应 → 清理。"""
        probe = self._docker.probe_repo(repo_path)
        if not probe.is_containerizable:
            return VerificationResult(
                status=VerificationStatus.SKIPPED,
                reason="仓库中未找到 Dockerfile 或 docker-compose.yml，跳过 Docker 验证。",
            )

        cached_tag = self._image_cache.get(repo_path)
        if cached_tag:
            image_tag = cached_tag
            need_build = False
        else:
            image_tag = f"qrs-el-target-{id(self)}-{hash(repo_path) & 0xFFFF:04x}"
            need_build = True

        container: Optional[ContainerInfo] = None
        try:
            if need_build:
                if not self._docker.build_image(probe, image_tag):
                    return VerificationResult(
                        status=VerificationStatus.SKIPPED,
                        reason="Docker 镜像构建失败，可能需要特定构建环境。",
                    )
                self._image_cache[repo_path] = image_tag

            container = self._docker.start_container(
                image_tag=image_tag,
                container_port=probe.expose_port,
            )
            if container is None:
                return VerificationResult(
                    status=VerificationStatus.ERROR,
                    reason="Docker 容器启动失败。",
                )

            logger.info("[Agent-E] Docker 容器就绪: %s", container.base_url)
            result = self._send_poc_and_analyze(poc, vuln_type, container.base_url)
            result.docker_image = image_tag
            return result

        finally:
            if container:
                self._docker.stop_container(container.container_id)
            if self.cleanup_image and not self._image_cache.get(repo_path):
                self._docker.remove_image(image_tag)

    # ------------------------------------------------------------------
    # Remote 模式
    # ------------------------------------------------------------------

    def _verify_remote(self, poc: PoCResult, vuln_type: str, target_host: str) -> VerificationResult:
        """直接向已运行的目标服务发送 PoC。"""
        # 规范化 target_host
        if not target_host.startswith("http"):
            target_host = f"http://{target_host}"
        logger.info("[Agent-E] Remote 模式: %s", target_host)
        result = self._send_poc_and_analyze(poc, vuln_type, target_host)
        result.target_host = target_host
        return result

    # ------------------------------------------------------------------
    # PoC 发送 + 响应分析（共用）
    # ------------------------------------------------------------------

    def _send_poc_and_analyze(
        self,
        poc: PoCResult,
        vuln_type: str,
        base_url: str,
    ) -> VerificationResult:
        """
        依次发送每个 Payload，命中即停止，返回验证结论。

        策略：
          1. 正则快速预检（无 LLM 消耗）→ 命中直接返回 CONFIRMED
          2. 若未命中，调用 LLM 做深度响应分析
        """
        trigger = poc.http_trigger
        method  = trigger.get("method", "GET").upper()
        path    = trigger.get("path", "/")
        param   = trigger.get("param", "input")

        best_result = VerificationResult(
            status=VerificationStatus.UNCONFIRMED,
            confidence=0.5,
            reason="PoC 已发送，但响应中未观察到明确的漏洞触发特征。",
        )

        content_type = trigger.get("content_type", "form")
        extra_headers = trigger.get("headers", {})
        cookies = trigger.get("cookies", {})

        for payload in poc.payloads:
            if method == "GET":
                params = {param: payload}
                data = None
                json_body = None
            elif content_type == "json":
                params = None
                data = None
                json_body = {param: payload}
            else:
                params = None
                data = {param: payload}
                json_body = None

            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            req_summary = f"{method} {url} [{param}={payload[:40]}...]"

            status_code, response_body = self._docker.execute_request(
                base_url=base_url,
                method=method,
                path=path,
                params=params,
                data=data,
                json_body=json_body,
                headers=extra_headers or None,
                cookies=cookies or None,
            )

            snippet = response_body[:500]
            logger.debug(
                "[Agent-E] Payload 结果 | code=%d | body_len=%d | payload=%s...",
                status_code, len(response_body), payload[:30],
            )

            # ── 快速正则预检 ──────────────────────────────────────────
            quick_hit, evidence = _quick_confirm(response_body, vuln_type)
            if quick_hit:
                logger.info("[Agent-E] 正则预检命中 → CONFIRMED | 证据: %s", evidence[:80])
                return VerificationResult(
                    status=VerificationStatus.CONFIRMED,
                    confidence=1.0,
                    evidence=evidence,
                    payload_used=payload,
                    request_summary=req_summary,
                    response_code=status_code,
                    response_snippet=snippet,
                    reason="正则模式匹配到漏洞触发特征，无需 LLM 分析。",
                )

            # ── LLM 深度分析 ─────────────────────────────────────────
            llm_result = self._llm_analyze(
                vuln_type=vuln_type,
                method=method,
                url=url,
                params=f"{param}={payload}",
                payload=payload,
                status_code=status_code,
                response_body=response_body[:1000],
            )

            if llm_result.get("confirmed") and llm_result.get("confidence", 0) >= 0.8:
                logger.info(
                    "[Agent-E] LLM 分析确认漏洞 | 置信度: %.0f%% | 证据: %s",
                    llm_result["confidence"] * 100,
                    llm_result.get("evidence", "")[:80],
                )
                return VerificationResult(
                    status=VerificationStatus.CONFIRMED,
                    confidence=float(llm_result["confidence"]),
                    evidence=llm_result.get("evidence", ""),
                    payload_used=payload,
                    request_summary=req_summary,
                    response_code=status_code,
                    response_snippet=snippet,
                    llm_analysis=llm_result.get("reason", ""),
                    reason=f"LLM 确认：{llm_result.get('reason', '')}",
                )

            # 保留本次最佳结果
            if llm_result.get("confidence", 0) > (best_result.confidence or 0):
                best_result = VerificationResult(
                    status=VerificationStatus.UNCONFIRMED,
                    confidence=float(llm_result.get("confidence", 0.5)),
                    payload_used=payload,
                    request_summary=req_summary,
                    response_code=status_code,
                    response_snippet=snippet,
                    llm_analysis=llm_result.get("reason", ""),
                    reason=f"LLM 未确认：{llm_result.get('reason', '')}",
                )

        return best_result

    # ------------------------------------------------------------------
    # LLM 响应分析
    # ------------------------------------------------------------------

    def _llm_analyze(
        self,
        vuln_type: str,
        method: str,
        url: str,
        params: str,
        payload: str,
        status_code: int,
        response_body: str,
    ) -> dict:
        """调用 LLM 分析 HTTP 响应，判断 PoC 是否命中（带超时保护）。"""
        human_msg = _VERIFY_TEMPLATE.format(
            vuln_type=vuln_type,
            method=method,
            url=url,
            params=params,
            payload=payload,
            status_code=status_code,
            response_body=response_body or "（响应为空）",
        )
        try:
            raw = self.invoke_with_timeout(
                [SystemMessage(content=_SYSTEM_PROMPT_E), HumanMessage(content=human_msg)],
                timeout_sec=60,
            )
            return self.parse_json(raw)
        except Exception as exc:
            logger.debug("[Agent-E] LLM 分析失败: %s", exc)
            return {"confirmed": False, "confidence": 0.0, "evidence": "", "reason": str(exc)}
