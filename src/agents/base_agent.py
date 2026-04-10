"""
BaseAgent：所有 Agent 的公共基类。

提取 6 个 Agent 共有的横切逻辑：
  - LLM 实例获取（通过 LLMFactory 复用）
  - JSON 响应解析（容忍 markdown 代码块包裹）
  - 带超时的 LLM 调用
  - 统一重试装饰器
  - 结构化指标采集
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Optional

from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from src.utils.llm_factory import get_llm

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 结构化指标
# ---------------------------------------------------------------------------


@dataclass
class AgentMetrics:
    """轻量级 LLM 调用指标采集器（线程安全）。"""

    llm_calls: int = 0
    llm_errors: int = 0
    llm_total_latency: float = 0.0
    llm_total_tokens: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_call(self, latency: float, tokens: int = 0, success: bool = True) -> None:
        with self._lock:
            self.llm_calls += 1
            self.llm_total_latency += latency
            self.llm_total_tokens += tokens
            if not success:
                self.llm_errors += 1

    def summary(self) -> dict[str, Any]:
        with self._lock:
            avg = (self.llm_total_latency / self.llm_calls) if self.llm_calls else 0
            err_rate = (self.llm_errors / self.llm_calls) if self.llm_calls else 0
            return {
                "total_calls": self.llm_calls,
                "total_errors": self.llm_errors,
                "error_rate": round(err_rate, 4),
                "avg_latency_sec": round(avg, 2),
                "total_latency_sec": round(self.llm_total_latency, 2),
                "total_tokens": self.llm_total_tokens,
            }


# ---------------------------------------------------------------------------
# 统一重试装饰器
# ---------------------------------------------------------------------------

_RETRYABLE_KEYWORDS = (
    "503", "502", "429", "DOCTYPE", "html",
    "超时", "Timeout", "JSON", "解析失败", "空响应",
)


def llm_retry(
    max_retries: int = 3,
    backoff_factor: float = 2.0,
    fallback: Optional[Callable] = None,
):
    """
    LLM 调用统一重试装饰器。

    支持指数退避和可选的 fallback 降级函数。
    仅对可重试的错误（网络/限流/解析）进行重试。
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Optional[Exception] = None
            for attempt in range(1, max_retries + 1):
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    exc_str = str(exc)
                    is_retryable = any(kw in exc_str for kw in _RETRYABLE_KEYWORDS)
                    if is_retryable and attempt < max_retries:
                        wait = backoff_factor ** attempt
                        logger.warning(
                            "[%s] 第 %d/%d 次尝试失败 (%s), %.0fs 后重试...",
                            fn.__qualname__, attempt, max_retries,
                            type(exc).__name__, wait,
                        )
                        time.sleep(wait)
                        continue
                    break
            if fallback is not None:
                return fallback(*args, **kwargs)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# BaseAgent 基类
# ---------------------------------------------------------------------------


class BaseAgent:
    """所有 Agent 的公共基类。"""

    agent_name: str = "BaseAgent"

    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        *,
        temperature: float = 0.0,
        timeout: Optional[int] = None,
        max_tokens: Optional[int] = None,
        max_retries: int = 2,
    ) -> None:
        self.llm: ChatOpenAI = llm or get_llm(
            temperature=temperature,
            timeout=timeout,
            max_tokens=max_tokens,
            max_retries=max_retries,
        )
        self._parser = StrOutputParser()
        self.metrics = AgentMetrics()

    # ------------------------------------------------------------------
    # JSON 解析
    # ------------------------------------------------------------------

    @staticmethod
    def parse_json(raw: str) -> dict[str, Any]:
        """
        从 LLM 原始输出中提取 JSON 对象，容忍 markdown 代码块包裹。

        Raises:
            ValueError: JSON 解析失败时抛出。
        """
        text = raw.strip() if raw else ""
        if not text:
            raise ValueError("LLM 返回空响应")
        if "```" in text:
            m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
            if m:
                text = m.group(1).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM 返回的 JSON 无效: {exc}\n原始内容:\n{raw}") from exc

    @staticmethod
    def parse_json_array(raw: str, expected_count: int = 0) -> list[dict[str, Any]]:
        """
        从 LLM 原始输出中提取 JSON 数组。

        Raises:
            ValueError: JSON 解析失败时抛出。
        """
        text = raw.strip() if raw else ""
        if not text:
            raise ValueError("LLM 返回空响应")

        if "```" in text:
            m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
            if m:
                text = m.group(1).strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            bracket_start = text.find("[")
            bracket_end = text.rfind("]")
            if bracket_start != -1 and bracket_end > bracket_start:
                try:
                    parsed = json.loads(text[bracket_start: bracket_end + 1])
                except json.JSONDecodeError as exc2:
                    raise ValueError(
                        f"批量 JSON 解析失败: {exc2}\n原始内容:\n{raw[:500]}"
                    ) from exc2
            else:
                brace_start = text.find("{")
                brace_end = text.rfind("}")
                if brace_start != -1 and brace_end > brace_start:
                    try:
                        parsed = [json.loads(text[brace_start: brace_end + 1])]
                    except json.JSONDecodeError as exc3:
                        raise ValueError(
                            f"批量 JSON 解析失败: {exc3}\n原始内容:\n{raw[:500]}"
                        ) from exc3
                else:
                    raise ValueError(
                        f"批量 JSON 解析失败: 未找到 JSON 结构\n原始内容:\n{raw[:500]}"
                    )

        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
        raise ValueError(f"期望 JSON 数组，实际类型: {type(parsed).__name__}")

    # ------------------------------------------------------------------
    # 带超时的 LLM 调用
    # ------------------------------------------------------------------

    def invoke_with_timeout(
        self,
        messages: list,
        timeout_sec: int = 120,
        heartbeat_interval: int = 30,
    ) -> str:
        """
        带超时、心跳日志和全局并发限流的 LLM 调用。

        使用 ThreadPoolExecutor + future.result(timeout) 替代手动 Thread 管理。
        通过 LLMFactory 的全局信号量控制并发数，防止触发 API 429 限流。

        Args:
            messages: LangChain 消息列表。
            timeout_sec: 最大等待秒数。
            heartbeat_interval: 心跳日志间隔秒数。

        Returns:
            LLM 原始文本响应。

        Raises:
            TimeoutError: 超过 timeout_sec 时抛出。
        """
        from src.utils.llm_factory import get_semaphore

        chain = self.llm | self._parser
        sem = get_semaphore()
        t0 = time.time()

        def _guarded_invoke(msgs: list) -> str:
            with sem:
                return chain.invoke(msgs)

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_guarded_invoke, messages)
            while True:
                try:
                    remaining = timeout_sec - (time.time() - t0)
                    if remaining <= 0:
                        future.cancel()
                        self.metrics.record_call(time.time() - t0, success=False)
                        raise TimeoutError(
                            f"[{self.agent_name}] LLM 调用超时 (>{timeout_sec}s)"
                        )
                    wait_time = min(heartbeat_interval, remaining)
                    result = future.result(timeout=wait_time)
                    elapsed = time.time() - t0
                    self.metrics.record_call(elapsed, success=True)
                    logger.info("[%s] LLM 响应完成 (%.1fs)", self.agent_name, elapsed)
                    return result
                except FutureTimeoutError:
                    elapsed = time.time() - t0
                    if elapsed >= timeout_sec:
                        future.cancel()
                        self.metrics.record_call(elapsed, success=False)
                        raise TimeoutError(
                            f"[{self.agent_name}] LLM 调用超时 (>{timeout_sec}s)"
                        )
                    logger.info(
                        "[%s] [WAIT] 等待 LLM 响应... %.0fs / %ds",
                        self.agent_name, elapsed, timeout_sec,
                    )
