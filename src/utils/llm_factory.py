"""
LLM 实例工厂：全局复用 ChatOpenAI 实例，避免每个 Agent 独立创建连接。

通过 (model, temperature, timeout, max_tokens, max_retries) 组合键缓存实例，
同参数的 Agent 共享同一个 HTTP 连接池，减少连接开销。

并发限流：通过全局信号量控制同时发起的 LLM 请求数，防止触发 API 速率限制（429）。
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Optional

from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_instances: dict[str, ChatOpenAI] = {}

_MAX_CONCURRENT_LLM = int(os.environ.get("LLM_MAX_CONCURRENT", "6"))
_llm_semaphore = threading.Semaphore(_MAX_CONCURRENT_LLM)


def get_semaphore() -> threading.Semaphore:
    """获取全局 LLM 并发信号量，供 BaseAgent.invoke_with_timeout 使用。"""
    return _llm_semaphore


def get_llm(
    *,
    temperature: float = 0.0,
    timeout: Optional[int] = None,
    max_tokens: Optional[int] = None,
    max_retries: int = 2,
    model: Optional[str] = None,
) -> ChatOpenAI:
    """
    获取或创建一个 ChatOpenAI 实例（按参数签名缓存）。

    Args:
        temperature: 采样温度。
        timeout: HTTP 超时秒数。
        max_tokens: 最大生成 token 数。
        max_retries: HTTP 层自动重试次数。
        model: 模型名称，默认读取 OPENAI_MODEL 环境变量。
    """
    model = model or os.environ.get("OPENAI_MODEL", "gpt-4o")
    key = f"{model}|t={temperature}|to={timeout}|mt={max_tokens}|mr={max_retries}"

    with _lock:
        if key not in _instances:
            kwargs: dict = dict(
                model=model,
                temperature=temperature,
                base_url=os.environ.get("OPENAI_BASE_URL") or None,
                max_retries=max_retries,
                use_responses_api=False,
            )
            if timeout is not None:
                kwargs["timeout"] = timeout
            if max_tokens is not None:
                kwargs["max_tokens"] = max_tokens

            _instances[key] = ChatOpenAI(**kwargs)
            logger.debug("[LLMFactory] 创建新实例: %s", key)
        return _instances[key]


def reset() -> None:
    """清空缓存（主要用于测试）。"""
    global _llm_semaphore
    with _lock:
        _instances.clear()
    _llm_semaphore = threading.Semaphore(_MAX_CONCURRENT_LLM)
