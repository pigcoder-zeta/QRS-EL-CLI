"""
AgentBus：轻量级事件总线，解耦 Coordinator 与各 Agent 间的通信。

Agent 通过 publish() 发布结构化消息，Coordinator 或其他 Agent 通过
subscribe() 注册事件处理器，实现松耦合的阶段依赖关系。
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class AgentMessage:
    """Agent 间通信的结构化消息。"""

    sender: str
    event: str
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class AgentBus:
    """
    轻量级事件总线，支持同步事件分发。

    线程安全：可在 ThreadPoolExecutor 环境下使用。
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[[AgentMessage], None]]] = {}
        self._lock = threading.Lock()
        self._history: list[AgentMessage] = []

    def subscribe(
        self,
        event: str,
        handler: Callable[[AgentMessage], None],
    ) -> None:
        """注册事件处理器。"""
        with self._lock:
            self._handlers.setdefault(event, []).append(handler)

    def unsubscribe(
        self,
        event: str,
        handler: Callable[[AgentMessage], None],
    ) -> None:
        """移除事件处理器。"""
        with self._lock:
            if event in self._handlers:
                self._handlers[event] = [
                    h for h in self._handlers[event] if h is not handler
                ]

    def publish(self, msg: AgentMessage) -> None:
        """发布事件，同步调用所有已注册的处理器。"""
        with self._lock:
            self._history.append(msg)
            handlers = list(self._handlers.get(msg.event, []))
            handlers.extend(self._handlers.get("*", []))

        for handler in handlers:
            try:
                handler(msg)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[AgentBus] 处理器异常 | event=%s | handler=%s | error=%s",
                    msg.event, handler.__qualname__, exc,
                )

    @property
    def history(self) -> list[AgentMessage]:
        """返回消息历史（只读副本）。"""
        with self._lock:
            return list(self._history)

    def clear(self) -> None:
        """清空所有处理器和历史记录。"""
        with self._lock:
            self._handlers.clear()
            self._history.clear()
