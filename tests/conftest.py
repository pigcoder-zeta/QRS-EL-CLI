"""
pytest 全局配置与共享 Fixtures。

确保测试不需要真实的 OPENAI_API_KEY 和 CodeQL CLI。
"""

import os
import pytest


def pytest_configure(config):
    """在测试开始前设置必要的环境变量（避免 LLM 初始化报错）。"""
    os.environ.setdefault("OPENAI_API_KEY", "sk-test-dummy-key-for-unit-tests")
    os.environ.setdefault("OPENAI_MODEL", "gpt-4o-mini")


@pytest.fixture(autouse=False)
def no_llm_calls(monkeypatch):
    """
    强制禁止真实 LLM 调用的 Fixture（按需使用）。

    在测试函数参数中声明 no_llm_calls 即可激活。
    """
    from unittest.mock import MagicMock
    import langchain_openai

    mock_llm = MagicMock()
    monkeypatch.setattr(langchain_openai, "ChatOpenAI", lambda **kw: mock_llm)
    return mock_llm
