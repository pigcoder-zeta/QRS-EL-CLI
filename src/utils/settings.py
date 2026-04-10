"""
Argus 全局配置中心：通过 Pydantic BaseSettings 统一管理环境变量。

所有散布在各模块中的 os.environ.get() 调用均可迁移到此处，
实现环境变量的集中校验、默认值管理和类型安全。

使用方式：
    from src.utils.settings import get_settings
    settings = get_settings()
    print(settings.openai_model)
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from pydantic import BaseModel, Field


class ArgusSettings(BaseModel):
    """Argus 系统全局配置（从环境变量加载）。"""

    # ── LLM 配置 ──────────────────────────────────────────────────────
    openai_api_key: str = Field(default="", description="OpenAI API Key")
    openai_base_url: str = Field(default="", description="OpenAI API Base URL")
    openai_model: str = Field(default="gpt-4o", description="默认 LLM 模型名称")

    # ── LLM 并发与超时 ──────────────────────────────────────────────
    llm_max_concurrent: int = Field(default=6, description="LLM 最大并发请求数")
    agent_r_timeout: int = Field(default=120, description="Agent-R LLM 调用超时（秒）")
    agent_r_max_tokens: int = Field(default=4096, description="Agent-R 最大生成 token 数")

    # ── Flask / Web ──────────────────────────────────────────────────
    flask_secret_key: str = Field(default="", description="Flask session 密钥")
    argus_api_key: str = Field(default="", description="Web API 鉴权密钥")
    argus_rate_limit: int = Field(default=30, description="API 速率限制（次/分钟）")

    # ── 数据目录 ──────────────────────────────────────────────────────
    data_dir: str = Field(default="data", description="数据根目录")

    @classmethod
    def from_env(cls) -> "ArgusSettings":
        """从当前环境变量构造 Settings 实例。"""
        return cls(
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
            openai_base_url=os.environ.get("OPENAI_BASE_URL", ""),
            openai_model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
            llm_max_concurrent=int(os.environ.get("LLM_MAX_CONCURRENT", "6")),
            agent_r_timeout=int(os.environ.get("AGENT_R_TIMEOUT", "120")),
            agent_r_max_tokens=int(os.environ.get("AGENT_R_MAX_TOKENS", "4096")),
            flask_secret_key=os.environ.get("FLASK_SECRET_KEY", ""),
            argus_api_key=os.environ.get("ARGUS_API_KEY", ""),
            argus_rate_limit=int(os.environ.get("ARGUS_RATE_LIMIT", "30")),
            data_dir=os.environ.get("ARGUS_DATA_DIR", "data"),
        )


@lru_cache(maxsize=1)
def get_settings() -> ArgusSettings:
    """获取全局 Settings 单例（首次调用时从环境变量加载）。"""
    return ArgusSettings.from_env()


def reset_settings() -> None:
    """清除缓存，强制下次重新加载（主要用于测试）。"""
    get_settings.cache_clear()
