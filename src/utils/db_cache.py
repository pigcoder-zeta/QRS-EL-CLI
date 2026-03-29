"""
CodeQL 数据库增量缓存管理器。

通过记录「仓库 URL + Git commit hash → 数据库路径」的映射，
避免对同一版本的代码库重复执行耗时的 `codeql database create`。

缓存索引持久化为 JSON 文件，存储于数据库根目录。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_CACHE_INDEX_FILENAME = "cache_index.json"


class DatabaseCache:
    """
    CodeQL 数据库增量缓存。

    缓存键格式：`<repo_url>#<commit_hash>`。
    缓存命中条件：相同 URL + 相同 commit hash + 数据库目录仍存在。

    Args:
        db_base_dir: 数据库根目录路径（cache_index.json 存于此处）。
    """

    def __init__(self, db_base_dir: str) -> None:
        self._base = Path(db_base_dir)
        self.db_base_dir = str(self._base)   # 公开属性，供外部读取
        self._base.mkdir(parents=True, exist_ok=True)
        self._index_path = self._base / _CACHE_INDEX_FILENAME
        self._index: dict[str, str] = self._load_index()

    # ------------------------------------------------------------------
    # 内部 I/O
    # ------------------------------------------------------------------

    def _load_index(self) -> dict[str, str]:
        if not self._index_path.exists():
            return {}
        try:
            with self._index_path.open(encoding="utf-8") as f:
                data = json.load(f)
            logger.debug("数据库缓存索引已加载，共 %d 条记录。", len(data))
            return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("缓存索引读取失败，将重新初始化: %s", exc)
            return {}

    def _save_index(self) -> None:
        try:
            with self._index_path.open("w", encoding="utf-8") as f:
                json.dump(self._index, f, indent=2, ensure_ascii=False)
        except OSError as exc:
            logger.warning("缓存索引写入失败: %s", exc)

    @staticmethod
    def _make_key(repo_url: str, commit_hash: str) -> str:
        return f"{repo_url}#{commit_hash}"

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def get(self, repo_url: str, commit_hash: str) -> Optional[str]:
        """
        查询缓存，返回已有数据库路径（若仍有效）。

        Args:
            repo_url: 仓库 URL。
            commit_hash: HEAD commit 的短 hash。

        Returns:
            数据库路径字符串，或 None（未命中 / 已失效）。
        """
        if not commit_hash:
            return None

        key = self._make_key(repo_url, commit_hash)
        db_path = self._index.get(key)

        if db_path and Path(db_path).is_dir():
            logger.info(
                "数据库缓存命中 [%s@%s] -> %s（跳过重新建库）",
                repo_url.split("/")[-1],
                commit_hash,
                db_path,
            )
            return db_path

        if db_path:
            # 记录存在但目录已删除，清理无效条目
            logger.debug("缓存条目已失效（目录不存在），移除: %s", db_path)
            del self._index[key]
            self._save_index()

        return None

    def put(self, repo_url: str, commit_hash: str, db_path: str) -> None:
        """
        将新建数据库记录写入缓存索引。

        Args:
            repo_url: 仓库 URL。
            commit_hash: HEAD commit 的短 hash。
            db_path: 数据库目录路径。
        """
        if not commit_hash:
            return

        key = self._make_key(repo_url, commit_hash)
        self._index[key] = db_path
        self._save_index()
        logger.info(
            "数据库缓存已记录 [%s@%s] -> %s",
            repo_url.split("/")[-1],
            commit_hash,
            db_path,
        )

    def invalidate(self, repo_url: str, commit_hash: str) -> None:
        """手动使某条缓存失效。"""
        key = self._make_key(repo_url, commit_hash)
        if key in self._index:
            del self._index[key]
            self._save_index()
            logger.info("已移除缓存条目: %s", key)
