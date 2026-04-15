import sqlite3
import json
import logging
import threading
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class ResultStore:
    """
    统一的 SQLite 数据持久化层，提供：
    1. Agent-R 的语义缓存 (降低相同代码段重复审查)
    2. 后续的扫描记录、数据库缓存索引、Pipeline Checkpoint 持久化
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: str = "data/argus_store.db"):
        if getattr(self, "_initialized", False):
            return
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()
        self._initialized = True

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None  # autocommit
            )
            # 开启 WAL 模式提高并发性能
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            with conn:
                # Agent-R 语义缓存表
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS agent_r_cache (
                        cache_key TEXT PRIMARY KEY,
                        verdict_json TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except Exception as exc:
            logger.error("初始化 ResultStore SQLite 数据库失败: %s", exc)

    # -------------------------------------------------------------------------
    # Agent-R 缓存接口
    # -------------------------------------------------------------------------

    def get_agent_r_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT verdict_json FROM agent_r_cache WHERE cache_key = ?",
                (cache_key,)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["verdict_json"])
        except Exception as exc:
            logger.warning("读取 Agent-R 缓存异常: %s", exc)
        return None

    def set_agent_r_cache(self, cache_key: str, verdict: Dict[str, Any]):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO agent_r_cache (cache_key, verdict_json)
                VALUES (?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    verdict_json=excluded.verdict_json,
                    created_at=CURRENT_TIMESTAMP
                """,
                (cache_key, json.dumps(verdict, ensure_ascii=False))
            )
        except Exception as exc:
            logger.warning("写入 Agent-R 缓存异常: %s", exc)
