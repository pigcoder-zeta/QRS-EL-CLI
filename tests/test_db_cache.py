"""测试 DatabaseCache：命中/未命中、过期路径清理。"""

import json
from pathlib import Path

import pytest
from src.utils.db_cache import DatabaseCache


@pytest.fixture
def cache(tmp_path):
    return DatabaseCache(db_base_dir=str(tmp_path / "databases"))


class TestDatabaseCache:

    def test_get_missing_returns_none(self, cache):
        result = cache.get("https://github.com/example/repo", "abc123")
        assert result is None

    def test_put_and_get(self, cache, tmp_path):
        db_path = str(tmp_path / "mydb")
        Path(db_path).mkdir()
        cache.put("https://github.com/example/repo", "abc123", db_path)
        result = cache.get("https://github.com/example/repo", "abc123")
        assert result == db_path

    def test_get_stale_path_returns_none(self, cache):
        """缓存的 db_path 不存在时应返回 None。"""
        cache.put("https://github.com/example/repo", "abc123", "/nonexistent/path")
        result = cache.get("https://github.com/example/repo", "abc123")
        assert result is None

    def test_different_commit_hashes(self, cache, tmp_path):
        db1 = str(tmp_path / "db1")
        db2 = str(tmp_path / "db2")
        Path(db1).mkdir()
        Path(db2).mkdir()
        cache.put("https://github.com/example/repo", "hash1", db1)
        cache.put("https://github.com/example/repo", "hash2", db2)
        assert cache.get("https://github.com/example/repo", "hash1") == db1
        assert cache.get("https://github.com/example/repo", "hash2") == db2

    def test_different_repos_same_hash(self, cache, tmp_path):
        db1 = str(tmp_path / "db1")
        db2 = str(tmp_path / "db2")
        Path(db1).mkdir()
        Path(db2).mkdir()
        cache.put("https://github.com/repo1", "abc123", db1)
        cache.put("https://github.com/repo2", "abc123", db2)
        assert cache.get("https://github.com/repo1", "abc123") == db1
        assert cache.get("https://github.com/repo2", "abc123") == db2

    def test_index_file_created(self, cache, tmp_path):
        db_path = str(tmp_path / "db")
        Path(db_path).mkdir()
        cache.put("https://github.com/example/repo", "abc123", db_path)
        index_file = Path(cache.db_base_dir) / "cache_index.json"
        assert index_file.exists()

    def test_overwrite_same_key(self, cache, tmp_path):
        db1 = str(tmp_path / "db1")
        db2 = str(tmp_path / "db2")
        Path(db1).mkdir()
        Path(db2).mkdir()
        cache.put("https://github.com/example/repo", "abc123", db1)
        cache.put("https://github.com/example/repo", "abc123", db2)
        result = cache.get("https://github.com/example/repo", "abc123")
        assert result == db2
