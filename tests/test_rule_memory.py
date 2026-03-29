"""测试 RuleMemory：归档、检索、持久化。"""

import json
import shutil
import tempfile
from pathlib import Path

import pytest
from src.utils.rule_memory import RuleMemory, RuleRecord


@pytest.fixture
def tmp_memory(tmp_path):
    """返回一个使用临时目录的 RuleMemory 实例。"""
    return RuleMemory(memory_dir=str(tmp_path / "rule_memory"), use_neural=False)


@pytest.fixture
def sample_ql(tmp_path) -> Path:
    """创建一个临时 .ql 文件用于测试。"""
    ql_file = tmp_path / "test.ql"
    ql_file.write_text("// sample CodeQL query\nselect 1", encoding="utf-8")
    return ql_file


class TestRuleMemorySave:

    def test_save_returns_record(self, tmp_memory, sample_ql):
        record = tmp_memory.save("java", "Spring EL Injection", str(sample_ql))
        assert isinstance(record, RuleRecord)
        assert record.language == "java"
        assert record.vuln_type == "Spring EL Injection"

    def test_saved_file_exists(self, tmp_memory, sample_ql):
        record = tmp_memory.save("java", "OGNL Injection", str(sample_ql))
        assert Path(record.query_path).exists()

    def test_count_increases(self, tmp_memory, sample_ql):
        assert tmp_memory.count() == 0
        tmp_memory.save("java", "SpEL", str(sample_ql))
        assert tmp_memory.count() == 1
        tmp_memory.save("python", "Jinja2 SSTI", str(sample_ql))
        assert tmp_memory.count() == 2

    def test_index_persisted_to_disk(self, tmp_memory, sample_ql):
        tmp_memory.save("java", "MVEL", str(sample_ql))
        assert tmp_memory.index_path.exists()
        with open(tmp_memory.index_path, encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["records"]) == 1

    def test_save_with_tags(self, tmp_memory, sample_ql):
        record = tmp_memory.save("java", "EL", str(sample_ql), tags=["spring", "rce"])
        assert "spring" in record.tags

    def test_save_missing_file_raises(self, tmp_memory):
        with pytest.raises(FileNotFoundError):
            tmp_memory.save("java", "Test", "/nonexistent/file.ql")


class TestRuleMemorySearch:

    def test_search_finds_similar(self, tmp_memory, sample_ql):
        tmp_memory.save("java", "Spring EL Injection", str(sample_ql))
        results = tmp_memory.search("java", "Spring EL Injection", top_k=1)
        assert len(results) == 1
        record, score = results[0]
        assert score > 0.0

    def test_search_filters_by_language(self, tmp_memory, sample_ql):
        tmp_memory.save("java", "SpEL Injection", str(sample_ql))
        tmp_memory.save("python", "Jinja2 SSTI", str(sample_ql))
        results = tmp_memory.search("python", "SSTI", top_k=5)
        for record, _ in results:
            assert record.language == "python"

    def test_search_empty_memory_returns_empty(self, tmp_memory):
        results = tmp_memory.search("java", "SpEL")
        assert results == []

    def test_top_k_limits_results(self, tmp_memory, sample_ql):
        for i in range(5):
            tmp_memory.save("java", f"EL variant {i}", str(sample_ql))
        results = tmp_memory.search("java", "EL injection", top_k=2)
        assert len(results) <= 2

    def test_load_query_code(self, tmp_memory, sample_ql):
        record = tmp_memory.save("java", "SpEL", str(sample_ql))
        code = tmp_memory.load_query_code(record)
        assert "CodeQL" in code

    def test_load_missing_file_raises(self, tmp_memory, sample_ql):
        record = tmp_memory.save("java", "Test", str(sample_ql))
        Path(record.query_path).unlink()
        with pytest.raises(FileNotFoundError):
            tmp_memory.load_query_code(record)


class TestRuleMemoryPersistence:

    def test_reload_from_disk(self, tmp_path, sample_ql):
        mem1 = RuleMemory(str(tmp_path / "mem"), use_neural=False)
        mem1.save("java", "SpEL", str(sample_ql))

        mem2 = RuleMemory(str(tmp_path / "mem"), use_neural=False)
        assert mem2.count() == 1

    def test_repr(self, tmp_memory):
        assert "RuleMemory" in repr(tmp_memory)
