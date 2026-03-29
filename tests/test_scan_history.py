"""测试 ScanHistory：写入、读取、统计。"""

import json
from pathlib import Path

import pytest
from src.orchestrator.coordinator import PipelineState
from src.agents.agent_r import ReviewResult, SarifFinding, VulnStatus
from src.utils.scan_history import ScanHistory


def _make_state(vuln_type: str = "SpEL", error: str | None = None) -> PipelineState:
    state = PipelineState(vuln_type=vuln_type)
    state.commit_hash = "abc123"
    state.completed_phases = ["create_database", "generate_query", "analyze"]
    state.error = error
    if not error:
        finding = SarifFinding("rule/spel", "msg", "Foo.java", 10)
        state.review_results = [
            ReviewResult(
                finding=finding,
                status=VulnStatus.VULNERABLE,
                confidence=0.9,
                engine_detected="Spring EL",
                reasoning="confirmed",
            )
        ]
    return state


@pytest.fixture
def history(tmp_path) -> ScanHistory:
    return ScanHistory(history_dir=str(tmp_path))


class TestScanHistory:

    def test_record_creates_file(self, history, tmp_path):
        history.record([_make_state()], language="java", source="http://example.com")
        assert history.history_path.exists()

    def test_record_count(self, history):
        assert history.count() == 0
        history.record([_make_state("SpEL"), _make_state("OGNL")], language="java")
        assert history.count() == 2

    def test_record_fields(self, history):
        history.record([_make_state("MVEL")], language="java", source="http://x.com")
        entry = history.recent(1)[0]
        assert entry["language"] == "java"
        assert entry["vuln_type"] == "MVEL"
        assert entry["source"] == "http://x.com"
        assert entry["commit_hash"] == "abc123"
        assert entry["status"] == "success"
        assert entry["vulnerable"] == 1

    def test_failed_state_recorded(self, history):
        history.record([_make_state(error="build failed")], language="java")
        entry = history.recent(1)[0]
        assert entry["status"] == "failed"
        assert entry["error"] == "build failed"

    def test_recent_returns_latest_first(self, history):
        history.record([_make_state("A")], language="java")
        history.record([_make_state("B")], language="java")
        recent = history.recent(2)
        assert recent[0]["vuln_type"] == "B"
        assert recent[1]["vuln_type"] == "A"

    def test_stats(self, history):
        history.record([_make_state("SpEL")], language="java")
        history.record([_make_state(error="fail")], language="python")
        stats = history.stats()
        assert stats["total_runs"] == 2
        assert stats["success_runs"] == 1
        assert stats["failed_runs"] == 1
        assert stats["total_vulnerabilities_found"] == 1
        assert "java" in stats["languages"]
        assert "python" in stats["languages"]

    def test_persistence(self, tmp_path):
        h1 = ScanHistory(str(tmp_path))
        h1.record([_make_state("SpEL")], language="java")
        h2 = ScanHistory(str(tmp_path))
        assert h2.count() == 1

    def test_max_entries_rolling(self, tmp_path):
        import src.utils.scan_history as mod
        original = mod._MAX_HISTORY_ENTRIES
        mod._MAX_HISTORY_ENTRIES = 3
        try:
            h = ScanHistory(str(tmp_path))
            for i in range(5):
                h.record([_make_state(f"v{i}")], language="java")
            assert h.count() <= 3
        finally:
            mod._MAX_HISTORY_ENTRIES = original

    def test_elapsed_seconds_stored(self, history):
        history.record([_make_state()], language="java", elapsed_seconds=42.5)
        entry = history.recent(1)[0]
        assert entry["elapsed_seconds"] == 42.5
