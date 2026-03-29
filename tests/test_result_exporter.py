"""测试 result_exporter 与 html_reporter 的导出功能。"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.agents.agent_r import ReviewResult, SarifFinding, VulnStatus
from src.agents.agent_s import PoCResult
from src.orchestrator.coordinator import PipelineState
from src.utils.result_exporter import export_json, export_summary_text
from src.utils.html_reporter import export_html


def _make_finding(file_uri: str = "src/Foo.java", line: int = 42) -> SarifFinding:
    return SarifFinding(
        rule_id="java/spring-el-injection",
        message="User-controlled data flows into parseExpression",
        file_uri=file_uri,
        start_line=line,
        code_context="42 | parser.parseExpression(userInput);",
    )


def _make_review(status: VulnStatus = VulnStatus.VULNERABLE) -> ReviewResult:
    return ReviewResult(
        finding=_make_finding(),
        status=status,
        confidence=0.9,
        engine_detected="Spring EL",
        reasoning="StandardEvaluationContext 被使用，无净化逻辑，确认为漏洞。",
        sink_method="org.springframework.expression.ExpressionParser.parseExpression",
    )


def _make_poc() -> PoCResult:
    return PoCResult(
        engine="Spring EL",
        sink_method="parseExpression",
        file_location="src/Foo.java:42",
        payloads=["T(java.lang.Runtime).getRuntime().exec('id')"],
        http_trigger={"method": "POST", "path": "/api/eval", "param": "expr"},
        expected_output="uid=0(root)...",
        severity="critical",
    )


def _make_state(
    vuln_type: str = "Spring EL Injection",
    with_review: bool = True,
    with_poc: bool = True,
    error: str | None = None,
) -> PipelineState:
    state = PipelineState(vuln_type=vuln_type)
    state.source_dir = "/tmp/repo"
    state.db_path = "/tmp/db"
    state.query_path = "data/queries/java/test.ql"
    state.sarif_path = "data/results/test.sarif"
    state.completed_phases = ["create_database", "generate_query", "analyze", "review"]
    state.error = error
    if with_review:
        state.review_results = [_make_review(VulnStatus.VULNERABLE), _make_review(VulnStatus.SAFE)]
    if with_poc:
        state.poc_results = [_make_poc()]
    return state


class TestExportJSON:

    def test_creates_file(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.json")
        export_json([state], out, language="java")
        assert Path(out).exists()

    def test_json_structure(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.json")
        export_json([state], out, language="java")
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert "meta" in data
        assert "runs" in data
        assert data["meta"]["language"] == "java"
        assert data["meta"]["total_runs"] == 1

    def test_vulnerable_count(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.json")
        export_json([state], out, language="java")
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        run = data["runs"][0]
        assert run["stats"]["vulnerable"] == 1
        assert run["stats"]["safe"] == 1

    def test_poc_in_findings(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.json")
        export_json([state], out, language="java")
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        findings = data["runs"][0]["findings"]
        vuln_findings = [f for f in findings if f["status"] == "vulnerable"]
        assert len(vuln_findings) == 1
        assert vuln_findings[0]["poc"] is not None

    def test_failed_state(self, tmp_path):
        state = _make_state(with_review=False, with_poc=False, error="CodeQL 失败")
        out = str(tmp_path / "report.json")
        export_json([state], out)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert data["runs"][0]["status"] == "failed"

    def test_multiple_states(self, tmp_path):
        states = [_make_state("SpEL"), _make_state("OGNL")]
        out = str(tmp_path / "report.json")
        export_json(states, out, language="java")
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert data["meta"]["total_runs"] == 2


class TestExportHTML:

    def test_creates_html_file(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.html")
        export_html([state], out, language="java")
        assert Path(out).exists()

    def test_html_contains_vuln_type(self, tmp_path):
        state = _make_state(vuln_type="Spring EL Injection")
        out = str(tmp_path / "report.html")
        export_html([state], out, language="java")
        content = Path(out).read_text(encoding="utf-8")
        assert "Spring EL Injection" in content

    def test_html_contains_payload(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.html")
        export_html([state], out, language="java")
        content = Path(out).read_text(encoding="utf-8")
        assert "Runtime" in content

    def test_html_is_valid_structure(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.html")
        export_html([state], out)
        content = Path(out).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content
        assert "<title>" in content

    def test_html_no_external_resources(self, tmp_path):
        state = _make_state()
        out = str(tmp_path / "report.html")
        export_html([state], out)
        content = Path(out).read_text(encoding="utf-8")
        assert "cdn." not in content
        assert 'src="http' not in content


class TestExportSummaryText:

    def test_summary_contains_vuln_type(self):
        state = _make_state(vuln_type="OGNL Injection")
        text = export_summary_text([state])
        assert "OGNL Injection" in text

    def test_summary_shows_vulnerability_count(self):
        state = _make_state()
        text = export_summary_text([state])
        assert "1" in text

    def test_failed_state_summary(self):
        state = _make_state(with_review=False, with_poc=False, error="建库失败")
        text = export_summary_text([state])
        assert "失败" in text
