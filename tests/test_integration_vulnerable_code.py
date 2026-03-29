"""
Phase 8b：集成测试 — 内置易漏代码绝对路径验证。

这些测试不依赖 CodeQL CLI 或 LLM，而是：
1. 在 tmp_path 下创建真实的 Java/Python 易漏代码文件
2. 验证 Agent-R 审查逻辑能正确识别关键代码模式
3. 验证 Agent-S 内置 Payload 策略与引擎匹配逻辑

注意：完整端到端测试（含 CodeQL 扫描）需要 codeql CLI，
      在 CI 中通过 pytest -m "not requires_codeql" 跳过。
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.agents.agent_r import (
    ReviewResult, SarifFinding, VulnStatus,
    _load_code_context, _parse_sarif,
)
from src.agents.agent_s import AgentS, PoCResult, _match_payloads
from src.orchestrator.coordinator import PipelineState


# ---------------------------------------------------------------------------
# 内置易漏代码片段
# ---------------------------------------------------------------------------

_JAVA_SPEL_VULNERABLE = """\
package com.example;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.*;

@RestController
public class EvalController {

    @PostMapping("/eval")
    public String evaluate(@RequestParam String expr) {
        // 危险：直接将用户输入传入 parseExpression
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        return parser.parseExpression(expr).getValue(ctx, String.class);
    }
}
"""

_JAVA_SPEL_SAFE = """\
package com.example;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

@RestController
public class SafeEvalController {

    @PostMapping("/safe-eval")
    public String evaluate(@RequestParam String expr) {
        // 安全：使用 SimpleEvaluationContext，限制功能集
        ExpressionParser parser = new SpelExpressionParser();
        SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return parser.parseExpression(expr).getValue(ctx, String.class);
    }
}
"""

_PYTHON_JINJA2_VULNERABLE = """\
from flask import Flask, request
import jinja2

app = Flask(__name__)

@app.route('/render')
def render():
    template_str = request.args.get('tmpl', '')
    # 危险：直接将用户输入作为模板字符串
    env = jinja2.Environment()
    return env.from_string(template_str).render()
"""

_MOCK_SARIF = {
    "runs": [
        {
            "results": [
                {
                    "ruleId": "java/spring-el-injection",
                    "message": {"text": "User data flows into parseExpression"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/EvalController.java"},
                                "region": {"startLine": 15},
                            }
                        }
                    ],
                }
            ]
        }
    ]
}


# ---------------------------------------------------------------------------
# 代码上下文读取测试
# ---------------------------------------------------------------------------

class TestLoadCodeContext:

    def test_reads_context_around_line(self, tmp_path):
        java_file = tmp_path / "src" / "EvalController.java"
        java_file.parent.mkdir(parents=True)
        java_file.write_text(_JAVA_SPEL_VULNERABLE, encoding="utf-8")

        ctx = _load_code_context(
            repo_root=str(tmp_path),
            file_uri="src/EvalController.java",
            center_line=15,
            window=3,
        )
        assert "parseExpression" in ctx
        assert "15" in ctx  # 行号前缀

    def test_missing_file_returns_placeholder(self, tmp_path):
        ctx = _load_code_context(str(tmp_path), "nonexistent.java", 1)
        assert "无法读取" in ctx or "nonexistent" in ctx

    def test_line_numbers_in_context(self, tmp_path):
        java_file = tmp_path / "Foo.java"
        java_file.write_text("line1\nline2\nline3\nline4\nline5", encoding="utf-8")
        ctx = _load_code_context(str(tmp_path), "Foo.java", 3, window=1)
        # 应包含行号 2,3,4
        assert "2" in ctx
        assert "3" in ctx
        assert "4" in ctx


# ---------------------------------------------------------------------------
# SARIF 解析测试
# ---------------------------------------------------------------------------

class TestParseSarif:

    def test_parses_findings(self, tmp_path):
        sarif_path = tmp_path / "results.sarif"
        sarif_path.write_text(
            json.dumps(_MOCK_SARIF), encoding="utf-8"
        )
        findings = _parse_sarif(str(sarif_path))
        assert len(findings) == 1
        assert findings[0].rule_id == "java/spring-el-injection"
        assert findings[0].start_line == 15
        assert findings[0].file_uri == "src/EvalController.java"

    def test_empty_sarif(self, tmp_path):
        sarif_path = tmp_path / "empty.sarif"
        sarif_path.write_text(json.dumps({"runs": [{"results": []}]}))
        findings = _parse_sarif(str(sarif_path))
        assert findings == []

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            _parse_sarif("/nonexistent/results.sarif")


# ---------------------------------------------------------------------------
# Agent-S Payload 匹配测试
# ---------------------------------------------------------------------------

class TestAgentSPayloadMatching:

    @pytest.mark.parametrize("engine, expected_fragment", [
        ("Spring EL",  "Runtime"),
        ("spring el",  "Runtime"),
        ("OGNL",       "Runtime"),
        ("MVEL",       "Runtime"),
        ("Jinja2",     "os"),
        ("jinja2",     "os"),
        ("Mako",       "os"),
    ])
    def test_payload_match(self, engine, expected_fragment):
        payloads = _match_payloads(engine)
        assert len(payloads) >= 1
        combined = " ".join(payloads)
        assert expected_fragment in combined

    def test_unknown_engine_fallback(self):
        payloads = _match_payloads("Unknown Engine XYZ")
        assert len(payloads) >= 1   # 降级到 SpEL

    def test_payloads_are_strings(self):
        for engine in ["Spring EL", "OGNL", "Jinja2", "Mako"]:
            payloads = _match_payloads(engine)
            assert all(isinstance(p, str) for p in payloads)


# ---------------------------------------------------------------------------
# Agent-S generate_poc mock 测试
# ---------------------------------------------------------------------------

class TestAgentSGeneratePoc:

    def _make_review(self, engine: str = "Spring EL") -> ReviewResult:
        finding = SarifFinding(
            rule_id="java/spring-el-injection",
            message="test",
            file_uri="src/EvalController.java",
            start_line=15,
            code_context="parser.parseExpression(userInput)",
        )
        return ReviewResult(
            finding=finding,
            status=VulnStatus.VULNERABLE,
            confidence=0.9,
            engine_detected=engine,
            reasoning="StandardEvaluationContext 确认为漏洞。",
        )

    def test_generate_poc_returns_poc_result(self, no_llm_calls):
        """模拟 LLM 返回 JSON PoC，验证 PoCResult 正确构建。"""
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = json.dumps({
            "payloads": ["T(java.lang.Runtime).getRuntime().exec('id')"],
            "http_trigger": {"method": "POST", "path": "/eval", "param": "expr",
                             "example": "curl -d 'expr=...' http://target/eval"},
            "expected_output": "uid=0(root)...",
            "severity": "critical",
        })

        agent = AgentS()
        agent.llm = MagicMock()
        agent.llm.__or__ = MagicMock(return_value=mock_chain)
        agent._parser = MagicMock()
        agent._parser.__ror__ = MagicMock(return_value=mock_chain)

        finding = self._make_review()
        poc = agent.generate_poc(finding)

        assert isinstance(poc, PoCResult)
        assert poc.severity == "critical"
        assert len(poc.payloads) >= 1
        assert poc.http_trigger.get("method") == "POST"

    def test_generate_all_empty_returns_empty(self):
        agent = AgentS()
        result = agent.generate_all([])
        assert result == []

    def test_poc_file_location_format(self, no_llm_calls):
        """验证 PoCResult.file_location 格式为 file:line。"""
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = json.dumps({
            "payloads": ["test"],
            "http_trigger": {},
            "expected_output": "uid=0",
            "severity": "high",
        })

        agent = AgentS()
        agent.llm = MagicMock()
        agent.llm.__or__ = MagicMock(return_value=mock_chain)
        agent._parser = MagicMock()
        agent._parser.__ror__ = MagicMock(return_value=mock_chain)

        finding = self._make_review()
        poc = agent.generate_poc(finding)
        assert ":" in poc.file_location
        assert "EvalController.java" in poc.file_location


# ---------------------------------------------------------------------------
# Vulnerable code fixture（供手工端到端测试参考）
# ---------------------------------------------------------------------------

@pytest.fixture
def vulnerable_java_repo(tmp_path) -> Path:
    """创建一个包含 SpEL 漏洞的最小 Java 项目（供手工 CodeQL 测试用）。"""
    src = tmp_path / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "EvalController.java").write_text(_JAVA_SPEL_VULNERABLE, encoding="utf-8")
    (src / "SafeEvalController.java").write_text(_JAVA_SPEL_SAFE, encoding="utf-8")
    # 简单 pom.xml（让 CodeQL 识别为 Maven 项目）
    pom = tmp_path / "pom.xml"
    pom.write_text("""<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>test-app</artifactId>
  <version>1.0</version>
</project>""", encoding="utf-8")
    return tmp_path


@pytest.fixture
def vulnerable_python_repo(tmp_path) -> Path:
    """创建一个包含 Jinja2 SSTI 漏洞的最小 Python 项目。"""
    app = tmp_path / "app.py"
    app.write_text(_PYTHON_JINJA2_VULNERABLE, encoding="utf-8")
    return tmp_path
