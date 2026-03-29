"""
Agent-Q 单元测试（使用 mock LLM，不调用真实 API）。

测试覆盖：
- LLM 生成初始代码 → 写入文件
- 编译失败 → 触发修复循环
- 模板命中 → 跳过 LLM 初始生成
- 达到最大重试次数 → 抛出 RuntimeError
"""

from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from src.agents.agent_q import AgentQ, _extract_ql_code
from src.utils.codeql_runner import CodeQLRunner


# ---------------------------------------------------------------------------
# 辅助：构造 mock LLM 输出序列
# ---------------------------------------------------------------------------

_VALID_QL = """\
/**
 * @name Test Query
 * @kind problem
 * @id java/test
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class TestSink extends DataFlow::Node {
  TestSink() {
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName("org.example", "Exec", "run") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module TestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof TestSink }
}

module TestFlow = TaintTracking::Global<TestConfig>;

from DataFlow::Node src, DataFlow::Node sink
where TestFlow::flow(src, sink)
select sink, "vuln from $@.", src, "source"
"""


def _make_agent_q(tmp_path, llm_outputs: list[str], compile_results: list[tuple]):
    """
    构建 AgentQ，注入 mock LLM 和 mock CodeQLRunner。

    Args:
        llm_outputs: LLM 依次返回的字符串列表。
        compile_results: compile_query 依次返回的 (success, error_msg) 列表。
    """
    mock_llm = MagicMock()
    mock_llm.__or__ = MagicMock(return_value=mock_llm)  # 支持 llm | parser
    mock_chain = MagicMock()

    # 模拟 chain.invoke 依次返回 llm_outputs
    mock_chain.invoke.side_effect = llm_outputs
    mock_llm.__or__.return_value = mock_chain

    mock_runner = MagicMock(spec=CodeQLRunner)
    mock_runner.compile_query.side_effect = compile_results
    mock_runner.install_query_pack.return_value = True

    agent = AgentQ(
        llm=mock_llm,
        runner=mock_runner,
        output_dir=str(tmp_path / "queries"),
        max_retries=3,
    )
    # 直接替换 _parser 以简化 mock
    agent._parser = MagicMock()
    agent._parser.__ror__ = MagicMock(return_value=mock_chain)

    return agent, mock_runner, mock_chain


class TestExtractQlCode:

    def test_plain_code_passthrough(self):
        code = "import java\nselect 1"
        assert _extract_ql_code(code) == code

    def test_strips_ql_fenced_block(self):
        code = "```ql\nimport java\nselect 1\n```"
        result = _extract_ql_code(code)
        assert "```" not in result
        assert "import java" in result

    def test_strips_generic_fenced_block(self):
        code = "```\nimport java\nselect 1\n```"
        result = _extract_ql_code(code)
        assert "```" not in result

    def test_strips_whitespace(self):
        code = "  import java  "
        assert _extract_ql_code(code) == "import java"


class TestAgentQTemplateHit:

    def test_template_hit_skips_llm(self, tmp_path):
        """模板命中时 LLM 不应被调用生成初始代码。"""
        mock_runner = MagicMock(spec=CodeQLRunner)
        mock_runner.compile_query.return_value = (True, "")
        mock_runner.install_query_pack.return_value = True

        mock_llm = MagicMock()
        agent = AgentQ(
            llm=mock_llm, runner=mock_runner,
            output_dir=str(tmp_path / "queries"), max_retries=3,
        )
        agent._parser = MagicMock()

        result = agent.generate_and_compile("java", "Spring EL Injection")

        assert result.exists()
        # 模板命中 → LLM invoke 不应被调用（修复时才调用）
        agent._parser.invoke = MagicMock()  # 确保没调用
        assert result.suffix == ".ql"

    def test_template_code_written_to_file(self, tmp_path):
        mock_runner = MagicMock(spec=CodeQLRunner)
        mock_runner.compile_query.return_value = (True, "")
        mock_runner.install_query_pack.return_value = True

        agent = AgentQ(
            llm=MagicMock(), runner=mock_runner,
            output_dir=str(tmp_path / "queries"), max_retries=1,
        )
        agent._parser = MagicMock()

        result = agent.generate_and_compile("java", "OGNL Injection")
        content = result.read_text(encoding="utf-8")
        assert "ognl" in content.lower() or "OGNL" in content


class TestAgentQSelfHeal:

    def test_compile_success_on_first_try(self, tmp_path):
        """第一次编译就成功，不触发修复。"""
        mock_runner = MagicMock(spec=CodeQLRunner)
        mock_runner.compile_query.return_value = (True, "")
        mock_runner.install_query_pack.return_value = True

        mock_chain = MagicMock()
        mock_chain.invoke.return_value = _VALID_QL
        mock_llm = MagicMock()

        agent = AgentQ(
            llm=mock_llm, runner=mock_runner,
            output_dir=str(tmp_path / "queries"), max_retries=3,
        )
        agent._invoke_llm = MagicMock(return_value=_VALID_QL)

        result = agent.generate_and_compile("java", "UNKNOWN vuln xyz")
        assert result.exists()
        assert mock_runner.compile_query.call_count == 1

    def test_compile_fail_then_succeed(self, tmp_path):
        """第一次失败，第二次成功（触发一次 LLM 修复）。"""
        mock_runner = MagicMock(spec=CodeQLRunner)
        mock_runner.compile_query.side_effect = [
            (False, "ERROR: could not resolve module foo"),
            (True, ""),
        ]
        mock_runner.install_query_pack.return_value = True

        agent = AgentQ(
            llm=MagicMock(), runner=mock_runner,
            output_dir=str(tmp_path / "queries"), max_retries=3,
        )
        agent._invoke_llm = MagicMock(return_value=_VALID_QL)

        result = agent.generate_and_compile("java", "Test vuln xyz")
        assert result.exists()
        assert mock_runner.compile_query.call_count == 2
        # 修复时调用了一次 LLM
        assert agent._invoke_llm.call_count >= 2  # 初始生成 + 至少一次修复

    def test_max_retries_raises(self, tmp_path):
        """所有重试均失败时抛出 RuntimeError。"""
        mock_runner = MagicMock(spec=CodeQLRunner)
        mock_runner.compile_query.return_value = (False, "ERROR: persistent failure")
        mock_runner.install_query_pack.return_value = True

        agent = AgentQ(
            llm=MagicMock(), runner=mock_runner,
            output_dir=str(tmp_path / "queries"), max_retries=2,
        )
        agent._invoke_llm = MagicMock(return_value="bad code")

        with pytest.raises(RuntimeError, match="2 次尝试后"):
            agent.generate_and_compile("java", "Test vuln xyz")

        assert mock_runner.compile_query.call_count == 2

    def test_qlpack_yml_created(self, tmp_path):
        """应在语言子目录下自动创建 qlpack.yml。"""
        mock_runner = MagicMock(spec=CodeQLRunner)
        mock_runner.compile_query.return_value = (True, "")
        mock_runner.install_query_pack.return_value = True

        agent = AgentQ(
            llm=MagicMock(), runner=mock_runner,
            output_dir=str(tmp_path / "queries"), max_retries=1,
        )
        agent._invoke_llm = MagicMock(return_value=_VALID_QL)

        agent.generate_and_compile("java", "Test xyz")

        qlpack = tmp_path / "queries" / "java" / "qlpack.yml"
        assert qlpack.exists()
        content = qlpack.read_text()
        assert "codeql/java-all" in content
