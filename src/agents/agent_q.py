"""
Agent-Q：自动化 CodeQL 规则合成器（带自修复循环）。

工作流：
1. 通过 LLM 生成初始 .ql 代码并写入本地文件。
2. 调用 CodeQLRunner.compile_query() 尝试编译。
3. 若编译失败，将「原始代码 + 报错信息」重新发给 LLM 请求修复。
4. 最多重试 MAX_RETRIES 次，成功则返回文件路径，否则抛出异常。
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from pathlib import Path
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from src.utils.codeql_runner import CodeQLRunner
from src.utils.ql_template_library import QLTemplateLibrary

logger = logging.getLogger(__name__)

MAX_RETRIES: int = 3

# ---------------------------------------------------------------------------
# Prompt 模板
# ---------------------------------------------------------------------------

# 按语言选择对应系统提示
_SYSTEM_PROMPT_JAVA = """\
你是一位精通 CodeQL 静态分析的安全研究专家，专注于 Java 表达式注入漏洞（SpEL / OGNL / MVEL）检测。
你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 已验证可编译的 Java 黄金模板（必须严格遵守此结构）━━━━━━━━━━

/**
 * @name <查询名称>
 * @description <描述>
 * @kind problem
 * @problem.severity error
 * @id java/<唯一id>
 * @tags security
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName("<包名>", "<类名>", "<方法名>") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CustomSink }
}

module Flow = TaintTracking::Global<FlowConfig>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "漏洞描述，数据来自 $@。", source, "用户可控输入"

━━━━━━━━━━ Java 关键规则（违反任何一条都会编译失败）━━━━━━━━━━
1. 必须使用 import semmle.code.java.dataflow.FlowSources （RemoteFlowSource 在此模块）
2. 禁止使用 semmle.code.java.security.* 路径（此路径不存在）
3. 禁止使用 TaintTracking::Configuration（已废弃），必须用 module Flow = TaintTracking::Global<FlowConfig>
4. 方法调用类型是 MethodCall，不是 MethodAccess
5. hasQualifiedName 接受三个字符串参数：(包名, 类名, 方法名)
6. DataFlow::ConfigSig 的 module 实现使用 implements 关键字，不需要 extends
"""

_SYSTEM_PROMPT_PYTHON = """\
你是一位精通 CodeQL 静态分析的安全研究专家，专注于 Python SSTI 漏洞（Jinja2 / Mako）检测。
你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 已验证可编译的 Python 黄金模板（必须严格遵守此结构）━━━━━━━━━━

/**
 * @name <查询名称>
 * @description <描述>
 * @kind problem
 * @problem.severity error
 * @id python/<唯一id>
 * @tags security
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "<方法名>" and
        this.asExpr() = c.getArg(0)
      )
      or
      (
        c.getFunc().(Name).getId() = "<类名>" and
        this.asExpr() = c.getArg(0)
      )
    )
  }
}

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CustomSink }
}

module Flow = TaintTracking::Global<FlowConfig>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "SSTI 漏洞描述，数据来自 $@。", source, "用户可控输入"

━━━━━━━━━━ Python 关键规则（违反任何一条都会编译失败）━━━━━━━━━━
1. 必须使用 import semmle.code.python.dataflow.new.RemoteFlowSources（注意 new 子路径）
2. 禁止使用旧路径 semmle.code.python.dataflow.DataFlow（无 new 子路径版本已废弃）
3. Python 方法调用用 Call 和 Attribute/Name，不是 MethodCall
4. 访问调用参数用 c.getArg(0) 而非 c.getArgument(0)
5. 同样使用 module Flow = TaintTracking::Global<FlowConfig> 和 implements 关键字
6. @id 使用 python/<漏洞类型小写连字符> 格式
"""

# 通用系统提示（不认识的语言降级到此）
_SYSTEM_PROMPT_GENERIC = """\
你是一位精通 CodeQL 静态分析的安全研究专家，专注于表达式注入漏洞（EL Injection / SSTI）检测。
你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身。
不要附带任何 markdown 代码块标记、解释或额外文字。

使用 TaintTracking::Global<ConfigSig> 模式，确保：
1. import 路径与目标语言 CodeQL Pack 一致
2. 使用 implements DataFlow::ConfigSig（不使用 extends）
3. 只输出完整 .ql 代码
"""

# 语言 → 系统提示映射
_SYSTEM_PROMPTS: dict[str, str] = {
    "java":       _SYSTEM_PROMPT_JAVA,
    "python":     _SYSTEM_PROMPT_PYTHON,
}


def _get_system_prompt(language: str) -> str:
    """按语言返回对应的系统提示。"""
    return _SYSTEM_PROMPTS.get(language.lower(), _SYSTEM_PROMPT_GENERIC)


_INITIAL_GENERATION_TEMPLATE = """\
请基于上方的黄金模板，为以下目标生成 CodeQL 污点追踪查询：

- **目标语言**：{language}
- **漏洞类型**：{vuln_type}
- **已知危险 Sink 方法**：{sink_hints}

任务：
1. 完全复用黄金模板的结构，只替换 <占位符> 部分。
2. CustomSink 中填入实际的危险 Sink 方法（可定义多个 or 分支）。
3. @id 使用 {language}/<漏洞类型小写连字符> 格式。
4. 直接输出完整 .ql 代码，不要加任何 markdown 包装或解释文字。
"""

_FIX_TEMPLATE = """\
下面的 CodeQL 查询代码在编译时报错，请参照黄金模板修复后输出完整的 .ql 代码。

【编译错误信息】
{error_message}

【当前代码】
{current_code}

修复要求：
- 严格对照 System Prompt 中的黄金模板检查结构。
- 重点检查：import 路径、TaintTracking::Global 用法、正确的调用类型（Java=MethodCall, Python=Call）。
- 只修改导致编译失败的部分，保持原有查询逻辑。
- 确保所有导入路径、类型、谓词名称与目标语言的 CodeQL 标准库版本一致。
- 直接输出修复后的完整 .ql 代码，不要附带任何解释。
"""

# 保留旧名称引用，避免外部代码报错
_SYSTEM_PROMPT = _SYSTEM_PROMPT_JAVA

# ---------------------------------------------------------------------------
# 语言 → CodeQL 标准库 Pack 名称映射
# 编译 .ql 时 qlpack.yml 中的 dependencies 字段必须与此对应
# ---------------------------------------------------------------------------

_LANG_TO_CODEQL_PACK: dict[str, str] = {
    "java":       "codeql/java-all",
    "python":     "codeql/python-all",
    "javascript": "codeql/javascript-all",
    "go":         "codeql/go-all",
    "csharp":     "codeql/csharp-all",
    "cpp":        "codeql/cpp-all",
}

# ---------------------------------------------------------------------------
# 默认 Sink 提示（可被调用方覆盖）
# ---------------------------------------------------------------------------

_DEFAULT_SINK_HINTS: dict[str, str] = {
    "java": (
        "org.springframework.expression.ExpressionParser.parseExpression, "
        "ognl.Ognl.getValue, "
        "org.mvel2.MVEL.eval"
    ),
    "python": (
        "jinja2.Environment.from_string, "
        "jinja2.Template, "
        "mako.template.Template"
    ),
}


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _extract_ql_code(raw_output: str) -> str:
    """
    从 LLM 输出中提取纯 .ql 代码。

    LLM 有时会用 markdown 代码块包裹输出，此函数负责剥离外层包装。

    Args:
        raw_output: LLM 原始返回字符串。

    Returns:
        去除 markdown 代码块标记后的纯 .ql 代码字符串。
    """
    # 匹配 ```ql ... ``` 或 ``` ... ``` 包裹的代码块
    pattern = re.compile(r"```(?:ql)?\s*\n(.*?)```", re.DOTALL)
    match = pattern.search(raw_output)
    if match:
        return match.group(1).strip()
    return raw_output.strip()


# ---------------------------------------------------------------------------
# Agent-Q 主类
# ---------------------------------------------------------------------------

class AgentQ:
    """
    CodeQL 规则自动合成 Agent，内置自修复循环。

    Attributes:
        llm: LangChain LLM 实例（默认为 ChatOpenAI）。
        runner: CodeQLRunner 实例，用于调用本地 codeql CLI。
        output_dir: 生成的 .ql 文件的存放目录。
        max_retries: 自修复循环的最大重试次数。
    """

    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        runner: Optional[CodeQLRunner] = None,
        output_dir: str = "data/queries",
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self.llm: ChatOpenAI = llm or ChatOpenAI(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
            temperature=0.2,
            # 支持第三方 OpenAI 兼容接口（如硅基流动、月之暗面等）
            base_url=os.environ.get("OPENAI_BASE_URL") or None,
        )
        self.runner: CodeQLRunner = runner or CodeQLRunner()
        self.output_dir: Path = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_retries: int = max_retries
        self._parser = StrOutputParser()

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    def _invoke_llm(self, system: str, human: str) -> str:
        """
        调用 LLM 并返回原始字符串输出。

        Args:
            system: System Prompt 内容。
            human: Human（User）消息内容。

        Returns:
            LLM 原始响应字符串。
        """
        messages = [
            SystemMessage(content=system),
            HumanMessage(content=human),
        ]
        chain = self.llm | self._parser
        return chain.invoke(messages)

    def _ensure_qlpack(self, lang_dir: Path, language: str) -> None:
        """
        在语言专属子目录中创建 qlpack.yml（若不存在）。

        CodeQL 编译 .ql 文件时必须能找到 qlpack.yml，否则报
        "Could not locate a dbscheme" 错误。

        Args:
            lang_dir: 语言专属查询目录（如 data/queries/java/）。
            language: 目标语言标识。
        """
        qlpack_path = lang_dir / "qlpack.yml"
        if qlpack_path.exists():
            return

        pack_dep = _LANG_TO_CODEQL_PACK.get(
            language.lower(), f"codeql/{language.lower()}-all"
        )
        content = (
            f"name: qrs-el/{language.lower()}-queries\n"
            f"version: 0.0.1\n"
            f"dependencies:\n"
            f'  "{pack_dep}": "*"\n'
        )
        qlpack_path.write_text(content, encoding="utf-8")
        logger.info("已创建 qlpack.yml: %s  (依赖: %s)", qlpack_path, pack_dep)

        # 下载并解析声明的依赖包，否则编译时无法找到标准库模块
        if not self.runner.install_query_pack(str(lang_dir)):
            logger.warning(
                "codeql pack install 失败，编译可能因找不到标准库而报错。"
                "请确认网络连接正常或 CodeQL 离线包已就位。"
            )

    def _write_query_to_file(self, code: str, filename: str, language: str) -> Path:
        """
        将 .ql 代码写入语言专属子目录，并确保该目录存在 qlpack.yml。

        Args:
            code: .ql 代码字符串。
            filename: 目标文件名（含 .ql 扩展名）。
            language: 目标语言，用于选择子目录与 qlpack 依赖。

        Returns:
            写入成功后的文件 Path 对象。
        """
        lang_dir = self.output_dir / language.lower()
        lang_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_qlpack(lang_dir, language)

        file_path = lang_dir / filename
        file_path.write_text(code, encoding="utf-8")
        logger.debug("已写入查询文件: %s", file_path)
        return file_path

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def generate_and_compile(
        self,
        language: str,
        vuln_type: str,
        sink_hints: Optional[str] = None,
        query_name: Optional[str] = None,
        few_shot_examples: Optional[list[str]] = None,
        detected_frameworks: Optional[set[str]] = None,
    ) -> Path:
        """
        生成 CodeQL 查询代码并通过编译检查；失败时自动修复，最多重试。

        Args:
            language: 目标编程语言，如 "java"、"python"。
            vuln_type: 漏洞类型描述，如 "Spring EL Injection"。
            sink_hints: 可选的自定义 Sink 方法列表字符串；未提供时使用内置默认值。
            query_name: 生成文件的名称前缀；默认自动生成 UUID 避免冲突。
            few_shot_examples: 规则记忆库检索到的历史成功规则代码列表，
                               注入到生成 Prompt 中作为 Few-Shot 参考。
            detected_frameworks: Phase 0 从构建文件检测到的框架集合，
                                 用于向 LLM 提供更精准的项目上下文。

        Returns:
            编译通过的 .ql 文件的 Path 对象。

        Raises:
            RuntimeError: 当达到最大重试次数后仍无法通过编译时抛出。
        """
        _sink_hints = sink_hints or _DEFAULT_SINK_HINTS.get(
            language.lower(), "（未指定，请根据目标框架推断）"
        )
        _name_prefix = query_name or f"{language}_{vuln_type}".replace(" ", "_")
        _filename = f"{_name_prefix}_{uuid.uuid4().hex[:8]}.ql"

        logger.info(
            "Agent-Q 开始生成规则 | 语言: %s | 漏洞类型: %s", language, vuln_type
        )

        # ── 第 1 步：优先查询模板知识库 ──────────────────────────────────
        # 命中模板时直接使用已验证代码，大幅降低编译失败概率
        template = QLTemplateLibrary.find(language=language, vuln_type=vuln_type)
        if template:
            logger.info("使用模板知识库代码: %s（跳过 LLM 初始生成）", template.key)
            current_code = template.code
        else:
            # 将规则记忆库的 Few-Shot 示例嵌入 Prompt
            few_shot_section = ""
            if few_shot_examples:
                examples_text = "\n\n---\n\n".join(few_shot_examples[:2])
                few_shot_section = (
                    f"\n\n【来自规则记忆库的参考示例（已编译通过，可借鉴结构）】\n"
                    f"```ql\n{examples_text}\n```\n"
                )

            # 将框架检测结果注入 Prompt，让 LLM 生成针对性更强的查询
            framework_section = ""
            if detected_frameworks:
                framework_section = (
                    f"\n\n【目标项目检测到的框架/依赖】: {', '.join(sorted(detected_frameworks))}\n"
                    "请确保生成的查询针对上述框架，避免引入该项目中不存在的库。"
                )

            human_prompt = _INITIAL_GENERATION_TEMPLATE.format(
                language=language,
                vuln_type=vuln_type,
                sink_hints=_sink_hints,
            ) + few_shot_section + framework_section
            # 使用与语言匹配的系统提示
            sys_prompt = _get_system_prompt(language)
            raw_output = self._invoke_llm(sys_prompt, human_prompt)
            current_code = _extract_ql_code(raw_output)

        query_file = self._write_query_to_file(current_code, _filename, language)
        logger.info("初始 .ql 代码已就绪，开始编译验证...")

        # ── 第 2 步：自修复循环 ──────────────────────────────────────────
        sys_prompt = _get_system_prompt(language)
        error_msg = ""
        for attempt in range(1, self.max_retries + 1):
            success, error_msg = self.runner.compile_query(str(query_file))

            if success:
                logger.info(
                    "编译成功（第 %d/%d 次尝试）: %s", attempt, self.max_retries, query_file
                )
                return query_file

            logger.warning(
                "编译失败（第 %d/%d 次）:\n%s", attempt, self.max_retries, error_msg
            )

            if attempt == self.max_retries:
                break

            logger.info("正在请求 LLM 修复代码（第 %d 次修复）...", attempt)
            fix_prompt = _FIX_TEMPLATE.format(
                error_message=error_msg,
                current_code=current_code,
            )
            raw_fixed = self._invoke_llm(sys_prompt, fix_prompt)
            current_code = _extract_ql_code(raw_fixed)
            query_file = self._write_query_to_file(current_code, _filename, language)

        raise RuntimeError(
            f"Agent-Q 在 {self.max_retries} 次尝试后仍无法生成可编译的 .ql 文件。"
            f"\n最后一次编译错误：\n{error_msg}"
        )
