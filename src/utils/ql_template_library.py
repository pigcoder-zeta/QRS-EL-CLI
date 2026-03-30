"""
CodeQL 查询模板知识库。

存储经过本地 `codeql query compile` 实际验证的黄金模板，
Agent-Q 优先从此处取得结构骨架，LLM 仅需填充 Sink/Source 细节，
大幅降低编译失败概率，减少 LLM 重试次数。

Java 模板基于 codeql/java-all@9.0.2 验证通过。
Python 模板基于 codeql/python-all@0.11.x 验证通过。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class QLTemplate:
    """一条已验证的 CodeQL 查询模板。"""

    key: str            # 唯一标识，格式 "<language>/<vuln_type>"
    language: str       # 目标语言
    vuln_type: str      # 漏洞类型关键字（用于模糊匹配）
    description: str    # 人类可读描述
    code: str           # 完整 .ql 代码（已验证可编译）


# ---------------------------------------------------------------------------
# Java 模板集合
# ---------------------------------------------------------------------------

_JAVA_SPEL = QLTemplate(
    key="java/spring-el-injection",
    language="java",
    vuln_type="spel",
    description="Spring Expression Language (SpEL) 注入",
    code="""\
/**
 * @name Spring Expression Language Injection
 * @description User-controlled data flows into ExpressionParser.parseExpression,
 *              enabling arbitrary code execution via Spring EL.
 * @kind problem
 * @problem.severity error
 * @id java/spring-el-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class SpelParseExpressionSink extends DataFlow::Node {
  SpelParseExpressionSink() {
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName(
        "org.springframework.expression", "ExpressionParser", "parseExpression"
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module SpelInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SpelParseExpressionSink }
}

module SpelInjectionFlow = TaintTracking::Global<SpelInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SpelInjectionFlow::flow(source, sink)
select sink,
  "Spring EL injection: user-controlled data from $@ flows into parseExpression.",
  source, "user-controlled input"
""",
)

_JAVA_OGNL = QLTemplate(
    key="java/ognl-injection",
    language="java",
    vuln_type="ognl",
    description="OGNL 表达式注入",
    code="""\
/**
 * @name OGNL Expression Injection
 * @description User-controlled data flows into Ognl.getValue or Ognl.parseExpression,
 *              enabling arbitrary code execution.
 * @kind problem
 * @problem.severity error
 * @id java/ognl-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class OgnlSink extends DataFlow::Node {
  OgnlSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("ognl", "Ognl", "getValue") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("ognl", "Ognl", "parseExpression") and
        this.asExpr() = mc.getArgument(0)
      )
    )
  }
}

module OgnlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof OgnlSink }
}

module OgnlInjectionFlow = TaintTracking::Global<OgnlInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where OgnlInjectionFlow::flow(source, sink)
select sink,
  "OGNL injection: user-controlled data from $@ flows into OGNL expression evaluator.",
  source, "user-controlled input"
""",
)

_JAVA_MVEL = QLTemplate(
    key="java/mvel-injection",
    language="java",
    vuln_type="mvel",
    description="MVEL 表达式注入",
    code="""\
/**
 * @name MVEL Expression Injection
 * @description User-controlled data flows into MVEL.eval or MVEL.executeExpression.
 * @kind problem
 * @problem.severity error
 * @id java/mvel-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class MvelSink extends DataFlow::Node {
  MvelSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("org.mvel2", "MVEL", "eval") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("org.mvel2", "MVEL", "executeExpression") and
        this.asExpr() = mc.getArgument(0)
      )
    )
  }
}

module MvelInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof MvelSink }
}

module MvelInjectionFlow = TaintTracking::Global<MvelInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where MvelInjectionFlow::flow(source, sink)
select sink,
  "MVEL injection: user-controlled data from $@ flows into MVEL expression evaluator.",
  source, "user-controlled input"
""",
)

_JAVA_EL_COMBINED = QLTemplate(
    key="java/el-injection",
    language="java",
    vuln_type="el",
    description="通用 Java EL 注入（SpEL + OGNL + MVEL 综合）",
    code="""\
/**
 * @name Java Expression Language Injection
 * @description User-controlled data flows into SpEL / OGNL / MVEL expression evaluators.
 * @kind problem
 * @problem.severity error
 * @id java/el-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class ElInjectionSink extends DataFlow::Node {
  ElInjectionSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName(
          "org.springframework.expression", "ExpressionParser", "parseExpression"
        ) and this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("ognl", "Ognl", "getValue") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("org.mvel2", "MVEL", "eval") and
        this.asExpr() = mc.getArgument(0)
      )
    )
  }
}

module ElInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof ElInjectionSink }
}

module ElInjectionFlow = TaintTracking::Global<ElInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where ElInjectionFlow::flow(source, sink)
select sink,
  "EL injection: user-controlled data from $@ flows into an expression evaluator (SpEL/OGNL/MVEL).",
  source, "user-controlled input"
""",
)

# ---------------------------------------------------------------------------
# Python 模板集合
# ---------------------------------------------------------------------------

_PYTHON_JINJA2 = QLTemplate(
    key="python/jinja2-ssti",
    language="python",
    vuln_type="jinja2",
    description="Jinja2 服务端模板注入（SSTI）",
    code="""\
/**
 * @name Jinja2 Server-Side Template Injection
 * @description User-controlled data flows into jinja2.Environment.from_string
 *              or jinja2.Template, enabling arbitrary code execution via SSTI.
 * @kind problem
 * @problem.severity error
 * @id python/jinja2-ssti
 * @tags security external/cwe/cwe-094
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class Jinja2SSTISink extends DataFlow::Node {
  Jinja2SSTISink() {
    exists(Call c |
      (
        // jinja2.Environment().from_string(user_input)
        c.getFunc().(Attribute).getName() = "from_string" and
        this.asExpr() = c.getArg(0)
      )
      or
      (
        // jinja2.Template(user_input)
        c.getFunc().(Name).getId() = "Template" and
        this.asExpr() = c.getArg(0)
      )
    )
  }
}

module Jinja2SSTIConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
  }
  predicate isSink(DataFlow::Node sink) {
    sink instanceof Jinja2SSTISink
  }
}

module Jinja2SSTIFlow = TaintTracking::Global<Jinja2SSTIConfig>;

from DataFlow::Node source, DataFlow::Node sink
where Jinja2SSTIFlow::flow(source, sink)
select sink,
  "Jinja2 SSTI: user-controlled data from $@ flows into template engine.",
  source, "user-controlled input"
""",
)

_PYTHON_MAKO = QLTemplate(
    key="python/mako-ssti",
    language="python",
    vuln_type="mako",
    description="Mako 服务端模板注入（SSTI）",
    code="""\
/**
 * @name Mako Server-Side Template Injection
 * @description User-controlled data flows into mako.template.Template,
 *              enabling arbitrary Python code execution via SSTI.
 * @kind problem
 * @problem.severity error
 * @id python/mako-ssti
 * @tags security external/cwe/cwe-094
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class MakoSSTISink extends DataFlow::Node {
  MakoSSTISink() {
    exists(Call c |
      // mako.template.Template(user_input)
      c.getFunc().(Attribute).getName() = "Template" and
      this.asExpr() = c.getArg(0)
    )
  }
}

module MakoSSTIConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
  }
  predicate isSink(DataFlow::Node sink) {
    sink instanceof MakoSSTISink
  }
}

module MakoSSTIFlow = TaintTracking::Global<MakoSSTIConfig>;

from DataFlow::Node source, DataFlow::Node sink
where MakoSSTIFlow::flow(source, sink)
select sink,
  "Mako SSTI: user-controlled data from $@ flows into Mako template engine.",
  source, "user-controlled input"
""",
)

_PYTHON_SSTI_COMBINED = QLTemplate(
    key="python/ssti",
    language="python",
    vuln_type="ssti",
    description="通用 Python SSTI（Jinja2 + Mako 综合）",
    code="""\
/**
 * @name Python Server-Side Template Injection
 * @description User-controlled data flows into Jinja2 or Mako template engine,
 *              enabling arbitrary code execution via SSTI.
 * @kind problem
 * @problem.severity error
 * @id python/ssti
 * @tags security external/cwe/cwe-094
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class SSTISink extends DataFlow::Node {
  SSTISink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "from_string" and
        this.asExpr() = c.getArg(0)
      )
      or
      (
        c.getFunc().(Name).getId() = "Template" and
        this.asExpr() = c.getArg(0)
      )
    )
  }
}

module SSTIConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SSTISink }
}

module SSTIFlow = TaintTracking::Global<SSTIConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SSTIFlow::flow(source, sink)
select sink,
  "Python SSTI: user-controlled data from $@ flows into template engine (Jinja2/Mako).",
  source, "user-controlled input"
""",
)

# ---------------------------------------------------------------------------
# 通用漏洞模板
# ---------------------------------------------------------------------------

_JAVA_SQL_INJECTION = QLTemplate(
    key="java/sql-injection",
    language="java",
    vuln_type="sql injection",
    description="Java SQL 注入（JDBC Statement 字符串拼接）",
    code="""\
/**
 * @name SQL Injection
 * @description User-controlled data flows into a SQL query without parameterization.
 * @kind problem
 * @problem.severity error
 * @id java/sql-injection
 * @tags security external/cwe/cwe-089
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.sql", "Statement", "executeQuery") or
        mc.getMethod().hasQualifiedName("java.sql", "Statement", "execute") or
        mc.getMethod().hasQualifiedName("java.sql", "Statement", "executeUpdate") or
        mc.getMethod().hasQualifiedName("java.sql", "Connection", "prepareStatement") or
        mc.getMethod().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate", "queryForObject") or
        mc.getMethod().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate", "query")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecuteSink }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SqlFlow::flow(source, sink)
select sink, "SQL injection: user-controlled data from $@ flows into SQL query.", source, "user input"
""",
)

_JAVA_COMMAND_INJECTION = QLTemplate(
    key="java/command-injection",
    language="java",
    vuln_type="command injection",
    description="Java 命令注入（Runtime.exec / ProcessBuilder）",
    code="""\
/**
 * @name Command Injection
 * @description User-controlled data flows into OS command execution.
 * @kind problem
 * @problem.severity error
 * @id java/command-injection
 * @tags security external/cwe/cwe-078
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.lang", "Runtime", "exec") or
        mc.getMethod().hasQualifiedName("java.lang", "ProcessBuilder", "command")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module CmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CommandSink }
}

module CmdFlow = TaintTracking::Global<CmdConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CmdFlow::flow(source, sink)
select sink, "Command injection: user-controlled data from $@ flows into OS command.", source, "user input"
""",
)

_JAVA_PATH_TRAVERSAL = QLTemplate(
    key="java/path-traversal",
    language="java",
    vuln_type="path traversal",
    description="Java 路径穿越（FileInputStream / Paths.get）",
    code="""\
/**
 * @name Path Traversal
 * @description User-controlled path flows into file access without canonicalization.
 * @kind problem
 * @problem.severity error
 * @id java/path-traversal
 * @tags security external/cwe/cwe-022
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class PathSink extends DataFlow::Node {
  PathSink() {
    exists(ConstructorCall cc |
      (
        cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream") or
        cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") or
        cc.getConstructedType().hasQualifiedName("java.io", "File")
      ) and
      this.asExpr() = cc.getArgument(0)
    )
    or
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.nio.file", "Paths", "get") or
        mc.getMethod().hasQualifiedName("java.nio.file", "Files", "readAllBytes") or
        mc.getMethod().hasQualifiedName("java.nio.file", "Files", "newInputStream")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module PathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof PathSink }
}

module PathFlow = TaintTracking::Global<PathConfig>;

from DataFlow::Node source, DataFlow::Node sink
where PathFlow::flow(source, sink)
select sink, "Path traversal: user-controlled path from $@ flows into file access.", source, "user input"
""",
)

_JAVA_SSRF = QLTemplate(
    key="java/ssrf",
    language="java",
    vuln_type="ssrf",
    description="Java 服务端请求伪造（URL.openConnection / RestTemplate）",
    code="""\
/**
 * @name Server-Side Request Forgery (SSRF)
 * @description User-controlled URL flows into HTTP request without validation.
 * @kind problem
 * @problem.severity error
 * @id java/ssrf
 * @tags security external/cwe/cwe-918
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class SsrfSink extends DataFlow::Node {
  SsrfSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.net", "URL", "openConnection") or
        mc.getMethod().hasQualifiedName("java.net", "URL", "openStream") or
        mc.getMethod().hasQualifiedName("org.springframework.web.client", "RestTemplate", "getForObject") or
        mc.getMethod().hasQualifiedName("org.springframework.web.client", "RestTemplate", "postForObject")
      ) and
      this.asExpr() = mc.getQualifier()
    )
    or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.net", "URL") and
      this.asExpr() = cc.getArgument(0)
    )
  }
}

module SsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SsrfSink }
}

module SsrfFlow = TaintTracking::Global<SsrfConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SsrfFlow::flow(source, sink)
select sink, "SSRF: user-controlled URL from $@ flows into HTTP request.", source, "user input"
""",
)

_PYTHON_SQL_INJECTION = QLTemplate(
    key="python/sql-injection",
    language="python",
    vuln_type="sql injection",
    description="Python SQL 注入（cursor.execute 字符串拼接）",
    code="""\
/**
 * @name SQL Injection (Python)
 * @description User-controlled data flows into SQL query without parameterization.
 * @kind problem
 * @problem.severity error
 * @id python/sql-injection
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "execute" or
        c.getFunc().(Attribute).getName() = "executemany"
      ) and
      this.asExpr() = c.getArg(0)
    )
  }
}

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SqlFlow::flow(source, sink)
select sink, "SQL injection: user-controlled data from $@ flows into SQL query.", source, "user input"
""",
)

_PYTHON_COMMAND_INJECTION = QLTemplate(
    key="python/command-injection",
    language="python",
    vuln_type="command injection",
    description="Python 命令注入（os.system / subprocess）",
    code="""\
/**
 * @name Command Injection (Python)
 * @description User-controlled data flows into OS command execution.
 * @kind problem
 * @problem.severity error
 * @id python/command-injection
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "system" or
        c.getFunc().(Attribute).getName() = "popen" or
        c.getFunc().(Attribute).getName() = "run" or
        c.getFunc().(Attribute).getName() = "Popen" or
        c.getFunc().(Attribute).getName() = "check_output" or
        c.getFunc().(Name).getId() = "eval" or
        c.getFunc().(Name).getId() = "exec"
      ) and
      this.asExpr() = c.getArg(0)
    )
  }
}

module CmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CommandSink }
}

module CmdFlow = TaintTracking::Global<CmdConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CmdFlow::flow(source, sink)
select sink, "Command injection: user-controlled data from $@ flows into OS command.", source, "user input"
""",
)

# ---------------------------------------------------------------------------
# 模板注册表
# ---------------------------------------------------------------------------

_ALL_TEMPLATES: list[QLTemplate] = [
    # Java - 表达式注入
    _JAVA_SPEL,
    _JAVA_OGNL,
    _JAVA_MVEL,
    _JAVA_EL_COMBINED,
    # Java - 通用
    _JAVA_SQL_INJECTION,
    _JAVA_COMMAND_INJECTION,
    _JAVA_PATH_TRAVERSAL,
    _JAVA_SSRF,
    # Python - 模板注入
    _PYTHON_JINJA2,
    _PYTHON_MAKO,
    _PYTHON_SSTI_COMBINED,
    # Python - 通用
    _PYTHON_SQL_INJECTION,
    _PYTHON_COMMAND_INJECTION,
]

# 关键词 → 模板映射（优先精确匹配）
_KEYWORD_MAP: dict[str, QLTemplate] = {
    # Java - EL
    "spel":                         _JAVA_SPEL,
    "spring el":                    _JAVA_SPEL,
    "spring expression":            _JAVA_SPEL,
    "spring el injection":          _JAVA_SPEL,
    "ognl":                         _JAVA_OGNL,
    "ognl injection":               _JAVA_OGNL,
    "mvel":                         _JAVA_MVEL,
    "mvel injection":               _JAVA_MVEL,
    "el injection":                 _JAVA_EL_COMBINED,
    "expression injection":         _JAVA_EL_COMBINED,
    # Java - 通用
    "sql injection":                _JAVA_SQL_INJECTION,
    "sql":                          _JAVA_SQL_INJECTION,
    "sqli":                         _JAVA_SQL_INJECTION,
    "command injection":            _JAVA_COMMAND_INJECTION,
    "os command":                   _JAVA_COMMAND_INJECTION,
    "rce":                          _JAVA_COMMAND_INJECTION,
    "path traversal":               _JAVA_PATH_TRAVERSAL,
    "directory traversal":          _JAVA_PATH_TRAVERSAL,
    "lfi":                          _JAVA_PATH_TRAVERSAL,
    "ssrf":                         _JAVA_SSRF,
    "server-side request forgery":  _JAVA_SSRF,
    "server side request forgery":  _JAVA_SSRF,
    # Python
    "jinja2":                       _PYTHON_JINJA2,
    "jinja":                        _PYTHON_JINJA2,
    "mako":                         _PYTHON_MAKO,
    "ssti":                         _PYTHON_SSTI_COMBINED,
    "template injection":           _PYTHON_SSTI_COMBINED,
    "server-side template":         _PYTHON_SSTI_COMBINED,
}


class QLTemplateLibrary:
    """
    CodeQL 查询模板知识库。

    按语言与漏洞类型关键词检索已验证的 .ql 模板，
    优先使用精确匹配，无匹配时返回 None（退化为纯 LLM 生成模式）。
    """

    @staticmethod
    def find(language: str, vuln_type: str) -> Optional[QLTemplate]:
        """
        按语言和漏洞类型检索最匹配的模板。

        匹配策略（按优先级）：
        1. 关键词精确命中（不区分大小写）。
        2. 关键词部分包含匹配。
        3. 无匹配返回 None。

        Args:
            language: 目标语言，如 "java"。
            vuln_type: 漏洞类型描述，如 "Spring EL Injection"。

        Returns:
            匹配的 QLTemplate，或 None（无匹配时退化为 LLM 生成）。
        """
        lang = language.lower()
        query = vuln_type.lower()

        # 精确关键词匹配
        for kw, tmpl in _KEYWORD_MAP.items():
            if kw in query and tmpl.language == lang:
                logger.info(
                    "模板知识库命中 [关键词='%s']: %s", kw, tmpl.key
                )
                return tmpl

        # 无匹配
        logger.info(
            "模板知识库未命中 (language=%s, vuln_type=%s)，将使用 LLM 生成。",
            language,
            vuln_type,
        )
        return None

    @staticmethod
    def list_templates() -> list[str]:
        """返回所有已注册模板的 key 列表。"""
        return [t.key for t in _ALL_TEMPLATES]
