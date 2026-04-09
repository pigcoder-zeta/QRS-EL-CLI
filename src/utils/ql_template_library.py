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
# JavaScript 模板集合
# ---------------------------------------------------------------------------

_JS_SQL_INJECTION = QLTemplate(
    key="javascript/sql-injection",
    language="javascript",
    vuln_type="sql injection",
    description="JavaScript SQL 注入（mysql/pg query 字符串拼接）",
    code="""\
/**
 * @name SQL Injection (JavaScript)
 * @description User-controlled data flows into a SQL query without parameterization.
 * @kind problem
 * @problem.severity error
 * @id javascript/sql-injection
 * @tags security external/cwe/cwe-089
 */
import javascript

private class SqlQuerySink extends DataFlow::Node {
  SqlQuerySink() {
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = "query" or
        call.getCalleeName() = "execute" or
        call.getCalleeName() = "raw"
      ) and
      this = call.getArgument(0)
    )
  }
}

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SqlQuerySink }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SqlFlow::flow(source, sink)
select sink, "SQL injection: user-controlled data from $@ flows into SQL query.", source, "user input"
""",
)

_JS_COMMAND_INJECTION = QLTemplate(
    key="javascript/command-injection",
    language="javascript",
    vuln_type="command injection",
    description="JavaScript 命令注入（child_process exec/spawn）",
    code="""\
/**
 * @name Command Injection (JavaScript)
 * @description User-controlled data flows into child_process command execution.
 * @kind problem
 * @problem.severity error
 * @id javascript/command-injection
 * @tags security external/cwe/cwe-078
 */
import javascript

private class CmdExecSink extends DataFlow::Node {
  CmdExecSink() {
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = "exec" or
        call.getCalleeName() = "execSync" or
        call.getCalleeName() = "execFile" or
        call.getCalleeName() = "execFileSync"
      ) and
      this = call.getArgument(0)
    )
  }
}

module CmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CmdExecSink }
}

module CmdFlow = TaintTracking::Global<CmdConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CmdFlow::flow(source, sink)
select sink, "Command injection: user-controlled data from $@ flows into OS command.", source, "user input"
""",
)

_JS_PATH_TRAVERSAL = QLTemplate(
    key="javascript/path-traversal",
    language="javascript",
    vuln_type="path traversal",
    description="JavaScript 路径穿越（fs.readFile / fs.createReadStream）",
    code="""\
/**
 * @name Path Traversal (JavaScript)
 * @description User-controlled path flows into file system access without validation.
 * @kind problem
 * @problem.severity error
 * @id javascript/path-traversal
 * @tags security external/cwe/cwe-022
 */
import javascript

private class FsReadSink extends DataFlow::Node {
  FsReadSink() {
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = "readFile" or
        call.getCalleeName() = "readFileSync" or
        call.getCalleeName() = "createReadStream" or
        call.getCalleeName() = "writeFile" or
        call.getCalleeName() = "writeFileSync"
      ) and
      this = call.getArgument(0)
    )
  }
}

module PathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof FsReadSink }
}

module PathFlow = TaintTracking::Global<PathConfig>;

from DataFlow::Node source, DataFlow::Node sink
where PathFlow::flow(source, sink)
select sink, "Path traversal: user-controlled path from $@ flows into file access.", source, "user input"
""",
)

_JS_SSRF = QLTemplate(
    key="javascript/ssrf",
    language="javascript",
    vuln_type="ssrf",
    description="JavaScript SSRF（fetch / axios / http.request）",
    code="""\
/**
 * @name Server-Side Request Forgery (JavaScript)
 * @description User-controlled URL flows into HTTP request without validation.
 * @kind problem
 * @problem.severity error
 * @id javascript/ssrf
 * @tags security external/cwe/cwe-918
 */
import javascript

private class SsrfSink extends DataFlow::Node {
  SsrfSink() {
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = "fetch" or
        call.getCalleeName() = "request"
      ) and
      this = call.getArgument(0)
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

# ---------------------------------------------------------------------------
# Go 模板集合
# ---------------------------------------------------------------------------

_GO_SQL_INJECTION = QLTemplate(
    key="go/sql-injection",
    language="go",
    vuln_type="sql injection",
    description="Go SQL 注入（database/sql Query/Exec 字符串拼接）",
    code="""\
/**
 * @name SQL Injection (Go)
 * @description User-controlled data flows into SQL query without parameterization.
 * @kind problem
 * @problem.severity error
 * @id go/sql-injection
 * @tags security external/cwe/cwe-089
 */
import go

private class SqlQuerySink extends DataFlow::Node {
  SqlQuerySink() {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().(Method).hasQualifiedName("database/sql", "DB", "Query") or
        call.getTarget().(Method).hasQualifiedName("database/sql", "DB", "QueryRow") or
        call.getTarget().(Method).hasQualifiedName("database/sql", "DB", "Exec") or
        call.getTarget().(Method).hasQualifiedName("database/sql", "Tx", "Query") or
        call.getTarget().(Method).hasQualifiedName("database/sql", "Tx", "Exec")
      ) and
      this = call.getArgument(0)
    )
  }
}

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SqlQuerySink }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SqlFlow::flow(source, sink)
select sink, "SQL injection: user-controlled data from $@ flows into SQL query.", source, "user input"
""",
)

_GO_COMMAND_INJECTION = QLTemplate(
    key="go/command-injection",
    language="go",
    vuln_type="command injection",
    description="Go 命令注入（os/exec Command）",
    code="""\
/**
 * @name Command Injection (Go)
 * @description User-controlled data flows into OS command execution.
 * @kind problem
 * @problem.severity error
 * @id go/command-injection
 * @tags security external/cwe/cwe-078
 */
import go

private class CmdSink extends DataFlow::Node {
  CmdSink() {
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("os/exec", "Command") and
      this = call.getArgument(0)
    )
  }
}

module CmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CmdSink }
}

module CmdFlow = TaintTracking::Global<CmdConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CmdFlow::flow(source, sink)
select sink, "Command injection: user-controlled data from $@ flows into OS command.", source, "user input"
""",
)

_GO_PATH_TRAVERSAL = QLTemplate(
    key="go/path-traversal",
    language="go",
    vuln_type="path traversal",
    description="Go 路径穿越（os.Open / os.ReadFile）",
    code="""\
/**
 * @name Path Traversal (Go)
 * @description User-controlled path flows into file access without validation.
 * @kind problem
 * @problem.severity error
 * @id go/path-traversal
 * @tags security external/cwe/cwe-022
 */
import go

private class PathSink extends DataFlow::Node {
  PathSink() {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("os", "Open") or
        call.getTarget().hasQualifiedName("os", "OpenFile") or
        call.getTarget().hasQualifiedName("os", "ReadFile") or
        call.getTarget().hasQualifiedName("io/ioutil", "ReadFile")
      ) and
      this = call.getArgument(0)
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

_GO_SSRF = QLTemplate(
    key="go/ssrf",
    language="go",
    vuln_type="ssrf",
    description="Go SSRF（net/http Get / http.NewRequest）",
    code="""\
/**
 * @name Server-Side Request Forgery (Go)
 * @description User-controlled URL flows into HTTP request without validation.
 * @kind problem
 * @problem.severity error
 * @id go/ssrf
 * @tags security external/cwe/cwe-918
 */
import go

private class SsrfSink extends DataFlow::Node {
  SsrfSink() {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("net/http", "Get") or
        call.getTarget().hasQualifiedName("net/http", "Post") or
        call.getTarget().hasQualifiedName("net/http", "Head")
      ) and
      this = call.getArgument(0)
    )
    or
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("net/http", "NewRequest") and
      this = call.getArgument(1)
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

# ---------------------------------------------------------------------------
# C# 模板集合
# ---------------------------------------------------------------------------

_CSHARP_SQL_INJECTION = QLTemplate(
    key="csharp/sql-injection",
    language="csharp",
    vuln_type="sql injection",
    description="C# SQL 注入（SqlCommand / Entity Framework raw SQL）",
    code="""\
/**
 * @name SQL Injection (C#)
 * @description User-controlled data flows into SQL query without parameterization.
 * @kind problem
 * @problem.severity error
 * @id csharp/sql-injection
 * @tags security external/cwe/cwe-089
 */
import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote

private class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(ObjectCreation oc |
      oc.getObjectType().hasQualifiedName("System.Data.SqlClient", "SqlCommand") and
      this.asExpr() = oc.getArgument(0)
    )
    or
    exists(MethodCall mc |
      (
        mc.getTarget().getName() = "FromSqlRaw" or
        mc.getTarget().getName() = "ExecuteSqlRaw"
      ) and
      this.asExpr() = mc.getArgument(0)
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

_CSHARP_COMMAND_INJECTION = QLTemplate(
    key="csharp/command-injection",
    language="csharp",
    vuln_type="command injection",
    description="C# 命令注入（Process.Start）",
    code="""\
/**
 * @name Command Injection (C#)
 * @description User-controlled data flows into OS command execution.
 * @kind problem
 * @problem.severity error
 * @id csharp/command-injection
 * @tags security external/cwe/cwe-078
 */
import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote

private class CmdSink extends DataFlow::Node {
  CmdSink() {
    exists(MethodCall mc |
      mc.getTarget().hasQualifiedName("System.Diagnostics", "Process", "Start") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module CmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CmdSink }
}

module CmdFlow = TaintTracking::Global<CmdConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CmdFlow::flow(source, sink)
select sink, "Command injection: user-controlled data from $@ flows into OS command.", source, "user input"
""",
)

_CSHARP_PATH_TRAVERSAL = QLTemplate(
    key="csharp/path-traversal",
    language="csharp",
    vuln_type="path traversal",
    description="C# 路径穿越（System.IO File / StreamReader）",
    code="""\
/**
 * @name Path Traversal (C#)
 * @description User-controlled path flows into file access without validation.
 * @kind problem
 * @problem.severity error
 * @id csharp/path-traversal
 * @tags security external/cwe/cwe-022
 */
import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote

private class PathSink extends DataFlow::Node {
  PathSink() {
    exists(MethodCall mc |
      (
        mc.getTarget().hasQualifiedName("System.IO", "File", "ReadAllText") or
        mc.getTarget().hasQualifiedName("System.IO", "File", "ReadAllBytes") or
        mc.getTarget().hasQualifiedName("System.IO", "File", "OpenRead") or
        mc.getTarget().hasQualifiedName("System.IO", "File", "Open")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    exists(ObjectCreation oc |
      (
        oc.getObjectType().hasQualifiedName("System.IO", "StreamReader") or
        oc.getObjectType().hasQualifiedName("System.IO", "FileStream")
      ) and
      this.asExpr() = oc.getArgument(0)
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

_CSHARP_SSRF = QLTemplate(
    key="csharp/ssrf",
    language="csharp",
    vuln_type="ssrf",
    description="C# SSRF（HttpClient / WebClient）",
    code="""\
/**
 * @name Server-Side Request Forgery (C#)
 * @description User-controlled URL flows into HTTP request without validation.
 * @kind problem
 * @problem.severity error
 * @id csharp/ssrf
 * @tags security external/cwe/cwe-918
 */
import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote

private class SsrfSink extends DataFlow::Node {
  SsrfSink() {
    exists(MethodCall mc |
      (
        mc.getTarget().hasQualifiedName("System.Net.Http", "HttpClient", "GetAsync") or
        mc.getTarget().hasQualifiedName("System.Net.Http", "HttpClient", "PostAsync") or
        mc.getTarget().hasQualifiedName("System.Net.Http", "HttpClient", "SendAsync") or
        mc.getTarget().hasQualifiedName("System.Net", "WebClient", "DownloadString")
      ) and
      this.asExpr() = mc.getArgument(0)
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

# ---------------------------------------------------------------------------
# C++ 模板集合
# ---------------------------------------------------------------------------

_CPP_COMMAND_INJECTION = QLTemplate(
    key="cpp/command-injection",
    language="cpp",
    vuln_type="command injection",
    description="C/C++ 命令注入（system / popen / exec 系列）",
    code="""\
/**
 * @name Command Injection (C/C++)
 * @description User-controlled data flows into OS command execution.
 * @kind problem
 * @problem.severity error
 * @id cpp/command-injection
 * @tags security external/cwe/cwe-078
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class CmdSink extends DataFlow::Node {
  CmdSink() {
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("system") or
        fc.getTarget().hasName("popen") or
        fc.getTarget().hasName("execl") or
        fc.getTarget().hasName("execlp") or
        fc.getTarget().hasName("execvp")
      ) and
      this.asExpr() = fc.getArgument(0)
    )
  }
}

private class ExternalInput extends DataFlow::Node {
  ExternalInput() {
    exists(Function main, Parameter argv |
      main.hasName("main") and
      argv = main.getParameter(1) and
      this.asParameter() = argv
    )
    or
    exists(FunctionCall fc |
      fc.getTarget().hasName("getenv") and
      this.asExpr() = fc
    )
  }
}

module CmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ExternalInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof CmdSink }
}

module CmdFlow = TaintTracking::Global<CmdConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CmdFlow::flow(source, sink)
select sink, "Command injection: user-controlled data from $@ flows into OS command.", source, "user input"
""",
)

_CPP_PATH_TRAVERSAL = QLTemplate(
    key="cpp/path-traversal",
    language="cpp",
    vuln_type="path traversal",
    description="C/C++ 路径穿越（fopen / open / ifstream）",
    code="""\
/**
 * @name Path Traversal (C/C++)
 * @description User-controlled path flows into file access without validation.
 * @kind problem
 * @problem.severity error
 * @id cpp/path-traversal
 * @tags security external/cwe/cwe-022
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class PathSink extends DataFlow::Node {
  PathSink() {
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("fopen") or
        fc.getTarget().hasName("open") or
        fc.getTarget().hasName("freopen") or
        fc.getTarget().hasName("access")
      ) and
      this.asExpr() = fc.getArgument(0)
    )
  }
}

private class ExternalInput extends DataFlow::Node {
  ExternalInput() {
    exists(Function main, Parameter argv |
      main.hasName("main") and
      argv = main.getParameter(1) and
      this.asParameter() = argv
    )
    or
    exists(FunctionCall fc |
      fc.getTarget().hasName("getenv") and
      this.asExpr() = fc
    )
  }
}

module PathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ExternalInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof PathSink }
}

module PathFlow = TaintTracking::Global<PathConfig>;

from DataFlow::Node source, DataFlow::Node sink
where PathFlow::flow(source, sink)
select sink, "Path traversal: user-controlled path from $@ flows into file access.", source, "user input"
""",
)

_CPP_SQL_INJECTION = QLTemplate(
    key="cpp/sql-injection",
    language="cpp",
    vuln_type="sql injection",
    description="C/C++ SQL 注入（sqlite3_exec / mysql_query 字符串拼接）",
    code="""\
/**
 * @name SQL Injection (C/C++)
 * @description User-controlled data flows into SQL query without parameterization.
 * @kind problem
 * @problem.severity error
 * @id cpp/sql-injection
 * @tags security external/cwe/cwe-089
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("sqlite3_exec") or
        fc.getTarget().hasName("mysql_query") or
        fc.getTarget().hasName("mysql_real_query") or
        fc.getTarget().hasName("PQexec") or
        fc.getTarget().hasName("PQexecParams")
      ) and
      this.asExpr() = fc.getArgument(1)
    )
  }
}

private class ExternalInput extends DataFlow::Node {
  ExternalInput() {
    exists(Function main, Parameter argv |
      main.hasName("main") and
      argv = main.getParameter(1) and
      this.asParameter() = argv
    )
    or
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("getenv") or
        fc.getTarget().hasName("fgets") or
        fc.getTarget().hasName("gets") or
        fc.getTarget().hasName("scanf") or
        fc.getTarget().hasName("recv")
      ) and
      this.asExpr() = fc
    )
  }
}

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ExternalInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SqlFlow::flow(source, sink)
select sink, "SQL injection: user-controlled data from $@ flows into SQL query.", source, "user input"
""",
)

_CPP_BUFFER_OVERFLOW = QLTemplate(
    key="cpp/buffer-overflow",
    language="cpp",
    vuln_type="buffer overflow",
    description="C/C++ 缓冲区溢出（strcpy/strcat/sprintf/gets/memcpy 无边界检查）",
    code="""\
/**
 * @name Buffer Overflow (C/C++)
 * @description User-controlled data flows into unsafe buffer manipulation functions
 *              without proper bounds checking.
 * @kind problem
 * @problem.severity error
 * @id cpp/buffer-overflow
 * @tags security external/cwe/cwe-120
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class UnsafeBufferSink extends DataFlow::Node {
  UnsafeBufferSink() {
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("strcpy") or
        fc.getTarget().hasName("strcat") or
        fc.getTarget().hasName("sprintf") or
        fc.getTarget().hasName("gets") or
        fc.getTarget().hasName("wcscpy") or
        fc.getTarget().hasName("wcscat")
      ) and
      this.asExpr() = fc.getArgument(1)
    )
    or
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("memcpy") or
        fc.getTarget().hasName("memmove")
      ) and
      this.asExpr() = fc.getArgument(2)
    )
  }
}

private class ExternalInput extends DataFlow::Node {
  ExternalInput() {
    exists(Function main, Parameter argv |
      main.hasName("main") and
      argv = main.getParameter(1) and
      this.asParameter() = argv
    )
    or
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("getenv") or
        fc.getTarget().hasName("fgets") or
        fc.getTarget().hasName("gets") or
        fc.getTarget().hasName("scanf") or
        fc.getTarget().hasName("recv")
      ) and
      this.asExpr() = fc
    )
  }
}

module BofConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ExternalInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeBufferSink }
}

module BofFlow = TaintTracking::Global<BofConfig>;

from DataFlow::Node source, DataFlow::Node sink
where BofFlow::flow(source, sink)
select sink, "Buffer overflow: user-controlled data from $@ flows into unsafe buffer operation.", source, "user input"
""",
)

_CPP_SSRF = QLTemplate(
    key="cpp/ssrf",
    language="cpp",
    vuln_type="ssrf",
    description="C/C++ SSRF（libcurl curl_easy_setopt CURLOPT_URL）",
    code="""\
/**
 * @name Server-Side Request Forgery (C/C++)
 * @description User-controlled URL flows into HTTP request without validation.
 * @kind problem
 * @problem.severity error
 * @id cpp/ssrf
 * @tags security external/cwe/cwe-918
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class SsrfSink extends DataFlow::Node {
  SsrfSink() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("curl_easy_setopt") and
      this.asExpr() = fc.getArgument(2)
    )
    or
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("connect") or
        fc.getTarget().hasName("getaddrinfo")
      ) and
      this.asExpr() = fc.getArgument(0)
    )
  }
}

private class ExternalInput extends DataFlow::Node {
  ExternalInput() {
    exists(Function main, Parameter argv |
      main.hasName("main") and
      argv = main.getParameter(1) and
      this.asParameter() = argv
    )
    or
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("getenv") or
        fc.getTarget().hasName("fgets") or
        fc.getTarget().hasName("recv")
      ) and
      this.asExpr() = fc
    )
  }
}

module SsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ExternalInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof SsrfSink }
}

module SsrfFlow = TaintTracking::Global<SsrfConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SsrfFlow::flow(source, sink)
select sink, "SSRF: user-controlled URL from $@ flows into HTTP request.", source, "user input"
""",
)

_PYTHON_PATH_TRAVERSAL = QLTemplate(
    key="python/path-traversal",
    language="python",
    vuln_type="path traversal",
    description="Python 路径穿越（open / os.path / shutil）",
    code="""\
/**
 * @name Path Traversal (Python)
 * @description User-controlled path flows into file access without validation.
 * @kind problem
 * @problem.severity error
 * @id python/path-traversal
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class PathSink extends DataFlow::Node {
  PathSink() {
    exists(Call c |
      (
        c.getFunc().(Name).getId() = "open" or
        c.getFunc().(Attribute).getName() = "read_text" or
        c.getFunc().(Attribute).getName() = "write_text" or
        c.getFunc().(Attribute).getName() = "open"
      ) and
      this.asExpr() = c.getArg(0)
    )
    or
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "join" or
        c.getFunc().(Attribute).getName() = "send_file"
      ) and
      this.asExpr() = c.getArg(0)
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

_PYTHON_XSS = QLTemplate(
    key="python/xss",
    language="python",
    vuln_type="xss",
    description="Python 反射型/存储型 XSS（直接返回用户输入到 HTML 响应）",
    code="""\
/**
 * @name Cross-Site Scripting (Python)
 * @description User-controlled data flows into HTTP response without escaping.
 * @kind problem
 * @problem.severity error
 * @id python/xss
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class XssSink extends DataFlow::Node {
  XssSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "make_response" or
        c.getFunc().(Name).getId() = "Markup" or
        c.getFunc().(Attribute).getName() = "mark_safe" or
        c.getFunc().(Name).getId() = "HttpResponse"
      ) and
      this.asExpr() = c.getArg(0)
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "format_html" and
      this.asExpr() = c.getArg(0)
    )
  }
}

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }
}

module XssFlow = TaintTracking::Global<XssConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XssFlow::flow(source, sink)
select sink, "XSS: user-controlled data from $@ flows into HTTP response without escaping.", source, "user input"
""",
)

_PYTHON_SSRF = QLTemplate(
    key="python/ssrf",
    language="python",
    vuln_type="ssrf",
    description="Python SSRF（requests.get / urllib.request.urlopen）",
    code="""\
/**
 * @name Server-Side Request Forgery (Python)
 * @description User-controlled URL flows into HTTP request without validation.
 * @kind problem
 * @problem.severity error
 * @id python/ssrf
 * @tags security external/cwe/cwe-918
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class SsrfSink extends DataFlow::Node {
  SsrfSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "get" or
        c.getFunc().(Attribute).getName() = "post" or
        c.getFunc().(Attribute).getName() = "put" or
        c.getFunc().(Attribute).getName() = "delete" or
        c.getFunc().(Attribute).getName() = "request" or
        c.getFunc().(Attribute).getName() = "urlopen"
      ) and
      this.asExpr() = c.getArg(0)
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

_GO_XSS = QLTemplate(
    key="go/xss",
    language="go",
    vuln_type="xss",
    description="Go XSS（net/http ResponseWriter.Write / template.HTML）",
    code="""\
/**
 * @name Cross-Site Scripting (Go)
 * @description User-controlled data flows into HTTP response without escaping.
 * @kind problem
 * @problem.severity error
 * @id go/xss
 * @tags security external/cwe/cwe-079
 */
import go

private class XssSink extends DataFlow::Node {
  XssSink() {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().(Method).hasQualifiedName("net/http", "ResponseWriter", "Write") or
        call.getTarget().hasQualifiedName("fmt", "Fprintf") or
        call.getTarget().hasQualifiedName("fmt", "Fprint")
      ) and
      this = call.getArgument(0)
    )
    or
    exists(TypeAssertExpr ta |
      ta.getTypeExpr().toString() = "template.HTML" and
      this.asExpr() = ta.getExpr()
    )
  }
}

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }
}

module XssFlow = TaintTracking::Global<XssConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XssFlow::flow(source, sink)
select sink, "XSS: user-controlled data from $@ flows into HTTP response without escaping.", source, "user input"
""",
)

# ---------------------------------------------------------------------------
# Java 新增模板（XSS / Deserialization / XXE / LDAP）
# ---------------------------------------------------------------------------

_JAVA_XSS = QLTemplate(
    key="java/xss",
    language="java",
    vuln_type="xss",
    description="Java 反射型/存储型 XSS（Servlet response.getWriter 直接输出用户输入）",
    code="""\
/**
 * @name Cross-Site Scripting (Java)
 * @description User-controlled data flows into HTTP response without escaping.
 * @kind problem
 * @problem.severity error
 * @id java/xss
 * @tags security external/cwe/cwe-079
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class XssSink extends DataFlow::Node {
  XssSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "print") or
        mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "println") or
        mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "write") or
        mc.getMethod().hasQualifiedName("javax.servlet", "ServletOutputStream", "print") or
        mc.getMethod().hasQualifiedName("javax.servlet", "ServletOutputStream", "println")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }
}

module XssFlow = TaintTracking::Global<XssConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XssFlow::flow(source, sink)
select sink, "XSS: user-controlled data from $@ flows into HTTP response without escaping.", source, "user input"
""",
)

_JAVA_DESERIALIZATION = QLTemplate(
    key="java/deserialization",
    language="java",
    vuln_type="deserialization",
    description="Java 不安全反序列化（ObjectInputStream.readObject）",
    code="""\
/**
 * @name Unsafe Deserialization (Java)
 * @description User-controlled data flows into ObjectInputStream.readObject,
 *              enabling arbitrary code execution via gadget chains.
 * @kind problem
 * @problem.severity error
 * @id java/unsafe-deserialization
 * @tags security external/cwe/cwe-502
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class DeserSink extends DataFlow::Node {
  DeserSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readObject") or
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readUnshared")
      ) and
      this.asExpr() = mc.getQualifier()
    )
    or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream") and
      this.asExpr() = cc.getArgument(0)
    )
  }
}

module DeserConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DeserSink }
}

module DeserFlow = TaintTracking::Global<DeserConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DeserFlow::flow(source, sink)
select sink, "Unsafe deserialization: user-controlled data from $@ reaches ObjectInputStream.", source, "user input"
""",
)

_JAVA_XXE = QLTemplate(
    key="java/xxe",
    language="java",
    vuln_type="xxe",
    description="Java XML External Entity 注入（DocumentBuilder / SAXParser / XMLReader）",
    code="""\
/**
 * @name XML External Entity Injection (Java)
 * @description User-controlled XML is parsed without disabling external entities,
 *              enabling file disclosure or SSRF.
 * @kind problem
 * @problem.severity error
 * @id java/xxe
 * @tags security external/cwe/cwe-611
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class XxeSink extends DataFlow::Node {
  XxeSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("javax.xml.parsers", "DocumentBuilder", "parse") or
        mc.getMethod().hasQualifiedName("javax.xml.parsers", "SAXParser", "parse") or
        mc.getMethod().hasQualifiedName("org.xml.sax", "XMLReader", "parse") or
        mc.getMethod().hasQualifiedName("javax.xml.transform", "Transformer", "transform")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module XxeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XxeSink }
}

module XxeFlow = TaintTracking::Global<XxeConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XxeFlow::flow(source, sink)
select sink, "XXE: user-controlled XML from $@ flows into XML parser without disabling external entities.", source, "user input"
""",
)

_JAVA_LDAP_INJECTION = QLTemplate(
    key="java/ldap-injection",
    language="java",
    vuln_type="ldap injection",
    description="Java LDAP 注入（DirContext.search 过滤器拼接用户输入）",
    code="""\
/**
 * @name LDAP Injection (Java)
 * @description User-controlled data flows into LDAP search filter without sanitization.
 * @kind problem
 * @problem.severity error
 * @id java/ldap-injection
 * @tags security external/cwe/cwe-090
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class LdapSink extends DataFlow::Node {
  LdapSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("javax.naming.directory", "DirContext", "search") or
        mc.getMethod().hasQualifiedName("javax.naming.directory", "InitialDirContext", "search")
      ) and
      this.asExpr() = mc.getArgument(1)
    )
  }
}

module LdapConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof LdapSink }
}

module LdapFlow = TaintTracking::Global<LdapConfig>;

from DataFlow::Node source, DataFlow::Node sink
where LdapFlow::flow(source, sink)
select sink, "LDAP injection: user-controlled data from $@ flows into LDAP search filter.", source, "user input"
""",
)

# ---------------------------------------------------------------------------
# JavaScript 新增模板（XSS / Prototype Pollution）
# ---------------------------------------------------------------------------

_JS_XSS = QLTemplate(
    key="javascript/xss",
    language="javascript",
    vuln_type="xss",
    description="JavaScript 反射型/存储型 XSS（res.send / innerHTML 直接输出用户输入）",
    code="""\
/**
 * @name Cross-Site Scripting (JavaScript)
 * @description User-controlled data flows into HTTP response or DOM sink without escaping.
 * @kind problem
 * @problem.severity error
 * @id javascript/xss
 * @tags security external/cwe/cwe-079
 */
import javascript

private class XssSink extends DataFlow::Node {
  XssSink() {
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = "send" or
        call.getCalleeName() = "end" or
        call.getCalleeName() = "write" or
        call.getCalleeName() = "html"
      ) and
      this = call.getArgument(0)
    )
    or
    exists(DataFlow::PropWrite pw |
      pw.getPropertyName() = "innerHTML" and
      this = pw.getRhs()
    )
  }
}

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }
}

module XssFlow = TaintTracking::Global<XssConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XssFlow::flow(source, sink)
select sink, "XSS: user-controlled data from $@ flows into response/DOM without escaping.", source, "user input"
""",
)

_JS_PROTOTYPE_POLLUTION = QLTemplate(
    key="javascript/prototype-pollution",
    language="javascript",
    vuln_type="prototype pollution",
    description="JavaScript 原型链污染（用户可控键值对赋值到对象属性）",
    code="""\
/**
 * @name Prototype Pollution (JavaScript)
 * @description User-controlled property name flows into dynamic property assignment,
 *              enabling prototype pollution attacks.
 * @kind problem
 * @problem.severity error
 * @id javascript/prototype-pollution
 * @tags security external/cwe/cwe-1321
 */
import javascript

private class ProtoPollutionSink extends DataFlow::Node {
  ProtoPollutionSink() {
    exists(DataFlow::PropWrite pw |
      pw.getPropertyNameExpr().flow().getALocalSource() instanceof RemoteFlowSource and
      this = pw.getRhs()
    )
    or
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = "merge" or
        call.getCalleeName() = "extend" or
        call.getCalleeName() = "assign" or
        call.getCalleeName() = "defaultsDeep"
      ) and
      this = call.getArgument(0)
    )
  }
}

module ProtoConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof ProtoPollutionSink }
}

module ProtoFlow = TaintTracking::Global<ProtoConfig>;

from DataFlow::Node source, DataFlow::Node sink
where ProtoFlow::flow(source, sink)
select sink, "Prototype pollution: user-controlled data from $@ flows into dynamic property assignment.", source, "user input"
""",
)

# ---------------------------------------------------------------------------
# Solidity 模板集合
# ---------------------------------------------------------------------------

_SOLIDITY_REENTRANCY = QLTemplate(
    key="solidity/reentrancy",
    language="solidity",
    vuln_type="reentrancy",
    description="Solidity 重入攻击（外部调用后修改状态变量）",
    code="""\
/**
 * @name Reentrancy Vulnerability (Solidity)
 * @description External call is made before state variable update,
 *              enabling reentrancy attack.
 * @kind problem
 * @problem.severity error
 * @id solidity/reentrancy
 * @tags security external/cwe/cwe-841
 */
import solidity

from FunctionDefinition f, ExternalCall ec, StateVariableWrite sw
where
  ec.getEnclosingFunction() = f and
  sw.getEnclosingFunction() = f and
  ec.getLocation().getStartLine() < sw.getLocation().getStartLine() and
  not exists(Modifier m |
    m.getName() = "nonReentrant" and
    f.getAModifier() = m
  )
select ec,
  "Reentrancy: external call at line " + ec.getLocation().getStartLine().toString() +
  " precedes state update at line " + sw.getLocation().getStartLine().toString() +
  " in function " + f.getName()
""",
)

_SOLIDITY_UNCHECKED_CALL = QLTemplate(
    key="solidity/unchecked-call",
    language="solidity",
    vuln_type="unchecked call",
    description="Solidity 未检查的外部调用返回值（call/send/transfer 返回值被忽略）",
    code="""\
/**
 * @name Unchecked External Call (Solidity)
 * @description Return value of low-level call/send is not checked,
 *              which may silently fail.
 * @kind problem
 * @problem.severity warning
 * @id solidity/unchecked-call
 * @tags security external/cwe/cwe-252
 */
import solidity

from LowLevelCall llc
where
  not exists(IfStmt ifStmt |
    ifStmt.getCondition().getAChild*() = llc
  ) and
  not exists(RequireCall req |
    req.getArgument(0).getAChild*() = llc
  ) and
  not exists(AssignExpr ae |
    ae.getRhs().getAChild*() = llc
  )
select llc,
  "Unchecked low-level call: return value of " + llc.toString() + " is not checked"
""",
)

_SOLIDITY_TX_ORIGIN = QLTemplate(
    key="solidity/tx-origin",
    language="solidity",
    vuln_type="tx.origin",
    description="Solidity tx.origin 鉴权绕过（使用 tx.origin 代替 msg.sender 做访问控制）",
    code="""\
/**
 * @name tx.origin Authentication Bypass (Solidity)
 * @description Using tx.origin for authorization enables phishing attacks.
 * @kind problem
 * @problem.severity warning
 * @id solidity/tx-origin
 * @tags security external/cwe/cwe-477
 */
import solidity

from RequireCall req, MemberAccess ma
where
  ma.getMemberName() = "origin" and
  ma.getExpression().toString() = "tx" and
  req.getArgument(0).getAChild*() = ma
select req,
  "Authentication bypass: tx.origin is used for authorization instead of msg.sender"
""",
)

# ---------------------------------------------------------------------------
# C# 新增模板（XSS / Deserialization）
# ---------------------------------------------------------------------------

_CSHARP_XSS = QLTemplate(
    key="csharp/xss",
    language="csharp",
    vuln_type="xss",
    description="C# 反射型 XSS（MVC Content / HTML raw 输出）",
    code="""\
/**
 * @name Cross-Site Scripting (C#)
 * @description User-controlled data flows into HTTP response without encoding.
 * @kind problem
 * @problem.severity error
 * @id csharp/xss
 * @tags security external/cwe/cwe-079
 */
import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote

private class XssSink extends DataFlow::Node {
  XssSink() {
    exists(MethodCall mc |
      (
        mc.getTarget().getName() = "Content" or
        mc.getTarget().getName() = "Write" or
        mc.getTarget().getName() = "WriteLiteral" or
        mc.getTarget().getName() = "Raw"
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }
}

module XssFlow = TaintTracking::Global<XssConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XssFlow::flow(source, sink)
select sink, "XSS: user-controlled data from $@ flows into HTTP response without encoding.", source, "user input"
""",
)

_CSHARP_DESERIALIZATION = QLTemplate(
    key="csharp/deserialization",
    language="csharp",
    vuln_type="deserialization",
    description="C# 不安全反序列化（BinaryFormatter / JavaScriptSerializer / Newtonsoft TypeNameHandling）",
    code="""\
/**
 * @name Unsafe Deserialization (C#)
 * @description User-controlled data flows into an unsafe deserializer,
 *              enabling arbitrary code execution.
 * @kind problem
 * @problem.severity error
 * @id csharp/unsafe-deserialization
 * @tags security external/cwe/cwe-502
 */
import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote

private class DeserSink extends DataFlow::Node {
  DeserSink() {
    exists(MethodCall mc |
      (
        mc.getTarget().hasQualifiedName("System.Runtime.Serialization.Formatters.Binary", "BinaryFormatter", "Deserialize") or
        mc.getTarget().hasQualifiedName("System.Web.Script.Serialization", "JavaScriptSerializer", "Deserialize") or
        mc.getTarget().hasQualifiedName("Newtonsoft.Json", "JsonConvert", "DeserializeObject")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module DeserConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DeserSink }
}

module DeserFlow = TaintTracking::Global<DeserConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DeserFlow::flow(source, sink)
select sink, "Unsafe deserialization: user-controlled data from $@ reaches unsafe deserializer.", source, "user input"
""",
)

# ---------------------------------------------------------------------------
# Python 新增模板（Deserialization / LDAP）
# ---------------------------------------------------------------------------

_PYTHON_DESERIALIZATION = QLTemplate(
    key="python/deserialization",
    language="python",
    vuln_type="deserialization",
    description="Python 不安全反序列化（pickle.loads / yaml.load / marshal.loads）",
    code="""\
/**
 * @name Unsafe Deserialization (Python)
 * @description User-controlled data flows into pickle.loads or yaml.load,
 *              enabling arbitrary code execution.
 * @kind problem
 * @problem.severity error
 * @id python/unsafe-deserialization
 * @tags security external/cwe/cwe-502
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class DeserSink extends DataFlow::Node {
  DeserSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "loads" or
        c.getFunc().(Attribute).getName() = "load"
      ) and
      this.asExpr() = c.getArg(0)
    )
  }
}

module DeserConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DeserSink }
}

module DeserFlow = TaintTracking::Global<DeserConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DeserFlow::flow(source, sink)
select sink, "Unsafe deserialization: user-controlled data from $@ reaches pickle/yaml deserializer.", source, "user input"
""",
)

_PYTHON_LDAP_INJECTION = QLTemplate(
    key="python/ldap-injection",
    language="python",
    vuln_type="ldap injection",
    description="Python LDAP 注入（ldap.search_s 过滤器拼接用户输入）",
    code="""\
/**
 * @name LDAP Injection (Python)
 * @description User-controlled data flows into LDAP search filter without escaping.
 * @kind problem
 * @problem.severity error
 * @id python/ldap-injection
 * @tags security external/cwe/cwe-090
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

private class LdapSink extends DataFlow::Node {
  LdapSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "search_s" or
        c.getFunc().(Attribute).getName() = "search" or
        c.getFunc().(Attribute).getName() = "search_ext_s"
      ) and
      this.asExpr() = c.getArg(2)
    )
  }
}

module LdapConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof LdapSink }
}

module LdapFlow = TaintTracking::Global<LdapConfig>;

from DataFlow::Node source, DataFlow::Node sink
where LdapFlow::flow(source, sink)
select sink, "LDAP injection: user-controlled data from $@ flows into LDAP search filter.", source, "user input"
""",
)

# ---------------------------------------------------------------------------
# C++ 新增模板（Format String / Use-After-Free）
# ---------------------------------------------------------------------------

_CPP_FORMAT_STRING = QLTemplate(
    key="cpp/format-string",
    language="cpp",
    vuln_type="format string",
    description="C/C++ 格式化字符串漏洞（printf/sprintf/fprintf 用户可控格式串）",
    code="""\
/**
 * @name Format String Vulnerability (C/C++)
 * @description User-controlled data is used as a format string argument.
 * @kind problem
 * @problem.severity error
 * @id cpp/format-string
 * @tags security external/cwe/cwe-134
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class FormatStringSink extends DataFlow::Node {
  FormatStringSink() {
    exists(FunctionCall fc, int fmtIdx |
      (
        fc.getTarget().hasName("printf") and fmtIdx = 0 or
        fc.getTarget().hasName("fprintf") and fmtIdx = 1 or
        fc.getTarget().hasName("sprintf") and fmtIdx = 1 or
        fc.getTarget().hasName("snprintf") and fmtIdx = 2 or
        fc.getTarget().hasName("syslog") and fmtIdx = 1
      ) and
      this.asExpr() = fc.getArgument(fmtIdx)
    )
  }
}

private class ExternalInput extends DataFlow::Node {
  ExternalInput() {
    exists(Function main, Parameter argv |
      main.hasName("main") and
      argv = main.getParameter(1) and
      this.asParameter() = argv
    )
    or
    exists(FunctionCall fc |
      (
        fc.getTarget().hasName("getenv") or
        fc.getTarget().hasName("fgets") or
        fc.getTarget().hasName("gets") or
        fc.getTarget().hasName("recv")
      ) and
      this.asExpr() = fc
    )
  }
}

module FmtConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ExternalInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof FormatStringSink }
}

module FmtFlow = TaintTracking::Global<FmtConfig>;

from DataFlow::Node source, DataFlow::Node sink
where FmtFlow::flow(source, sink)
select sink, "Format string vulnerability: user-controlled data from $@ used as format string.", source, "user input"
""",
)

_CPP_USE_AFTER_FREE = QLTemplate(
    key="cpp/use-after-free",
    language="cpp",
    vuln_type="use after free",
    description="C/C++ 释放后使用（free 之后继续解引用指针）",
    code="""\
/**
 * @name Use After Free (C/C++)
 * @description Pointer is dereferenced after being freed.
 * @kind problem
 * @problem.severity error
 * @id cpp/use-after-free
 * @tags security external/cwe/cwe-416
 */
import cpp
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall freeCall, VariableAccess useAccess, Variable v
where
  (freeCall.getTarget().hasName("free") or freeCall.getTarget().hasName("kfree")) and
  freeCall.getArgument(0).(VariableAccess).getTarget() = v and
  useAccess.getTarget() = v and
  useAccess.getLocation().getStartLine() > freeCall.getLocation().getStartLine() and
  useAccess.getEnclosingFunction() = freeCall.getEnclosingFunction() and
  not exists(AssignExpr reassign |
    reassign.getLValue().(VariableAccess).getTarget() = v and
    reassign.getLocation().getStartLine() > freeCall.getLocation().getStartLine() and
    reassign.getLocation().getStartLine() < useAccess.getLocation().getStartLine()
  )
select useAccess,
  "Use after free: variable '" + v.getName() + "' is used after being freed at line " +
  freeCall.getLocation().getStartLine().toString()
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
    _JAVA_XSS,
    _JAVA_DESERIALIZATION,
    _JAVA_XXE,
    _JAVA_LDAP_INJECTION,
    # Python - 模板注入
    _PYTHON_JINJA2,
    _PYTHON_MAKO,
    _PYTHON_SSTI_COMBINED,
    # Python - 通用
    _PYTHON_SQL_INJECTION,
    _PYTHON_COMMAND_INJECTION,
    _PYTHON_PATH_TRAVERSAL,
    _PYTHON_XSS,
    _PYTHON_SSRF,
    _PYTHON_DESERIALIZATION,
    _PYTHON_LDAP_INJECTION,
    # JavaScript
    _JS_SQL_INJECTION,
    _JS_COMMAND_INJECTION,
    _JS_PATH_TRAVERSAL,
    _JS_SSRF,
    _JS_XSS,
    _JS_PROTOTYPE_POLLUTION,
    # Go
    _GO_SQL_INJECTION,
    _GO_COMMAND_INJECTION,
    _GO_PATH_TRAVERSAL,
    _GO_SSRF,
    _GO_XSS,
    # C#
    _CSHARP_SQL_INJECTION,
    _CSHARP_COMMAND_INJECTION,
    _CSHARP_PATH_TRAVERSAL,
    _CSHARP_SSRF,
    _CSHARP_XSS,
    _CSHARP_DESERIALIZATION,
    # C++
    _CPP_COMMAND_INJECTION,
    _CPP_PATH_TRAVERSAL,
    _CPP_SQL_INJECTION,
    _CPP_BUFFER_OVERFLOW,
    _CPP_SSRF,
    _CPP_FORMAT_STRING,
    _CPP_USE_AFTER_FREE,
    # Solidity
    _SOLIDITY_REENTRANCY,
    _SOLIDITY_UNCHECKED_CALL,
    _SOLIDITY_TX_ORIGIN,
]

# 关键词 → 模板映射（优先精确匹配）
_KEYWORD_MAP: dict[str, dict[str, QLTemplate]] = {}

_KEYWORD_MAP_FLAT: dict[str, QLTemplate] = {
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
    # Python
    "jinja2":                       _PYTHON_JINJA2,
    "jinja":                        _PYTHON_JINJA2,
    "mako":                         _PYTHON_MAKO,
    "ssti":                         _PYTHON_SSTI_COMBINED,
    "template injection":           _PYTHON_SSTI_COMBINED,
    "server-side template":         _PYTHON_SSTI_COMBINED,
}

_LANG_KEYWORD_MAP: dict[str, dict[str, QLTemplate]] = {
    "java": {
        "sql injection":                _JAVA_SQL_INJECTION,
        "sql":                          _JAVA_SQL_INJECTION,
        "sqli":                         _JAVA_SQL_INJECTION,
        "command injection":            _JAVA_COMMAND_INJECTION,
        "os command":                   _JAVA_COMMAND_INJECTION,
        "rce":                          _JAVA_COMMAND_INJECTION,
        "path traversal":              _JAVA_PATH_TRAVERSAL,
        "directory traversal":         _JAVA_PATH_TRAVERSAL,
        "lfi":                          _JAVA_PATH_TRAVERSAL,
        "ssrf":                         _JAVA_SSRF,
        "server-side request forgery":  _JAVA_SSRF,
        "server side request forgery":  _JAVA_SSRF,
        "xss":                          _JAVA_XSS,
        "cross-site scripting":        _JAVA_XSS,
        "cross site scripting":        _JAVA_XSS,
        "deserialization":             _JAVA_DESERIALIZATION,
        "unsafe deserialization":      _JAVA_DESERIALIZATION,
        "readobject":                   _JAVA_DESERIALIZATION,
        "xxe":                          _JAVA_XXE,
        "xml external entity":         _JAVA_XXE,
        "xml injection":               _JAVA_XXE,
        "ldap injection":              _JAVA_LDAP_INJECTION,
        "ldap":                         _JAVA_LDAP_INJECTION,
    },
    "python": {
        "sql injection":                _PYTHON_SQL_INJECTION,
        "sql":                          _PYTHON_SQL_INJECTION,
        "sqli":                         _PYTHON_SQL_INJECTION,
        "command injection":            _PYTHON_COMMAND_INJECTION,
        "os command":                   _PYTHON_COMMAND_INJECTION,
        "rce":                          _PYTHON_COMMAND_INJECTION,
        "path traversal":              _PYTHON_PATH_TRAVERSAL,
        "directory traversal":         _PYTHON_PATH_TRAVERSAL,
        "lfi":                          _PYTHON_PATH_TRAVERSAL,
        "xss":                          _PYTHON_XSS,
        "cross-site scripting":        _PYTHON_XSS,
        "cross site scripting":        _PYTHON_XSS,
        "ssrf":                         _PYTHON_SSRF,
        "server-side request forgery":  _PYTHON_SSRF,
        "server side request forgery":  _PYTHON_SSRF,
        "deserialization":             _PYTHON_DESERIALIZATION,
        "unsafe deserialization":      _PYTHON_DESERIALIZATION,
        "pickle":                       _PYTHON_DESERIALIZATION,
        "yaml.load":                    _PYTHON_DESERIALIZATION,
        "ldap injection":              _PYTHON_LDAP_INJECTION,
        "ldap":                         _PYTHON_LDAP_INJECTION,
    },
    "javascript": {
        "sql injection":                _JS_SQL_INJECTION,
        "sql":                          _JS_SQL_INJECTION,
        "sqli":                         _JS_SQL_INJECTION,
        "command injection":            _JS_COMMAND_INJECTION,
        "os command":                   _JS_COMMAND_INJECTION,
        "rce":                          _JS_COMMAND_INJECTION,
        "path traversal":              _JS_PATH_TRAVERSAL,
        "directory traversal":         _JS_PATH_TRAVERSAL,
        "lfi":                          _JS_PATH_TRAVERSAL,
        "ssrf":                         _JS_SSRF,
        "server-side request forgery":  _JS_SSRF,
        "server side request forgery":  _JS_SSRF,
        "xss":                          _JS_XSS,
        "cross-site scripting":        _JS_XSS,
        "cross site scripting":        _JS_XSS,
        "prototype pollution":         _JS_PROTOTYPE_POLLUTION,
        "prototype":                    _JS_PROTOTYPE_POLLUTION,
    },
    "go": {
        "sql injection":                _GO_SQL_INJECTION,
        "sql":                          _GO_SQL_INJECTION,
        "sqli":                         _GO_SQL_INJECTION,
        "command injection":            _GO_COMMAND_INJECTION,
        "os command":                   _GO_COMMAND_INJECTION,
        "rce":                          _GO_COMMAND_INJECTION,
        "path traversal":              _GO_PATH_TRAVERSAL,
        "directory traversal":         _GO_PATH_TRAVERSAL,
        "lfi":                          _GO_PATH_TRAVERSAL,
        "ssrf":                         _GO_SSRF,
        "server-side request forgery":  _GO_SSRF,
        "server side request forgery":  _GO_SSRF,
        "xss":                          _GO_XSS,
        "cross-site scripting":        _GO_XSS,
        "cross site scripting":        _GO_XSS,
    },
    "csharp": {
        "sql injection":                _CSHARP_SQL_INJECTION,
        "sql":                          _CSHARP_SQL_INJECTION,
        "sqli":                         _CSHARP_SQL_INJECTION,
        "command injection":            _CSHARP_COMMAND_INJECTION,
        "os command":                   _CSHARP_COMMAND_INJECTION,
        "rce":                          _CSHARP_COMMAND_INJECTION,
        "path traversal":              _CSHARP_PATH_TRAVERSAL,
        "directory traversal":         _CSHARP_PATH_TRAVERSAL,
        "lfi":                          _CSHARP_PATH_TRAVERSAL,
        "ssrf":                         _CSHARP_SSRF,
        "server-side request forgery":  _CSHARP_SSRF,
        "server side request forgery":  _CSHARP_SSRF,
        "xss":                          _CSHARP_XSS,
        "cross-site scripting":        _CSHARP_XSS,
        "cross site scripting":        _CSHARP_XSS,
        "deserialization":             _CSHARP_DESERIALIZATION,
        "unsafe deserialization":      _CSHARP_DESERIALIZATION,
        "binaryformatter":             _CSHARP_DESERIALIZATION,
    },
    "cpp": {
        "command injection":            _CPP_COMMAND_INJECTION,
        "os command":                   _CPP_COMMAND_INJECTION,
        "rce":                          _CPP_COMMAND_INJECTION,
        "path traversal":              _CPP_PATH_TRAVERSAL,
        "directory traversal":         _CPP_PATH_TRAVERSAL,
        "lfi":                          _CPP_PATH_TRAVERSAL,
        "sql injection":                _CPP_SQL_INJECTION,
        "sql":                          _CPP_SQL_INJECTION,
        "sqli":                         _CPP_SQL_INJECTION,
        "buffer overflow":             _CPP_BUFFER_OVERFLOW,
        "stack overflow":              _CPP_BUFFER_OVERFLOW,
        "heap overflow":               _CPP_BUFFER_OVERFLOW,
        "bof":                          _CPP_BUFFER_OVERFLOW,
        "ssrf":                         _CPP_SSRF,
        "server-side request forgery":  _CPP_SSRF,
        "server side request forgery":  _CPP_SSRF,
        "format string":               _CPP_FORMAT_STRING,
        "printf":                       _CPP_FORMAT_STRING,
        "use after free":              _CPP_USE_AFTER_FREE,
        "uaf":                          _CPP_USE_AFTER_FREE,
        "double free":                 _CPP_USE_AFTER_FREE,
    },
    "solidity": {
        "reentrancy":                   _SOLIDITY_REENTRANCY,
        "reentrant":                    _SOLIDITY_REENTRANCY,
        "re-entrancy":                  _SOLIDITY_REENTRANCY,
        "unchecked call":              _SOLIDITY_UNCHECKED_CALL,
        "unchecked return":            _SOLIDITY_UNCHECKED_CALL,
        "unchecked send":              _SOLIDITY_UNCHECKED_CALL,
        "tx.origin":                    _SOLIDITY_TX_ORIGIN,
        "tx origin":                    _SOLIDITY_TX_ORIGIN,
        "authentication bypass":       _SOLIDITY_TX_ORIGIN,
    },
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

        # 1. 语言无关的特殊关键词（如 spel / ognl / jinja2）
        for kw, tmpl in _KEYWORD_MAP_FLAT.items():
            if kw in query and tmpl.language == lang:
                logger.info(
                    "模板知识库命中 [特殊关键词='%s']: %s", kw, tmpl.key
                )
                return tmpl

        # 2. 按语言查找通用漏洞模板
        lang_map = _LANG_KEYWORD_MAP.get(lang, {})
        for kw, tmpl in lang_map.items():
            if kw in query:
                logger.info(
                    "模板知识库命中 [语言=%s, 关键词='%s']: %s", lang, kw, tmpl.key
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
