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

from src.agents.base_agent import BaseAgent
from src.utils.codeql_runner import CodeQLRunner
from src.utils.ql_template_library import QLTemplateLibrary
from src.utils import vuln_catalog

logger = logging.getLogger(__name__)

MAX_RETRIES: int = 3

# ---------------------------------------------------------------------------
# Prompt 模板
# ---------------------------------------------------------------------------

# 按语言选择对应系统提示
_SYSTEM_PROMPT_JAVA = """\
你是一位精通 CodeQL 静态分析的安全研究专家，擅长检测各类 Java 安全漏洞，包括但不限于：
- 注入类：SQL注入、命令注入、路径穿越、SSRF、反序列化、表达式注入
- 密码学：弱加密算法、硬编码凭证、不安全随机数、不安全TLS配置
- 资源管理：资源泄露、并发竞态
- 信息泄露：敏感数据暴露、堆栈跟踪泄露

你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 黄金模板 A：污点追踪查询（注入类漏洞）━━━━━━━━━━

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

━━━━━━━━━━ 黄金模板 B：模式匹配查询（密码学/配置/资源类问题）━━━━━━━━━━

/**
 * @name 使用不安全的加密算法
 * @description 检测 MD5/SHA-1/DES 等已被破解的算法
 * @kind problem
 * @problem.severity warning
 * @id java/weak-crypto-algorithm
 * @tags security
 *       cryptography
 */
import java

from MethodCall mc
where
  mc.getMethod().hasQualifiedName("java.security", "MessageDigest", "getInstance") and
  mc.getArgument(0).(CompileTimeConstantExpr).getStringValue().regexpMatch("(?i)(MD5|SHA-1|DES|RC4)")
select mc, "使用了不安全的加密算法: " + mc.getArgument(0).(CompileTimeConstantExpr).getStringValue()

━━━━━━━━━━ 黄金模板 C：硬编码凭证检测 ━━━━━━━━━━

/**
 * @name 硬编码密码/密钥
 * @description 检测源代码中硬编码的密码或密钥
 * @kind problem
 * @problem.severity error
 * @id java/hardcoded-credential
 * @tags security
 */
import java

from Assignment assign, Variable v
where
  v.getName().regexpMatch("(?i).*(password|passwd|secret|api_?key|token|credential).*") and
  assign.getDest() = v.getAnAccess() and
  assign.getSource() instanceof StringLiteral and
  assign.getSource().(StringLiteral).getValue().length() > 3
select assign, "变量 '" + v.getName() + "' 可能包含硬编码凭证"

━━━━━━━━━━ Java 关键规则（违反任何一条都会编译失败）━━━━━━━━━━
1. 必须使用 import semmle.code.java.dataflow.FlowSources （RemoteFlowSource 在此模块）
2. 禁止使用 semmle.code.java.security.* 路径（此路径不存在）
3. 禁止使用 TaintTracking::Configuration（已废弃），必须用 module Flow = TaintTracking::Global<FlowConfig>
4. 方法调用类型是 MethodCall，不是 MethodAccess
5. hasQualifiedName 接受三个字符串参数：(包名, 类名, 方法名)
6. DataFlow::ConfigSig 的 module 实现使用 implements 关键字，不需要 extends
7. 模式匹配查询（模板 B/C）不需要 import TaintTracking 和 FlowSources，只需 import java
"""

_SYSTEM_PROMPT_PYTHON = """\
你是一位精通 CodeQL 静态分析的安全研究专家，擅长检测各类 Python 安全漏洞（SQL注入、命令注入、模板注入SSTI、路径穿越、不安全反序列化等）。
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

_SYSTEM_PROMPT_JAVASCRIPT = """\
你是一位精通 CodeQL 静态分析的安全研究专家，擅长检测各类 JavaScript/TypeScript 安全漏洞（SQL注入、命令注入、XSS、路径穿越、SSRF、原型链污染等）。
你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 已验证可编译的 JavaScript 黄金模板（必须严格遵守此结构）━━━━━━━━━━

/**
 * @name <查询名称>
 * @description <描述>
 * @kind problem
 * @problem.severity error
 * @id javascript/<唯一id>
 * @tags security
 */
import javascript

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "<函数名>" and
      this = call.getArgument(0)
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

━━━━━━━━━━ JavaScript 关键规则（违反任何一条都会编译失败）━━━━━━━━━━
1. 只需 import javascript（已包含 DataFlow、TaintTracking、RemoteFlowSource）
2. 禁止使用 import semmle.javascript.*（会导致重复导入错误）
3. 使用 DataFlow::CallNode 而非 MethodCall；用 call.getCalleeName() 获取函数名
4. 获取参数用 call.getArgument(n)，返回 DataFlow::Node，直接与 this 比较（不需要 .asExpr()）
5. RemoteFlowSource 覆盖 Express req.query / req.body / req.params 等
6. 同样使用 module Flow = TaintTracking::Global<FlowConfig> 和 implements 关键字
"""

_SYSTEM_PROMPT_GO = """\
你是一位精通 CodeQL 静态分析的安全研究专家，擅长检测各类 Go 安全漏洞（SQL注入、命令注入、路径穿越、SSRF、不安全反序列化等）。
你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 已验证可编译的 Go 黄金模板（必须严格遵守此结构）━━━━━━━━━━

/**
 * @name <查询名称>
 * @description <描述>
 * @kind problem
 * @problem.severity error
 * @id go/<唯一id>
 * @tags security
 */
import go

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("<包路径>", "<函数名>") and
      this = call.getArgument(0)
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

━━━━━━━━━━ Go 关键规则（违反任何一条都会编译失败）━━━━━━━━━━
1. 只需 import go（已包含 DataFlow、TaintTracking、RemoteFlowSource）
2. 包级函数用 call.getTarget().hasQualifiedName("包路径", "函数名")（两参数）
3. 方法用 call.getTarget().(Method).hasQualifiedName("包路径", "类型名", "方法名")（三参数）
4. 获取参数用 call.getArgument(n)，返回 DataFlow::Node（不需要 .asExpr()）
5. RemoteFlowSource 覆盖 net/http Handler 参数等
6. 同样使用 module Flow = TaintTracking::Global<FlowConfig> 和 implements 关键字
"""

_SYSTEM_PROMPT_CSHARP = """\
你是一位精通 CodeQL 静态分析的安全研究专家，擅长检测各类 C# 安全漏洞（SQL注入、命令注入、路径穿越、SSRF、不安全反序列化、XSS等）。
你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 已验证可编译的 C# 黄金模板（必须严格遵守此结构）━━━━━━━━━━

/**
 * @name <查询名称>
 * @description <描述>
 * @kind problem
 * @problem.severity error
 * @id csharp/<唯一id>
 * @tags security
 */
import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(MethodCall mc |
      mc.getTarget().hasQualifiedName("<命名空间>", "<类名>", "<方法名>") and
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

━━━━━━━━━━ C# 关键规则（违反任何一条都会编译失败）━━━━━━━━━━
1. 必须导入 semmle.code.csharp.dataflow.TaintTracking 和 DataFlow
2. RemoteFlowSource 需要 import semmle.code.csharp.security.dataflow.flowsources.Remote
3. 方法调用类型是 MethodCall，与 Java 类似；构造器用 ObjectCreation
4. hasQualifiedName 接受三个字符串参数：(命名空间, 类名, 方法名)
5. 获取参数用 mc.getArgument(n)，this.asExpr() = mc.getArgument(n)
6. 同样使用 module Flow = TaintTracking::Global<FlowConfig> 和 implements 关键字
"""

_SYSTEM_PROMPT_CPP = """\
你是一位精通 CodeQL 静态分析的安全研究专家，擅长检测各类 C/C++ 安全漏洞，包括但不限于：
- 注入类：命令注入、格式化字符串、路径穿越
- 内存安全：缓冲区溢出、Use-After-Free、整数溢出、Double-Free
- 资源管理：内存泄露、文件句柄泄露
- 并发安全：竞态条件、数据竞争

你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 黄金模板 A：污点追踪查询（注入/格式化字符串类）━━━━━━━━━━

/**
 * @name <查询名称>
 * @description <描述>
 * @kind problem
 * @problem.severity error
 * @id cpp/<唯一id>
 * @tags security
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("<函数名>") and
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

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ExternalInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof CustomSink }
}

module Flow = TaintTracking::Global<FlowConfig>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "漏洞描述，数据来自 $@。", source, "用户可控输入"

━━━━━━━━━━ 黄金模板 B：模式匹配查询（危险 API 使用 / 缓冲区溢出）━━━━━━━━━━

/**
 * @name 使用不安全的字符串函数
 * @description 检测 strcpy/strcat/sprintf/gets 等无边界检查的函数
 * @kind problem
 * @problem.severity error
 * @id cpp/unsafe-string-function
 * @tags security
 *       memory-safety
 */
import cpp

from FunctionCall fc
where fc.getTarget().hasName(["strcpy", "strcat", "sprintf", "gets", "scanf"])
select fc, "调用了不安全的函数 " + fc.getTarget().getName() + "，建议使用带长度限制的安全版本"

━━━━━━━━━━ 黄金模板 C：整数溢出检测 ━━━━━━━━━━

/**
 * @name 整数溢出用于内存分配
 * @description 算术运算结果未经检查直接用于 malloc 等内存分配函数
 * @kind problem
 * @problem.severity error
 * @id cpp/integer-overflow-allocation
 * @tags security
 *       memory-safety
 */
import cpp
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall alloc, BinaryArithmeticOperation arith
where
  alloc.getTarget().hasName(["malloc", "calloc", "realloc", "alloca"]) and
  DataFlow::localFlow(DataFlow::exprNode(arith), DataFlow::exprNode(alloc.getArgument(0)))
select alloc, "内存分配大小来自未经检查的算术运算 $@。", arith, arith.toString()

━━━━━━━━━━ C/C++ 关键规则（违反任何一条都会编译失败）━━━━━━━━━━
1. 必须导入 semmle.code.cpp.dataflow.TaintTracking 和 DataFlow（污点追踪模板）
2. C/C++ 没有标准 RemoteFlowSource，需自定义 ExternalInput（argv、getenv 等）
3. 函数调用类型是 FunctionCall，用 fc.getTarget().hasName("<名称>") 匹配
4. 获取参数用 fc.getArgument(n)，this.asExpr() = fc.getArgument(n)
5. 同样使用 module Flow = TaintTracking::Global<FlowConfig> 和 implements 关键字
6. 对于 C++ 类方法可用 fc.getTarget().hasQualifiedName("<命名空间>", "<函数名>")
7. 模式匹配查询（模板 B）只需 import cpp，不需要 TaintTracking
8. 本地数据流查询（模板 C）用 DataFlow::localFlow()
"""

# ---------------------------------------------------------------------------
# Solidity / 智能合约 专用系统提示（v2.3 新增）
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT_SOLIDITY = """\
你是一位精通 Solidity 智能合约安全的静态分析专家。
你的输出必须是合法的、可以被 CodeQL 编译通过的 .ql 源代码，且只输出代码本身。
不要附带任何 markdown 代码块标记、解释或额外文字。

CodeQL 对 Solidity 的实验性支持使用以下 import 路径和类型：
- import solidity
- 常用类型：FunctionCall, Function, StateVariable, Assignment, BinaryExpr, IfStmt, Expr
- 可用谓词：getCallee(), getName(), getValue(), getAnArgument() 等

────────────────────────
黄金模板 1：重入攻击检测（@kind problem，模式匹配）
────────────────────────
/**
 * @name Reentrancy vulnerability
 * @description External call is made before state variable is updated
 * @kind problem
 * @problem.severity error
 * @id solidity/reentrancy
 * @tags security
 *       smart-contract
 */
import solidity

from FunctionCall externalCall, Assignment stateUpdate, Function f
where
  f = externalCall.getEnclosingFunction() and
  f = stateUpdate.getEnclosingFunction() and
  externalCall.getCallee().getName().matches("%call%") and
  externalCall.getLocation().getStartLine() < stateUpdate.getLocation().getStartLine()
select externalCall, "外部调用在状态更新之前执行，可能存在重入攻击风险"

────────────────────────
黄金模板 2：未检查的外部调用返回值
────────────────────────
/**
 * @name Unchecked external call return value
 * @description Return value of low-level call is not checked
 * @kind problem
 * @problem.severity warning
 * @id solidity/unchecked-call
 * @tags security
 *       smart-contract
 */
import solidity

from FunctionCall call
where
  call.getCallee().getName().regexpMatch("call|send|delegatecall") and
  not exists(IfStmt ifStmt | ifStmt.getCondition().getAChildExpr*() = call)
select call, "低层调用的返回值未被检查，可能导致资金丢失"

────────────────────────
支持的漏洞类型（优先模式匹配范式）：
1. 重入攻击（Reentrancy） - 外部调用先于状态更新
2. 未检查返回值（Unchecked call） - call/send/delegatecall 返回值未判断
3. 整数溢出（Integer Overflow） - Solidity < 0.8 无内置溢出检查
4. 权限控制缺失（Access Control） - 敏感函数缺少 onlyOwner 等修饰符
5. 自毁攻击（Selfdestruct） - selfdestruct 函数未做权限校验
6. tx.origin 认证（tx.origin Auth） - 使用 tx.origin 代替 msg.sender
"""

# ---------------------------------------------------------------------------
# Linux Kernel C 专用系统提示（Agent-T kernel_module 模式）
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT_KERNEL_C = """\
你是一位精通 CodeQL 静态分析的 Linux 内核安全研究专家，擅长检测内核代码中的安全漏洞，包括但不限于：
- 内存安全：Use-After-Free、Double-Free、缓冲区溢出（堆/栈）、整数溢出导致的内存分配错误
- 用户态输入校验：copy_from_user/get_user 返回值未检查、__user 指针直接解引用
- 竞态条件：锁保护不当、TOCTOU、引用计数错误
- 权限提升：capability 检查缺失、ioctl handler 未鉴权
- 信息泄露：未初始化内存通过 copy_to_user 泄露到用户态
- 空指针解引用：kmalloc/kzalloc 返回值未判空

你的输出必须是合法的、可以被 `codeql query compile` 编译通过的 .ql 源代码，且只输出代码本身，
不要附带任何 markdown 代码块标记（如 ```ql）、解释或注释以外的文字。

━━━━━━━━━━ 黄金模板 A：copy_from_user 返回值未检查 ━━━━━━━━━━

/**
 * @name Unchecked copy_from_user return value
 * @description copy_from_user 返回值未检查可能导致未初始化内存使用
 * @kind problem
 * @problem.severity error
 * @id cpp/kernel-unchecked-copy-from-user
 * @tags security
 *       kernel
 */
import cpp

from FunctionCall fc
where
  fc.getTarget().hasName("copy_from_user") and
  not exists(IfStmt ifStmt |
    ifStmt.getCondition().getAChild*() = fc
    or
    exists(AssignExpr assign |
      assign.getRValue() = fc and
      ifStmt.getCondition().getAChild*() = assign.getLValue().getAnAccess()
    )
  )
select fc, "copy_from_user 的返回值未被检查，可能导致使用未初始化的内核缓冲区数据"

━━━━━━━━━━ 黄金模板 B：kmalloc 返回值未判空 ━━━━━━━━━━

/**
 * @name Unchecked kmalloc return value
 * @description kmalloc/kzalloc 返回值未判空可能导致空指针解引用
 * @kind problem
 * @problem.severity error
 * @id cpp/kernel-unchecked-kmalloc
 * @tags security
 *       kernel
 *       memory-safety
 */
import cpp

from FunctionCall alloc, Variable v
where
  alloc.getTarget().hasName(["kmalloc", "kzalloc", "kcalloc", "kmalloc_array", "vmalloc", "vzalloc"]) and
  exists(AssignExpr assign |
    assign.getRValue() = alloc and
    assign.getLValue() = v.getAnAccess()
  ) and
  not exists(IfStmt ifStmt |
    ifStmt.getCondition().getAChild*().(EqualityOperation).getAnOperand() = v.getAnAccess() or
    ifStmt.getCondition().getAChild*().(NotExpr).getOperand() = v.getAnAccess() or
    ifStmt.getCondition().getAChild*() = v.getAnAccess()
  )
select alloc, "内核内存分配函数 " + alloc.getTarget().getName() + " 的返回值未检查是否为 NULL"

━━━━━━━━━━ 黄金模板 C：污点追踪（用户输入到危险 Sink）━━━━━━━━━━

/**
 * @name User-controlled data flows to dangerous kernel sink
 * @description 用户态数据经 copy_from_user 进入内核后未经校验直接用于危险操作
 * @kind problem
 * @problem.severity error
 * @id cpp/kernel-tainted-sink
 * @tags security
 *       kernel
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

private class KernelUserInput extends DataFlow::Node {
  KernelUserInput() {
    exists(FunctionCall fc |
      fc.getTarget().hasName(["copy_from_user", "__copy_from_user", "get_user", "__get_user"]) and
      this.asExpr() = fc.getArgument(0)
    )
  }
}

private class KernelDangerousSink extends DataFlow::Node {
  KernelDangerousSink() {
    exists(FunctionCall fc |
      fc.getTarget().hasName(["memcpy", "__memcpy", "memmove", "kmalloc", "kzalloc"]) and
      this.asExpr() = fc.getArgument(fc.getTarget().hasName(["kmalloc", "kzalloc"]).booleanNot().booleanAnd(true).toString().toInt())
    )
    or
    exists(ArrayExpr ae | this.asExpr() = ae.getArrayOffset())
  }
}

module KernelFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof KernelUserInput }
  predicate isSink(DataFlow::Node sink) { sink instanceof KernelDangerousSink }
}

module KernelFlow = TaintTracking::Global<KernelFlowConfig>;

from DataFlow::Node source, DataFlow::Node sink
where KernelFlow::flow(source, sink)
select sink, "用户态数据从 $@ 流入危险内核操作", source, "copy_from_user"

━━━━━━━━━━ 黄金模板 D：kfree 后使用（UAF 模式匹配）━━━━━━━━━━

/**
 * @name Potential Use-After-Free via kfree
 * @description kfree 释放内存后指针仍被使用
 * @kind problem
 * @problem.severity error
 * @id cpp/kernel-use-after-free
 * @tags security
 *       kernel
 *       memory-safety
 */
import cpp

from FunctionCall freeCall, VariableAccess useAfter, Variable v
where
  freeCall.getTarget().hasName(["kfree", "vfree", "kvfree"]) and
  freeCall.getArgument(0) = v.getAnAccess() and
  useAfter = v.getAnAccess() and
  useAfter != freeCall.getArgument(0) and
  useAfter.getLocation().getStartLine() > freeCall.getLocation().getStartLine() and
  useAfter.getEnclosingFunction() = freeCall.getEnclosingFunction()
select useAfter, "变量 '" + v.getName() + "' 在 $@ 被 kfree 释放后仍被使用", freeCall, "kfree 调用"

━━━━━━━━━━ Linux 内核 C 关键规则 ━━━━━━━━━━
1. 内核代码使用 cpp 语言包：import cpp
2. C/C++ 没有标准 RemoteFlowSource，内核的 Source 是 copy_from_user / get_user / ioctl 参数
3. 函数调用类型是 FunctionCall，用 fc.getTarget().hasName("<名称>") 匹配
4. 内核特有分配函数：kmalloc, kzalloc, kcalloc, vmalloc, vzalloc, kmalloc_array
5. 内核特有释放函数：kfree, vfree, kvfree, kfree_rcu
6. 同步原语：spin_lock/spin_unlock, mutex_lock/mutex_unlock, rcu_read_lock/rcu_read_unlock
7. 优先使用模式匹配（@kind problem）而非污点追踪，因为内核代码的数据流通常较短且局部
8. 同样使用 module Flow = TaintTracking::Global<FlowConfig> 和 implements 关键字
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
    "javascript": _SYSTEM_PROMPT_JAVASCRIPT,
    "go":         _SYSTEM_PROMPT_GO,
    "csharp":     _SYSTEM_PROMPT_CSHARP,
    "cpp":        _SYSTEM_PROMPT_CPP,
    "solidity":   _SYSTEM_PROMPT_SOLIDITY,
    "kernel":     _SYSTEM_PROMPT_KERNEL_C,
}


def _get_system_prompt(language: str, prompt_preset: str = "") -> str:
    """按语言或 prompt_preset 返回对应的系统提示。

    prompt_preset 优先于 language（由 Agent-T 的 CodebaseProfile 指定）。
    """
    if prompt_preset:
        hit = _SYSTEM_PROMPTS.get(prompt_preset.lower())
        if hit:
            return hit
    return _SYSTEM_PROMPTS.get(language.lower(), _SYSTEM_PROMPT_GENERIC)


_INITIAL_GENERATION_TEMPLATE = """\
请为以下目标生成 CodeQL 查询：

- **目标语言**：{language}
- **漏洞类型**：{vuln_type}
- **已知危险 Sink 方法 / 匹配特征**：{sink_hints}

查询范式选择指引（根据漏洞类型自动选择最合适的查询模式）：

**A. 污点追踪查询（Source → Sink 数据流）**
适用于：注入类漏洞（SQL注入/命令注入/XSS/SSRF/路径穿越/表达式注入/反序列化等）
→ 使用上方系统提示中的污点追踪黄金模板

**B. 模式匹配查询（@kind problem，无需数据流）**
适用于：硬编码凭证、弱加密算法、不安全随机数、不安全TLS配置、资源泄露、危险API使用
→ 直接匹配 AST 模式，示例结构：
```ql
/**
 * @name <查询名>
 * @description <描述>
 * @kind problem
 * @problem.severity warning
 * @id {language}/<漏洞类型小写连字符>
 * @tags security
 */
import {language}

from <表达式类型> expr
where <匹配条件>
select expr, "问题描述"
```

**C. 本地数据流查询（无需远程 Source，仅追踪本地数据流）**
适用于：整数溢出、格式化字符串、缓冲区溢出（C/C++）
→ 使用 DataFlow::localFlow() 或局部步骤

任务：
1. 根据漏洞类型选择最合适的查询范式（A/B/C）。
2. 如果是范式 A，复用黄金模板的结构，只替换 <占位符>。
3. 如果是范式 B/C，生成对应的 @kind problem 或本地数据流查询。
4. @id 使用 {language}/<漏洞类型小写连字符> 格式。
5. 直接输出完整 .ql 代码，不要加任何 markdown 包装或解释文字。
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
    "solidity":   "codeql/solidity-all",
}

# ---------------------------------------------------------------------------
# 默认 Sink 提示（可被调用方覆盖）
# ---------------------------------------------------------------------------

_DEFAULT_SINK_HINTS: dict[str, str] = {
    "java": (
        "org.springframework.expression.ExpressionParser.parseExpression, "
        "ognl.Ognl.getValue, "
        "org.mvel2.MVEL.eval, "
        "java.lang.Runtime.exec, java.sql.Statement.executeQuery, "
        "java.io.ObjectInputStream.readObject"
    ),
    "python": (
        "jinja2.Environment.from_string, "
        "jinja2.Template, "
        "mako.template.Template, "
        "os.system, subprocess.run, cursor.execute, "
        "pickle.loads, eval, exec"
    ),
    "javascript": (
        "child_process.exec, child_process.spawn, eval, "
        "fs.readFile, fs.readFileSync, sequelize.query, "
        "res.send, res.write, innerHTML, "
        "axios.get, fetch, http.request"
    ),
    "go": (
        "os/exec.Command, database/sql.DB.Query, database/sql.DB.Exec, "
        "net/http.Get, net/http.Client.Do, "
        "os.Open, os.ReadFile, filepath.Join, "
        "encoding/xml.Decoder.Decode, fmt.Fprintf"
    ),
    "cpp": (
        "system, popen, execl, execvp, "
        "strcpy, strcat, sprintf, gets, memcpy, memmove, "
        "malloc, calloc, realloc, free, "
        "printf, fprintf, fopen, open, "
        "scanf, sscanf"
    ),
    "csharp": (
        "System.Diagnostics.Process.Start, "
        "System.Data.SqlClient.SqlCommand.ExecuteReader, "
        "System.IO.File.ReadAllText, System.IO.File.Open, "
        "System.Net.Http.HttpClient.GetAsync, "
        "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize"
    ),
    "kernel": (
        "copy_from_user, __copy_from_user, get_user, __get_user, "
        "kmalloc, kzalloc, kcalloc, vmalloc, vzalloc, kmalloc_array, "
        "kfree, vfree, kvfree, kfree_rcu, "
        "memcpy, __memcpy, memmove, memset, "
        "spin_lock, spin_unlock, mutex_lock, mutex_unlock, "
        "rcu_read_lock, rcu_read_unlock, rcu_dereference, "
        "capable, ns_capable"
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

class AgentQ(BaseAgent):
    """
    CodeQL 规则自动合成 Agent，内置自修复循环。

    Attributes:
        llm: LangChain LLM 实例（默认为 ChatOpenAI）。
        runner: CodeQLRunner 实例，用于调用本地 codeql CLI。
        output_dir: 生成的 .ql 文件的存放目录。
        max_retries: 自修复循环的最大重试次数。
    """

    agent_name = "Agent-Q"

    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        runner: Optional[CodeQLRunner] = None,
        output_dir: str = "data/queries",
        max_retries: int = MAX_RETRIES,
    ) -> None:
        super().__init__(llm=llm, temperature=0.2)
        self.runner: CodeQLRunner = runner or CodeQLRunner()
        self.output_dir: Path = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_retries: int = max_retries

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
        prompt_preset: str = "",
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
        # 优先使用用户指定的 sink_hints，其次从通用漏洞目录查询，最后用语言默认值
        # prompt_preset 为 "kernel" 时优先使用内核 sink hints
        _effective_lang = prompt_preset if prompt_preset and prompt_preset in _DEFAULT_SINK_HINTS else language.lower()
        _sink_hints = (
            sink_hints
            or vuln_catalog.get_sink_hints(vuln_type, language)
            or _DEFAULT_SINK_HINTS.get(_effective_lang, "（未指定，请根据目标框架推断）")
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
            # 使用与语言匹配的系统提示（prompt_preset 优先）
            sys_prompt = _get_system_prompt(language, prompt_preset=prompt_preset)
            raw_output = self._invoke_llm(sys_prompt, human_prompt)
            current_code = _extract_ql_code(raw_output)

        query_file = self._write_query_to_file(current_code, _filename, language)
        logger.info("初始 .ql 代码已就绪，开始编译验证...")

        # ── 第 2 步：自修复循环 ──────────────────────────────────────────
        sys_prompt = _get_system_prompt(language, prompt_preset=prompt_preset)
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
