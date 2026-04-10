"""
Agent-R：语义审查与误报过滤。

工作流：
1. 解析 SARIF 文件，提取每条发现的文件路径、行号与消息。
2. 读取对应源文件的代码上下文（发现行前后各 N 行）。
3. 将「数据流描述 + 源码片段」发送给 LLM，判断是否为真实漏洞。
4. 返回带置信度与推理说明的 ReviewResult 列表。

通用审查维度：
- 数据是否真正来自用户可控输入（HTTP 参数、Header、Cookie、Body）？
- 到达 Sink 之前是否经过了有效的净化、参数化或白名单校验？
- 漏洞是否处于可达的代码路径（非测试代码、非废弃接口）？
- 实际利用复杂度（前置条件、认证要求、利用稳定性）？
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from src.agents.base_agent import BaseAgent, llm_retry

logger = logging.getLogger(__name__)


def _flush_logs() -> None:
    """强制刷新所有 logging handler 及 stdout/stderr。"""
    for h in logging.root.handlers:
        try:
            h.flush()
        except Exception:  # noqa: BLE001
            pass
    try:
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass
    try:
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass

# 源码上下文窗口：发现行前后各取 N 行
_CONTEXT_LINES: int = 30

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


class VulnStatus(str, Enum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    UNCERTAIN = "uncertain"


@dataclass
class SarifFinding:
    """从 SARIF 文件解析出的单条发现。"""

    rule_id: str
    message: str
    file_uri: str           # 相对于仓库根目录的文件路径
    start_line: int
    code_context: str = ""  # 填充后的源码上下文片段
    additional_locations: list = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.additional_locations is None:
            self.additional_locations = []


@dataclass
class ReviewResult:
    """Agent-R 对单条发现的研判输出。"""

    finding: SarifFinding
    status: VulnStatus
    confidence: float       # [0.0, 1.0]
    engine_detected: str    # 识别出的 EL 引擎，如 "Spring EL"
    reasoning: str          # LLM 的推理说明
    sink_method: str = ""   # 触发告警的 Sink 方法


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_R_JAVA = """\
你是一位资深 Java 安全研究员，同时擅长识别**真实漏洞**和**静态分析误报**。
你的核心任务不是"尽可能多地发现漏洞"，而是**精准判断每条发现是 TP 还是 FP**。

你将收到一段 CodeQL 静态扫描发现，以及对应的 Java 源码上下文。
请仔细分析代码，判断这个发现是真实的安全问题（vulnerable），还是误报（safe）。

## 审查原则

**最重要的原则：追踪数据流。** 不要仅看 Sink 处的代码模式，必须回溯变量的实际值：
- 变量在到达 Sink 之前，是否被重新赋值为硬编码常量？
- 条件分支是否使得污染数据不可达 Sink？
- 集合/数组操作是否选取了安全的元素？

## 常见误报（FP）模式 — 遇到以下模式应判 safe：

**F1. 硬编码常量覆盖：** 变量虽来自用户输入，但在到达 Sink 前被赋值为硬编码常量。
  例：`bar = doSomething(param)` 而 `doSomething()` 内部直接 `return "safe!"`

**F2. 不可达的污染分支：** if/switch 条件使污染数据的分支永远不会执行。
  例：`int num=86; if ((7*42)-num > 200) bar="safe"; else bar=param;`
  → (7×42)-86=208>200 恒为true，bar 永远是 "safe"，用户输入 param 永远不会到达 Sink。
  **你必须实际计算数学表达式来验证条件。**

**F3. 集合操作选取安全元素：** List/Array 中虽添加了用户输入，但实际使用的是安全元素。
  例：`list.add("safe"); list.add(param); list.add("moresafe"); list.remove(0); bar=list.get(1);`
  → remove(0) 后列表为 [param, "moresafe"]，get(1) 取的是 "moresafe"，非用户输入。
  **你必须逐步模拟集合操作来确定最终取出的值。**

**F4. 类型转换天然净化：** 用户输入经过 Integer.parseInt()、Long.parseLong()、Double.parseDouble() 等类型转换后，注入攻击不可能成功。

**F5. 安全 API 替代：** 使用了安全 API 如 PreparedStatement (SQL)、exec(String[]) (命令)、Encoder.encode() (XSS) 等。

**F6. 内部方法返回常量：** 调用链中某个方法无论接收什么参数，都返回固定的安全值（如 "safe!"、"alsosafe" 等硬编码字符串）。如果上下文中提供了该方法的定义，请检查其返回值。

## 真实漏洞（TP）确认 — 以下模式应判 vulnerable：

**T1. 直接拼接：** 用户输入直接拼接到命令/SQL/路径/URL字符串中，无任何净化。
**T2. 无效净化：** 虽有过滤但不充分（如仅 URL decode、Base64 编解码、trim 不算净化）。
**T3. 条件分支均污染：** 所有可达的分支都包含用户输入流向 Sink 的路径。

## 审查步骤（必须逐步执行）：

1. 识别 Source：找到用户输入的来源（request.getParameter/getHeader/getCookies 等）
2. 追踪 Transform：变量经历了哪些赋值、方法调用、条件分支？
3. 判断到达 Sink 的实际值：**不是变量名，而是变量的实际内容**是否可控？
4. 检查 FP 模式 F1~F6：是否命中任何已知的误报模式？
5. 综合判定：给出最终结论

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 Command Injection / SQL Injection / Spring EL / MD5 / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据，特别是数据流分析过程）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_PYTHON = """\
你是一位资深 Python 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、模板注入SSTI、路径穿越、反序列化、开放重定向等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 Python 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（Flask request.args/form/json、Django request.GET/POST 等）？
2. **净化器**：是否经过了参数化查询、shlex.quote()、os.path.realpath() 校验、escape() 或白名单过滤？
3. **漏洞类型专属**：
   - SQL注入：是否使用了参数绑定（%s占位符 + 元组参数）而非字符串拼接？
   - 命令注入：是否使用了 subprocess 的列表形式（非 shell=True 的字符串）？
   - SSTI：用户输入是用作模板字符串还是仅作为渲染变量（变量安全，字符串危险）？
   - 路径穿越：是否调用了 os.path.realpath() + 路径前缀校验？
   - 反序列化：pickle.loads 的数据是否来自可信源？
4. **可达性**：代码是否处于可触达的请求处理路径中？
5. **框架特性**：Django ORM / SQLAlchemy 的 ORM 查询通常安全，raw()/execute() 需关注。

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 Jinja2 / SQLite3 / subprocess / pickle / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_JAVASCRIPT = """\
你是一位资深 JavaScript/TypeScript 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、XSS、路径穿越、SSRF、原型链污染、不安全反序列化等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 JavaScript/TypeScript 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（Express req.query/body/params、Koa ctx.request 等）？
2. **净化器**：是否经过了参数化查询、validator/sanitize-html 库、path.resolve() + 前缀校验？
3. **漏洞类型专属**：
   - SQL注入：是否使用了参数化（mysql2 ? 占位符、knex 绑定、Sequelize ORM）？
   - 命令注入：是否使用了 execFile（数组参数）而非 exec（字符串拼接）？
   - XSS：输出是否经过 DOMPurify / escape-html / 模板引擎自动转义？
   - 路径穿越：是否调用了 path.resolve() + startsWith() 前缀校验？
   - SSRF：URL 是否经过白名单过滤？
   - 原型链污染：merge/extend 是否对 __proto__ / constructor 做了过滤？
4. **可达性**：代码路径是否可触达（非测试代码/中间件是否拦截）？
5. **框架特性**：Express / Koa / NestJS 中间件链是否引入了安全防护？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 child_process / mysql / express / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_GO = """\
你是一位资深 Go 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、路径穿越、SSRF、不安全反序列化等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 Go 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（http.Request FormValue/URL.Query/Body、gin c.Query 等）？
2. **净化器**：是否经过了参数化查询、filepath.Clean() + 前缀校验、html.EscapeString()？
3. **漏洞类型专属**：
   - SQL注入：是否使用了 database/sql 的 ? 占位符参数绑定？
   - 命令注入：是否使用了 exec.Command 的参数数组形式（非 bash -c 字符串）？
   - 路径穿越：是否调用了 filepath.Clean() + strings.HasPrefix() 校验？
   - SSRF：URL 是否经过白名单或 IP 过滤？
4. **可达性**：Handler 是否注册在路由中？中间件是否有鉴权拦截？
5. **Go 特性**：强类型转换是否天然阻止了注入（如 strconv.Atoi）？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或包名（如 database/sql / os/exec / net/http / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_CSHARP = """\
你是一位资深 C# 安全研究员，擅长审查各类漏洞（SQL注入、命令注入、路径穿越、SSRF、XSS、不安全反序列化等）。
你将收到一段 CodeQL 静态扫描发现，以及对应的 C# 源码上下文。
请判断这个发现是真实可利用的漏洞，还是误报（false positive）。

通用审查维度：
1. **数据来源**：用户输入是否真正可控（ASP.NET Request.Query/Form/Body、[FromQuery]/[FromBody] 参数）？
2. **净化器**：是否经过了参数化查询、Path.GetFullPath() + 前缀校验、HtmlEncoder.Encode()？
3. **漏洞类型专属**：
   - SQL注入：是否使用了 SqlParameter 参数化 / Entity Framework LINQ 查询？
   - 命令注入：ProcessStartInfo.Arguments 是否拼接了用户输入？
   - 路径穿越：是否调用了 Path.GetFullPath() + StartsWith() 校验？
   - SSRF：HttpClient URL 是否经过白名单过滤？
   - 反序列化：BinaryFormatter / JavaScriptSerializer 是否接受了不可信输入？
4. **可达性**：Controller Action 是否可从外部触达？[Authorize] 属性影响？
5. **框架特性**：ASP.NET Core 模型绑定 / Anti-Forgery Token / CORS 策略是否减轻风险？

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型或框架名（如 SqlCommand / Process / HttpClient / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPT_R_CPP = """\
你是一位资深 C/C++ 安全研究员，擅长审查各类安全问题，包括但不限于：
- 注入类：命令注入、格式化字符串、路径穿越
- 内存安全：缓冲区溢出、Use-After-Free、Double-Free、整数溢出、空指针解引用
- 资源管理：内存泄露、文件句柄泄露
- 并发安全：竞态条件、死锁

你将收到一段 CodeQL 静态扫描发现，以及对应的 C/C++ 源码上下文。
请判断这个发现是真实的安全问题，还是误报（false positive）。

审查维度（根据漏洞类别灵活选择）：

**A. 注入/格式化字符串：**
1. 数据来源：用户输入是否真正可控（argv、getenv、fgets/scanf/read、网络 recv）？
2. 净化器：是否经过长度校验、白名单过滤、路径规范化？
3. 命令注入：system()/popen() 是否拼接了外部输入？格式化字符串：printf 是否直接使用了外部输入？

**B. 内存安全：**
1. 缓冲区溢出：目标缓冲区大小是否足够？是否使用了 strncpy/snprintf 等安全版本？
2. UAF/Double-Free：内存释放后是否有后续使用？指针释放后是否置 NULL？
3. 整数溢出：算术运算结果是否用于内存分配（malloc）或数组索引？是否有范围检查？
4. 不安全 API：是否使用了 strcpy/strcat/sprintf/gets 等无边界检查函数？

**C. 资源/并发：**
1. 分配的内存/打开的文件是否在所有路径上正确释放/关闭？
2. 共享数据是否有适当的锁保护？

**D. 通用维度：**
1. 可达性：该代码路径是否在实际运行中可触达？
2. 编译器防护：ASLR/Stack Canary/FORTIFY_SOURCE 可以缓解但不消除漏洞。

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型（如 strcpy / malloc / printf / free / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，说明判断依据）",
  "sink_method": "被调用的危险函数全名"
}
"""

_SYSTEM_PROMPT_R_KERNEL = """\
你是一位资深 Linux 内核安全研究员，专精内核漏洞分析（CVE 级别）。
你熟悉内核开发规范、内存管理子系统、锁机制、引用计数以及用户态-内核态数据传递。

你将收到一段 CodeQL 静态扫描发现，以及对应的内核 C 源码上下文。
请判断这个发现是真实的安全问题，还是误报（false positive）。

## 内核特有审查维度

**A. 用户态输入校验（__user 指针）：**
1. `copy_from_user` / `get_user` / `__get_user` 的返回值是否检查？
2. 用户传入的长度/偏移量是否做了上界校验？
3. `access_ok()` 是否在拷贝前调用？

**B. 内存安全：**
1. `kmalloc` / `kzalloc` / `vmalloc` 返回值是否判空？
2. `kfree` 后指针是否置 NULL？是否存在 double-free？
3. Use-After-Free：对象释放后是否仍被引用？特别关注 RCU 保护对象和引用计数。
4. 缓冲区溢出：`memcpy` / `copy_from_user` 的长度参数是否受控？是否依赖用户输入？
5. 整数溢出：乘法/加法结果用于 `kmalloc` 大小时是否有溢出检查（`check_mul_overflow` / `array_size`）？

**C. 竞态条件：**
1. 共享数据结构是否在正确的锁保护下访问（spin_lock / mutex / rcu_read_lock）？
2. TOCTOU：检查和使用之间是否可能被其他线程修改？
3. `atomic_t` / `refcount_t` 操作是否正确？

**D. 权限提升：**
1. `capable()` / `ns_capable()` 检查是否充分？
2. 特权操作是否仅限 root 或具备特定 capability 的进程？
3. `ioctl` handler 是否对 cmd 做了范围校验？

**E. 信息泄露：**
1. `copy_to_user` 的源缓冲区是否已初始化（避免栈/堆未初始化内存泄露到用户态）？
2. `struct` padding 是否清零（memset 或 kzalloc）？

## 常见内核 FP 模式（遇到以下模式应判 safe）：
1. **kmalloc 检查已有**：代码在 kmalloc 后立即 `if (!ptr)` 返回 -ENOMEM
2. **copy_from_user 已校验**：返回值被 `if (copy_from_user(...))` 包围
3. **锁已持有**：函数注释或调用者明确持有相关锁（`must hold xxx_lock`）
4. **BUILD_BUG_ON / static_assert**：编译期保证的约束
5. **kref / refcount 保护**：引用计数正确管理的对象生命周期
6. **内部 helper 函数**：仅被内核内部调用、输入已在上层校验

## 审查步骤：
1. 识别 Source（用户可控数据来源：ioctl 参数、copy_from_user、sysfs/procfs write）
2. 追踪数据流（赋值、类型转换、边界检查、锁状态）
3. 判断到达 Sink 时数据是否仍然用户可控且危险
4. 检查内核防护机制（KASLR/SMAP/SMEP 缓解但不消除）
5. 给出结论

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞类型（如 UAF / OOB / Race Condition / Null Deref / Info Leak / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，特别强调内核安全模型分析）",
  "sink_method": "被调用的危险函数或宏（如 kmalloc / memcpy / copy_from_user / kfree）"
}
"""

_SYSTEM_PROMPT_R_GENERIC = """\
你是一位资深安全研究员，同时擅长识别**真实漏洞**和**静态分析误报**。
你的核心任务是**精准判断每条发现是 TP 还是 FP**，而不是尽可能多地报告漏洞。

你将收到一段 CodeQL 静态扫描发现，以及对应的源码上下文。
请仔细分析代码的数据流，判断这个发现是真实的安全问题（vulnerable），还是误报（safe）。

## 审查原则

**最重要的原则：追踪数据流。** 不要仅看 Sink 处的代码模式，必须回溯变量的实际值：
- 变量在到达 Sink 之前，是否被重新赋值为硬编码常量？
- 条件分支是否使得污染数据不可达 Sink？
- 集合/数组操作是否选取了安全的元素？

## 常见误报（FP）模式 — 遇到以下模式应判 safe：
1. **硬编码覆盖**：变量虽源自用户输入，但后续被赋值为常量
2. **不可达分支**：条件恒真/恒假使得污染路径不可达（需计算验证）
3. **安全元素选取**：集合操作最终取出的是非用户控制的元素
4. **类型转换净化**：parseInt/parseLong 等使注入不可能
5. **安全 API**：参数化查询、编码输出等
6. **非安全场景**：弱哈希用于缓存键而非密码、随机数用于非安全用途

## 审查步骤：
1. 识别 Source（用户输入来源）
2. 追踪 Transform（赋值、调用、分支）
3. 判断到达 Sink 的实际值是否用户可控
4. 检查是否命中 FP 模式
5. 给出结论

你的回复必须是合法的 JSON，格式如下：
{
  "status": "vulnerable" | "safe" | "uncertain",
  "confidence": 0.0 ~ 1.0,
  "engine_detected": "漏洞/问题类型（如 SQL Injection / MD5 / Buffer Overflow / Unknown）",
  "reasoning": "简洁的中文推理说明（2-5句话，特别是数据流分析过程）",
  "sink_method": "被调用的危险方法全名"
}
"""

_SYSTEM_PROMPTS_R: dict[str, str] = {
    "java":       _SYSTEM_PROMPT_R_JAVA,
    "python":     _SYSTEM_PROMPT_R_PYTHON,
    "javascript": _SYSTEM_PROMPT_R_JAVASCRIPT,
    "go":         _SYSTEM_PROMPT_R_GO,
    "csharp":     _SYSTEM_PROMPT_R_CSHARP,
    "cpp":        _SYSTEM_PROMPT_R_CPP,
    "kernel":     _SYSTEM_PROMPT_R_KERNEL,
    "generic":    _SYSTEM_PROMPT_R_GENERIC,
}

# 兼容旧引用
_SYSTEM_PROMPT_R = _SYSTEM_PROMPT_R_JAVA


def _get_review_system_prompt(language: str, prompt_preset: str = "") -> str:
    """按语言或 prompt_preset 返回对应的审查系统提示。

    prompt_preset 优先于 language（由 Agent-T 的 CodebaseProfile 指定）。
    """
    if prompt_preset:
        hit = _SYSTEM_PROMPTS_R.get(prompt_preset.lower())
        if hit:
            return hit
    return _SYSTEM_PROMPTS_R.get(language.lower(), _SYSTEM_PROMPT_R_GENERIC)


def _get_code_block_lang(language: str) -> str:
    """返回 markdown 代码块对应的语言标签。"""
    return {
        "java": "java", "python": "python", "javascript": "js",
        "go": "go", "csharp": "csharp", "cpp": "cpp",
    }.get(language.lower(), "")


_REVIEW_TEMPLATE = """\
【CodeQL 发现】
- 规则 ID : {rule_id}
- 文件    : {file_uri}
- 行号    : {start_line}
- 消息    : {message}

【源码上下文（第 {start_line} 行附近）】
```{code_lang}
{code_context}
```

请按要求输出 JSON 格式的研判结论。
"""

# ---------------------------------------------------------------------------
# 批量审查 Prompt
# ---------------------------------------------------------------------------

_BATCH_REVIEW_TEMPLATE = """\
你需要一次性审查以下 {count} 条 CodeQL 发现，对每条分别给出独立的研判结论。

{findings_block}

请返回一个 JSON **数组**，包含 {count} 个对象，每个对象的格式与单条审查相同：
```json
[
  {{
    "id": 1,
    "status": "vulnerable" | "safe" | "uncertain",
    "confidence": 0.0 ~ 1.0,
    "engine_detected": "漏洞类型",
    "reasoning": "简洁的中文推理说明（2-5句话）",
    "sink_method": "危险方法全名"
  }},
  ...
]
```
注意：数组中对象的 id 必须与上面发现编号一一对应，不要遗漏任何一条。
"""

_BATCH_FINDING_TEMPLATE = """\
--- 发现 #{idx} ---
- 规则 ID : {rule_id}
- 文件    : {file_uri}
- 行号    : {start_line}
- 消息    : {message}

```{code_lang}
{code_context}
```
"""


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _parse_sarif(sarif_path: str) -> list[SarifFinding]:
    """
    解析 SARIF 文件，提取每条发现的关键信息。

    Args:
        sarif_path: SARIF 文件路径。

    Returns:
        SarifFinding 列表。
    """
    path = Path(sarif_path)
    if not path.exists():
        raise FileNotFoundError(f"SARIF 文件不存在: {sarif_path}")

    with path.open(encoding="utf-8") as f:
        sarif: dict[str, Any] = json.load(f)

    findings: list[SarifFinding] = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")

            locs = result.get("locations", [])
            if not locs:
                continue
            pl = locs[0].get("physicalLocation", {})
            uri = pl.get("artifactLocation", {}).get("uri", "")
            line = pl.get("region", {}).get("startLine", 0)

            extra_locs: list[dict[str, Any]] = []
            for loc in locs[1:]:
                epl = loc.get("physicalLocation", {})
                extra_locs.append({
                    "uri": epl.get("artifactLocation", {}).get("uri", ""),
                    "startLine": epl.get("region", {}).get("startLine", 0),
                })
            for rl in result.get("relatedLocations", []):
                rpl = rl.get("physicalLocation", {})
                extra_locs.append({
                    "uri": rpl.get("artifactLocation", {}).get("uri", ""),
                    "startLine": rpl.get("region", {}).get("startLine", 0),
                    "message": rl.get("message", {}).get("text", ""),
                })

            findings.append(SarifFinding(
                rule_id=rule_id,
                message=message,
                file_uri=uri,
                start_line=line,
                additional_locations=extra_locs,
            ))

    logger.info("SARIF 解析完成，共 %d 条发现。", len(findings))
    return findings


_SINK_METHOD_RE = re.compile(r"`([a-zA-Z_][\w.]*(?:\([^)]*\))?)`")


def _extract_sink_method(message: str) -> str:
    """从 SARIF message 中提取结构化的 sink 方法名。

    优先匹配反引号中的方法签名（如 ``parseExpression(...)``），
    匹配失败时回退到截取前 80 字符。
    """
    if not message:
        return ""
    matches = _SINK_METHOD_RE.findall(message)
    if matches:
        return matches[-1]
    return message[:80]


def _load_code_context(
    repo_root: str,
    file_uri: str,
    center_line: int,
    window: int = _CONTEXT_LINES,
) -> str:
    """
    从仓库本地路径读取发现行附近的源码片段。

    Args:
        repo_root: 仓库根目录的本地路径。
        file_uri: SARIF 中的相对文件路径。
        center_line: 发现所在行号（1-indexed）。
        window: 前后各取的行数。

    Returns:
        带行号前缀的源码上下文字符串。
    """
    # SARIF uri 可能含 file:// 前缀
    clean_uri = file_uri.removeprefix("file://").lstrip("/")
    file_path = Path(repo_root) / clean_uri

    if not file_path.exists():
        return f"（无法读取源文件: {file_path}）"

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"（读取源文件失败: {exc}）"

    start = max(0, center_line - window - 1)
    end = min(len(lines), center_line + window)
    snippet = lines[start:end]

    # 带行号前缀，方便 LLM 定位
    numbered = [
        f"{start + i + 1:4d} | {line}"
        for i, line in enumerate(snippet)
    ]
    return "\n".join(numbered)


def _parse_llm_json(raw: str) -> dict[str, Any]:
    """从 LLM 原始输出中提取 JSON 对象（委托给 BaseAgent.parse_json）。"""
    return BaseAgent.parse_json(raw)


def _parse_llm_json_array(raw: str, expected_count: int) -> list[dict[str, Any]]:
    """从 LLM 原始输出中提取 JSON 数组（委托给 BaseAgent.parse_json_array + id 对齐）。"""
    parsed = BaseAgent.parse_json_array(raw, expected_count=expected_count)

    if expected_count > 0 and all("id" in item for item in parsed):
        indexed: dict[int, dict] = {}
        for item in parsed:
            try:
                idx = int(item["id"])
                indexed[idx] = item
            except (ValueError, TypeError):
                pass
        if indexed:
            aligned: list[dict] = []
            for i in range(1, expected_count + 1):
                if i in indexed:
                    aligned.append(indexed[i])
                else:
                    aligned.append({
                        "id": i,
                        "verdict": "UNCERTAIN",
                        "confidence": 0.3,
                        "engine": "",
                        "reasoning": f"Finding #{i} 缺失 LLM 响应，默认标记为 UNCERTAIN",
                    })
            return aligned

    return parsed


# ---------------------------------------------------------------------------
# Agent-R 主类
# ---------------------------------------------------------------------------


class AgentR(BaseAgent):
    """
    漏洞语义审查 Agent。

    对 CodeQL 的每条发现执行 LLM 语义分析，过滤误报，
    输出带置信度评分的研判结论列表。

    v2.1 升级（受 K-REPRO arXiv:2602.07287 启发）：
      - 集成 CodeBrowser，使用符号级代码导航替代固定 ±15 行窗口
      - 自动追踪 Sink 方法定义和关键调用链
      - 在不超出 token 预算前提下提供最大信息量

    Args:
        llm: LangChain LLM 实例；默认使用环境变量中的 ChatOpenAI。
        context_lines: 源码上下文窗口大小（前后各取 N 行）。
        enable_code_browser: 是否启用 CodeBrowser 智能上下文（默认开启）。
    """

    agent_name = "Agent-R"

    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        context_lines: int = _CONTEXT_LINES,
        enable_code_browser: bool = True,
    ) -> None:
        _http_timeout = int(os.environ.get("AGENT_R_TIMEOUT", "120"))
        super().__init__(
            llm=llm,
            temperature=0.0,
            timeout=_http_timeout,
            max_tokens=int(os.environ.get("AGENT_R_MAX_TOKENS", "4096")),
            max_retries=2,
        )
        self.context_lines = context_lines
        self.enable_code_browser = enable_code_browser

    def _invoke_llm(
        self,
        finding: SarifFinding,
        language: str = "generic",
        prompt_preset: str = "",
    ) -> dict[str, Any]:
        """
        调用 LLM 对单条发现进行语义审查。

        Args:
            finding: 待审查的 SARIF 发现。
            language: 目标语言，用于选择对应的系统提示和代码块语法高亮。
            prompt_preset: Agent-T 指定的 prompt 预设（优先于 language）。
        """
        code_lang = _get_code_block_lang(language)
        human_msg = _REVIEW_TEMPLATE.format(
            rule_id=finding.rule_id,
            file_uri=finding.file_uri,
            start_line=finding.start_line,
            message=finding.message,
            code_context=finding.code_context or "（源码上下文不可用）",
            code_lang=code_lang,
        )
        sys_prompt = _get_review_system_prompt(language, prompt_preset=prompt_preset)
        _timeout_sec = int(os.environ.get("AGENT_R_TIMEOUT", "120"))
        raw = self.invoke_with_timeout(
            [SystemMessage(content=sys_prompt), HumanMessage(content=human_msg)],
            timeout_sec=_timeout_sec,
        )
        _flush_logs()
        return self.parse_json(raw)

    def _invoke_llm_batch(
        self,
        findings_with_context: list[SarifFinding],
        language: str = "generic",
        prompt_preset: str = "",
    ) -> list[dict[str, Any]]:
        """对一批 findings 执行单次 LLM 调用，返回审查结果数组。"""
        code_lang = _get_code_block_lang(language)
        blocks = []
        for i, f in enumerate(findings_with_context, 1):
            blocks.append(_BATCH_FINDING_TEMPLATE.format(
                idx=i,
                rule_id=f.rule_id,
                file_uri=f.file_uri,
                start_line=f.start_line,
                message=f.message,
                code_context=f.code_context or "(源码上下文不可用)",
                code_lang=code_lang,
            ))

        human_msg = _BATCH_REVIEW_TEMPLATE.format(
            count=len(findings_with_context),
            findings_block="\n".join(blocks),
        )
        sys_prompt = _get_review_system_prompt(language, prompt_preset=prompt_preset)
        _timeout_sec = int(os.environ.get("AGENT_R_TIMEOUT", "120"))
        raw = self.invoke_with_timeout(
            [SystemMessage(content=sys_prompt), HumanMessage(content=human_msg)],
            timeout_sec=_timeout_sec,
        )
        _flush_logs()
        return self.parse_json_array(raw, expected_count=len(findings_with_context))

    @llm_retry(max_retries=3, backoff_factor=5.0)
    def _invoke_llm_batch_with_retry(
        self,
        findings_with_context: list[SarifFinding],
        language: str = "generic",
        prompt_preset: str = "",
    ) -> list[dict[str, Any]]:
        """带重试的批量 LLM 调用（由 @llm_retry 装饰器控制重试策略）。"""
        return self._invoke_llm_batch(findings_with_context, language=language, prompt_preset=prompt_preset)

    def _review_batch(
        self,
        batch_findings: list[SarifFinding],
        batch_start_idx: int,
        total: int,
        repo_root: str,
        language: str,
        code_browser: Any,
        prompt_preset: str = "",
    ) -> list[ReviewResult]:
        """审查一批 findings（单次 LLM 调用），返回 ReviewResult 列表。"""
        batch_size = len(batch_findings)
        logger.info(
            "[Agent-R] 批量审查 %d~%d/%d（%d条/批）",
            batch_start_idx + 1,
            batch_start_idx + batch_size,
            total,
            batch_size,
        )
        _flush_logs()

        # 填充源码上下文
        for f in batch_findings:
            if code_browser:
                try:
                    f.code_context = code_browser.build_rich_context(
                        file_uri=f.file_uri,
                        center_line=f.start_line,
                        sink_method=_extract_sink_method(f.message),
                        base_window=self.context_lines,
                    )
                except Exception:
                    f.code_context = _load_code_context(
                        repo_root=repo_root,
                        file_uri=f.file_uri,
                        center_line=f.start_line,
                        window=self.context_lines,
                    )
            else:
                f.code_context = _load_code_context(
                    repo_root=repo_root,
                    file_uri=f.file_uri,
                    center_line=f.start_line,
                    window=self.context_lines,
                )

        # 批量 LLM 调用（含应用层重试，失败降级为逐条审查）
        verdicts = None
        try:
            verdicts = self._invoke_llm_batch_with_retry(
                batch_findings, language=language, prompt_preset=prompt_preset,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[Agent-R] 批量审查失败（重试用尽），降级为逐条审查: %s", exc,
            )

        if verdicts is None:
            logger.info(
                "[Agent-R] 降级模式: 逐条审查 %d 条 findings (批次 %d~%d)",
                batch_size, batch_start_idx + 1, batch_start_idx + batch_size,
            )
            _flush_logs()
            verdicts = []
            for _fi, _f in enumerate(batch_findings):
                try:
                    _single = self._invoke_llm(_f, language=language, prompt_preset=prompt_preset)
                    verdicts.append(_single)
                    logger.info(
                        "[Agent-R] 逐条 #%d %s (%.0f%%)",
                        batch_start_idx + _fi + 1,
                        _single.get("status", "uncertain").upper(),
                        _single.get("confidence", 0) * 100,
                    )
                except Exception as _single_exc:  # noqa: BLE001
                    logger.warning(
                        "[Agent-R] 逐条 #%d 也失败: %s",
                        batch_start_idx + _fi + 1, _single_exc,
                    )
                    verdicts.append({
                        "status": "uncertain",
                        "confidence": 0.0,
                        "engine_detected": "Unknown",
                        "reasoning": f"LLM 异常(逐条降级也失败): {_single_exc}",
                        "sink_method": "",
                    })
                _flush_logs()

        # 确保 verdicts 数量匹配
        while len(verdicts) < batch_size:
            verdicts.append({
                "status": "uncertain",
                "confidence": 0.0,
                "engine_detected": "Unknown",
                "reasoning": "LLM 未返回足够结果",
                "sink_method": "",
            })

        results = []
        for i, (finding, verdict) in enumerate(zip(batch_findings, verdicts)):
            status = VulnStatus(verdict.get("status", "uncertain"))
            result = ReviewResult(
                finding=finding,
                status=status,
                confidence=float(verdict.get("confidence", 0.0)),
                engine_detected=verdict.get("engine_detected", "Unknown"),
                reasoning=verdict.get("reasoning", ""),
                sink_method=verdict.get("sink_method", ""),
            )
            logger.info(
                "[Agent-R] #%d %s (%.0f%%) | %s",
                batch_start_idx + i + 1,
                status.value.upper(),
                result.confidence * 100,
                result.reasoning[:60],
            )
            results.append(result)

        return results

    def _review_one(
        self,
        finding: Any,
        idx: int,
        total: int,
        repo_root: str,
        language: str,
        code_browser: Any,
        prompt_preset: str = "",
    ) -> ReviewResult:
        """审查单条 finding（可在线程池中并发执行）。"""
        logger.info(
            "[Agent-R] 审查发现 %d/%d: %s:%d",
            idx, total, finding.file_uri, finding.start_line,
        )

        # 读取源码上下文（优先 CodeBrowser 智能导航，降级为固定窗口）
        if code_browser:
            try:
                finding.code_context = code_browser.build_rich_context(
                    file_uri=finding.file_uri,
                    center_line=finding.start_line,
                    sink_method=finding.message[:80] if finding.message else "",
                    base_window=self.context_lines,
                )
                logger.debug(
                    "[Agent-R] CodeBrowser 上下文: %d 字符（含调用链追踪）",
                    len(finding.code_context),
                )
            except Exception:
                finding.code_context = _load_code_context(
                    repo_root=repo_root,
                    file_uri=finding.file_uri,
                    center_line=finding.start_line,
                    window=self.context_lines,
                )
        else:
            finding.code_context = _load_code_context(
                repo_root=repo_root,
                file_uri=finding.file_uri,
                center_line=finding.start_line,
                window=self.context_lines,
            )

        # LLM 语义审查
        try:
            verdict = self._invoke_llm(finding, language=language, prompt_preset=prompt_preset)
        except (ValueError, Exception) as exc:  # noqa: BLE001
            logger.warning(
                "[Agent-R] 发现 %d 审查失败（LLM 异常），标记为 UNCERTAIN: %s", idx, exc
            )
            verdict = {
                "status": "uncertain",
                "confidence": 0.0,
                "engine_detected": "Unknown",
                "reasoning": f"LLM 审查异常: {exc}",
                "sink_method": "",
            }

        status = VulnStatus(verdict.get("status", "uncertain"))
        result = ReviewResult(
            finding=finding,
            status=status,
            confidence=float(verdict.get("confidence", 0.0)),
            engine_detected=verdict.get("engine_detected", "Unknown"),
            reasoning=verdict.get("reasoning", ""),
            sink_method=verdict.get("sink_method", ""),
        )

        logger.info(
            "[Agent-R] 结论: %s (置信度: %.0f%%) | %s",
            status.value.upper(),
            result.confidence * 100,
            result.reasoning[:80],
        )
        return result

    def review(
        self,
        sarif_path: str,
        repo_root: str,
        language: str = "generic",
        parallel_workers: int = 1,
        batch_size: int = 1,
        checkpoint_done: dict | None = None,
        checkpoint_callback: Any = None,
        prompt_preset: str = "",
    ) -> list[ReviewResult]:
        """
        审查 CodeQL SARIF 扫描结果，返回带研判结论的列表。

        Args:
            sarif_path: SARIF 文件路径。
            repo_root: 仓库本地根目录（用于读取源码上下文）。
            language: 编程语言。
            parallel_workers: 批次级并发线程数（默认 1 串行）。
            batch_size: 每次 LLM 调用包含的 finding 数。
            checkpoint_done: 已完成的 finding key→verdict 映射（断点续跑）。
            checkpoint_callback: 每批完成后的回调 fn(batch_results)。
            prompt_preset: Agent-T 指定的 prompt 预设（如 "kernel"），优先于 language。

        Returns:
            ReviewResult 列表，顺序与 SARIF findings 一致。
        """
        findings = _parse_sarif(sarif_path)
        if not findings:
            logger.info("SARIF 中无发现，Agent-R 跳过审查。")
            return []

        total = len(findings)
        done = checkpoint_done or {}

        # 初始化 CodeBrowser（共享只读实例）
        code_browser = None
        if self.enable_code_browser:
            try:
                from src.utils.code_browser import CodeBrowser
                code_browser = CodeBrowser(repo_root=repo_root, language=language)
                logger.info("[Agent-R] CodeBrowser 已启用，使用智能上下文导航")
            except Exception as exc:
                logger.debug("[Agent-R] CodeBrowser 初始化失败，降级为固定窗口: %s", exc)

        # ---- 批量模式（batch_size > 1） ----
        if batch_size > 1:
            batches = [
                findings[i:i + batch_size]
                for i in range(0, total, batch_size)
            ]
            n_batches = len(batches)
            logger.info(
                "[Agent-R] 批量模式: %d 条 findings / %d 批 / 每批 %d 条 / %d 并发",
                total, n_batches, batch_size, parallel_workers,
            )

            all_results: list[ReviewResult] = []

            if parallel_workers <= 1:
                for bi, batch in enumerate(batches):
                    # 断点续跑：跳过已完成的整批
                    batch_keys = [f"{f.file_uri}:{f.start_line}" for f in batch]
                    if all(k in done for k in batch_keys):
                        restored = []
                        for f, k in zip(batch, batch_keys):
                            v = done[k]
                            restored.append(ReviewResult(
                                finding=f,
                                status=VulnStatus(v["status"]),
                                confidence=float(v.get("confidence", 0)),
                                engine_detected=v.get("engine_detected", ""),
                                reasoning=v.get("reasoning", "(restored)"),
                                sink_method=v.get("sink_method", ""),
                            ))
                        all_results.extend(restored)
                        continue

                    batch_results = self._review_batch(
                        batch, bi * batch_size, total,
                        repo_root, language, code_browser,
                        prompt_preset=prompt_preset,
                    )
                    all_results.extend(batch_results)
                    if checkpoint_callback:
                        try:
                            checkpoint_callback(batch_results)
                        except Exception:  # noqa: BLE001
                            pass
            else:
                logger.info("[Agent-R] 启用批次级并行（workers=%d）", parallel_workers)
                ordered_results: list[list[ReviewResult]] = [[] for _ in batches]

                # 断点续跑：先恢复已完成的批次
                pending_indices: list[int] = []
                for bi, batch in enumerate(batches):
                    batch_keys = [f"{f.file_uri}:{f.start_line}" for f in batch]
                    if all(k in done for k in batch_keys):
                        restored = []
                        for f, k in zip(batch, batch_keys):
                            v = done[k]
                            restored.append(ReviewResult(
                                finding=f,
                                status=VulnStatus(v["status"]),
                                confidence=float(v.get("confidence", 0)),
                                engine_detected=v.get("engine_detected", ""),
                                reasoning=v.get("reasoning", "(restored)"),
                                sink_method=v.get("sink_method", ""),
                            ))
                        ordered_results[bi] = restored
                    else:
                        pending_indices.append(bi)

                if len(pending_indices) < len(batches):
                    logger.info(
                        "[Agent-R] 断点恢复: %d 批已跳过, %d 批待处理",
                        len(batches) - len(pending_indices), len(pending_indices),
                    )

                import threading as _cb_lock_mod
                _cb_lock = _cb_lock_mod.Lock()

                def _safe_callback(br: list) -> None:
                    if checkpoint_callback:
                        with _cb_lock:
                            try:
                                checkpoint_callback(br)
                            except Exception:  # noqa: BLE001
                                pass

                def _run_batch(bi: int) -> list[ReviewResult]:
                    br = self._review_batch(
                        batches[bi], bi * batch_size, total,
                        repo_root, language, code_browser,
                        prompt_preset=prompt_preset,
                    )
                    _safe_callback(br)
                    return br

                with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
                    future_to_bi = {
                        executor.submit(_run_batch, bi): bi
                        for bi in pending_indices
                    }
                    for future in as_completed(future_to_bi):
                        bi = future_to_bi[future]
                        try:
                            ordered_results[bi] = future.result()
                        except Exception as exc:  # noqa: BLE001
                            logger.error("[Agent-R] 批次 %d 异常: %s", bi + 1, exc)
                            ordered_results[bi] = [
                                ReviewResult(
                                    finding=f,
                                    status=VulnStatus.UNCERTAIN,
                                    confidence=0.0,
                                    engine_detected="Unknown",
                                    reasoning=f"批次异常: {exc}",
                                    sink_method="",
                                )
                                for f in batches[bi]
                            ]
                for batch_results in ordered_results:
                    all_results.extend(batch_results)

            vulnerable = sum(1 for r in all_results if r.status == VulnStatus.VULNERABLE)
            logger.info(
                "[Agent-R] 审查完成 | 共 %d 条 | 真实漏洞: %d | 安全/不确定: %d",
                total, vulnerable, total - vulnerable,
            )
            return all_results

        # ---- 逐条模式（batch_size == 1，保持原有行为） ----
        logger.info(
            "SARIF 中共发现 %d 条待审查结果（逐条模式，并发线程: %d）",
            total, parallel_workers,
        )

        results: list[ReviewResult] = [None] * total  # type: ignore[list-item]

        if parallel_workers <= 1:
            for idx, finding in enumerate(findings, 1):
                results[idx - 1] = self._review_one(
                    finding, idx, total, repo_root, language, code_browser,
                    prompt_preset=prompt_preset,
                )
        else:
            logger.info("[Agent-R] 启用 finding 级并行（workers=%d）", parallel_workers)
            with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
                future_to_idx = {
                    executor.submit(
                        self._review_one,
                        finding, idx, total, repo_root, language, code_browser,
                        prompt_preset,
                    ): idx - 1
                    for idx, finding in enumerate(findings, 1)
                }
                for future in as_completed(future_to_idx):
                    pos = future_to_idx[future]
                    try:
                        results[pos] = future.result()
                    except Exception as exc:  # noqa: BLE001
                        logger.error("[Agent-R] finding %d 线程异常: %s", pos + 1, exc)
                        results[pos] = ReviewResult(
                            finding=findings[pos],
                            status=VulnStatus.UNCERTAIN,
                            confidence=0.0,
                            engine_detected="Unknown",
                            reasoning=f"线程异常: {exc}",
                            sink_method="",
                        )

        vulnerable = sum(1 for r in results if r and r.status == VulnStatus.VULNERABLE)
        logger.info(
            "[Agent-R] 审查完成 | 共 %d 条 | 真实漏洞: %d | 安全/不确定: %d",
            total, vulnerable, total - vulnerable,
        )
        return [r for r in results if r is not None]
