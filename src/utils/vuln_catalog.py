"""
通用漏洞目录（Vulnerability Catalog）。

为每种漏洞类型提供：
- CWE 编号与描述
- 漏洞分类（注入 / 认证 / 配置 / 数据验证）
- 默认 Sink 方法提示（供 Agent-Q 生成 CodeQL 查询时使用）
- 关键字列表（用于模糊匹配用户输入的漏洞类型名称）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VulnEntry:
    """单条漏洞类型描述。"""

    name: str                       # 标准名称，如 "SQL Injection"
    cwe: str                        # CWE 编号，如 "CWE-089"
    cwe_desc: str                   # CWE 简述
    category: str                   # 分类：injection / auth / config / validation / crypto
    keywords: tuple[str, ...]       # 用于模糊匹配的关键字（小写）
    java_sinks: tuple[str, ...]     # Java Sink 方法提示
    python_sinks: tuple[str, ...]   # Python Sink 方法提示
    javascript_sinks: tuple[str, ...] = field(default_factory=tuple)
    go_sinks: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""           # 漏洞危害描述


# ---------------------------------------------------------------------------
# 漏洞目录
# ---------------------------------------------------------------------------

VULN_CATALOG: list[VulnEntry] = [

    # ── 表达式注入（原有，保留） ─────────────────────────────────────────
    VulnEntry(
        name="Spring EL Injection",
        cwe="CWE-094",
        cwe_desc="Improper Control of Generation of Code ('Code Injection')",
        category="injection",
        keywords=("spel", "spring el", "spring expression", "expressionparser"),
        java_sinks=(
            "org.springframework.expression.ExpressionParser#parseExpression",
            "org.springframework.expression.Expression#getValue",
        ),
        python_sinks=(),
        description="用户可控数据进入 Spring EL 解析器，导致任意代码执行。",
    ),
    VulnEntry(
        name="OGNL Injection",
        cwe="CWE-094",
        cwe_desc="Improper Control of Generation of Code ('Code Injection')",
        category="injection",
        keywords=("ognl", "ognl injection", "object graph navigation"),
        java_sinks=(
            "ognl.Ognl#parseExpression",
            "ognl.Ognl#getValue",
            "ognl.Ognl#setValue",
        ),
        python_sinks=(),
        description="用户可控数据进入 OGNL 表达式引擎，导致任意代码执行。",
    ),
    VulnEntry(
        name="MVEL Injection",
        cwe="CWE-094",
        cwe_desc="Improper Control of Generation of Code ('Code Injection')",
        category="injection",
        keywords=("mvel", "mvel injection", "mvflex expression language"),
        java_sinks=(
            "org.mvel2.MVEL#eval",
            "org.mvel2.MVEL#executeExpression",
            "org.mvel2.MVEL#compileExpression",
        ),
        python_sinks=(),
        description="用户可控数据进入 MVEL 表达式引擎，导致任意代码执行。",
    ),

    # ── SQL 注入 ────────────────────────────────────────────────────────────
    VulnEntry(
        name="SQL Injection",
        cwe="CWE-089",
        cwe_desc="Improper Neutralization of Special Elements used in an SQL Command",
        category="injection",
        keywords=("sql injection", "sqli", "sql", "jdbc", "database injection"),
        java_sinks=(
            "java.sql.Statement#executeQuery",
            "java.sql.Statement#execute",
            "java.sql.Statement#executeUpdate",
            "java.sql.Connection#prepareStatement",
            "javax.persistence.EntityManager#createNativeQuery",
            "org.springframework.jdbc.core.JdbcTemplate#queryForObject",
        ),
        python_sinks=(
            "cursor.execute",
            "cursor.executemany",
            "session.execute",
            "db.execute",
        ),
        javascript_sinks=(
            "sequelize.query",
            "knex.raw",
            "connection.query",
        ),
        description="用户可控数据未经参数化直接拼接进 SQL 查询，导致数据泄露或权限提升。",
    ),

    # ── 命令注入 ────────────────────────────────────────────────────────────
    VulnEntry(
        name="Command Injection",
        cwe="CWE-078",
        cwe_desc="Improper Neutralization of Special Elements used in an OS Command",
        category="injection",
        keywords=("command injection", "os command", "rce", "shell injection", "code execution"),
        java_sinks=(
            "java.lang.Runtime#exec",
            "java.lang.ProcessBuilder#command",
            "org.apache.commons.exec.CommandLine#addArgument",
        ),
        python_sinks=(
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_output",
            "eval",
            "exec",
        ),
        javascript_sinks=(
            "child_process.exec",
            "child_process.execSync",
            "child_process.spawn",
            "eval",
        ),
        go_sinks=(
            "os/exec.Command",
            "exec.Command",
        ),
        description="用户可控数据拼接进操作系统命令，导致远程代码执行。",
    ),

    # ── 路径穿越 ────────────────────────────────────────────────────────────
    VulnEntry(
        name="Path Traversal",
        cwe="CWE-022",
        cwe_desc="Improper Limitation of a Pathname to a Restricted Directory",
        category="validation",
        keywords=("path traversal", "directory traversal", "lfi", "local file inclusion", "path injection"),
        java_sinks=(
            "java.io.FileInputStream#<init>",
            "java.io.FileOutputStream#<init>",
            "java.io.File#<init>",
            "java.nio.file.Paths#get",
            "java.nio.file.Files#readAllBytes",
            "org.springframework.core.io.FileSystemResource#<init>",
        ),
        python_sinks=(
            "open",
            "os.path.join",
            "pathlib.Path",
            "shutil.copyfile",
            "flask.send_file",
        ),
        javascript_sinks=(
            "fs.readFile",
            "fs.readFileSync",
            "path.join",
            "res.sendFile",
        ),
        description="用户可控路径未经规范化校验，导致访问限制目录外的文件。",
    ),

    # ── 跨站脚本（XSS） ─────────────────────────────────────────────────────
    VulnEntry(
        name="Cross-Site Scripting",
        cwe="CWE-079",
        cwe_desc="Improper Neutralization of Input During Web Page Generation",
        category="injection",
        keywords=("xss", "cross site scripting", "cross-site scripting", "reflected xss", "stored xss"),
        java_sinks=(
            "javax.servlet.http.HttpServletResponse#getWriter",
            "javax.servlet.http.HttpServletResponse#getOutputStream",
            "org.springframework.web.servlet.ModelAndView#addObject",
        ),
        python_sinks=(
            "flask.render_template_string",
            "jinja2.Environment#from_string",
            "markupsafe.Markup",
            "HttpResponse",
        ),
        javascript_sinks=(
            "innerHTML",
            "outerHTML",
            "document.write",
            "element.innerHTML",
            "res.send",
            "res.write",
        ),
        description="用户可控数据未经转义输出到 HTML 页面，导致 XSS 攻击。",
    ),

    # ── SSRF ────────────────────────────────────────────────────────────────
    VulnEntry(
        name="Server-Side Request Forgery",
        cwe="CWE-918",
        cwe_desc="Server-Side Request Forgery (SSRF)",
        category="validation",
        keywords=("ssrf", "server side request forgery", "server-side request forgery", "request forgery"),
        java_sinks=(
            "java.net.URL#openConnection",
            "java.net.URL#openStream",
            "org.apache.http.client.HttpClient#execute",
            "org.springframework.web.client.RestTemplate#getForObject",
            "okhttp3.OkHttpClient#newCall",
        ),
        python_sinks=(
            "requests.get",
            "requests.post",
            "requests.request",
            "urllib.request.urlopen",
            "httpx.get",
            "aiohttp.ClientSession#get",
        ),
        javascript_sinks=(
            "axios.get",
            "fetch",
            "http.request",
            "https.request",
            "request.get",
        ),
        description="用户可控 URL 未经验证直接发起服务端请求，导致内网探测或数据泄露。",
    ),

    # ── 不安全反序列化 ──────────────────────────────────────────────────────
    VulnEntry(
        name="Insecure Deserialization",
        cwe="CWE-502",
        cwe_desc="Deserialization of Untrusted Data",
        category="injection",
        keywords=("deserialization", "insecure deserialization", "unsafe deserialization", "java deserialization", "pickle"),
        java_sinks=(
            "java.io.ObjectInputStream#readObject",
            "java.io.ObjectInputStream#readUnshared",
            "com.fasterxml.jackson.databind.ObjectMapper#readValue",
            "org.yaml.snakeyaml.Yaml#load",
            "com.thoughtworks.xstream.XStream#fromXML",
        ),
        python_sinks=(
            "pickle.loads",
            "pickle.load",
            "marshal.loads",
            "yaml.load",
            "shelve.open",
        ),
        javascript_sinks=(
            "JSON.parse",
            "unserialize",
            "node-serialize.unserialize",
        ),
        description="对不可信数据执行反序列化操作，导致任意代码执行。",
    ),

    # ── XXE ────────────────────────────────────────────────────────────────
    VulnEntry(
        name="XML External Entity Injection",
        cwe="CWE-611",
        cwe_desc="Improper Restriction of XML External Entity Reference",
        category="injection",
        keywords=("xxe", "xml external entity", "xml injection", "xml parsing"),
        java_sinks=(
            "javax.xml.parsers.DocumentBuilder#parse",
            "javax.xml.parsers.SAXParser#parse",
            "javax.xml.transform.Transformer#transform",
            "org.dom4j.io.SAXReader#read",
        ),
        python_sinks=(
            "xml.etree.ElementTree.parse",
            "xml.etree.ElementTree.fromstring",
            "lxml.etree.parse",
            "xml.dom.minidom.parse",
        ),
        description="XML 解析器未禁用外部实体，导致文件读取或 SSRF。",
    ),

    # ── SSTI ────────────────────────────────────────────────────────────────
    VulnEntry(
        name="Server-Side Template Injection",
        cwe="CWE-094",
        cwe_desc="Improper Control of Generation of Code ('Code Injection')",
        category="injection",
        keywords=("ssti", "server side template injection", "template injection", "jinja2", "mako", "freemarker", "velocity", "thymeleaf"),
        java_sinks=(
            "freemarker.template.Template#process",
            "org.apache.velocity.app.VelocityEngine#evaluate",
            "org.thymeleaf.TemplateEngine#process",
        ),
        python_sinks=(
            "jinja2.Template#render",
            "jinja2.Environment#from_string",
            "flask.render_template_string",
            "mako.template.Template#render",
        ),
        javascript_sinks=(
            "ejs.render",
            "pug.render",
            "handlebars.compile",
            "nunjucks.renderString",
        ),
        description="用户可控数据注入模板引擎，导致模板渲染时执行任意代码。",
    ),

    # ── 不安全的加密 ────────────────────────────────────────────────────────
    VulnEntry(
        name="Weak Cryptography",
        cwe="CWE-327",
        cwe_desc="Use of a Broken or Risky Cryptographic Algorithm",
        category="crypto",
        keywords=("weak crypto", "weak cryptography", "md5", "sha1", "des", "rc4", "ecb mode"),
        java_sinks=(
            "java.security.MessageDigest#getInstance[MD5]",
            "java.security.MessageDigest#getInstance[SHA-1]",
            "javax.crypto.Cipher#getInstance[DES]",
            "javax.crypto.Cipher#getInstance[ECB]",
        ),
        python_sinks=(
            "hashlib.md5",
            "hashlib.sha1",
            "Crypto.Cipher.DES",
        ),
        description="使用已知不安全的加密算法（MD5/SHA1/DES/ECB），数据存在被破解风险。",
    ),

    # ── 日志注入 ────────────────────────────────────────────────────────────
    VulnEntry(
        name="Log Injection",
        cwe="CWE-117",
        cwe_desc="Improper Output Neutralization for Logs",
        category="injection",
        keywords=("log injection", "log forging", "crlf injection", "log4j"),
        java_sinks=(
            "org.slf4j.Logger#info",
            "org.slf4j.Logger#warn",
            "org.slf4j.Logger#error",
            "java.util.logging.Logger#info",
        ),
        python_sinks=(
            "logging.info",
            "logging.warning",
            "logging.error",
            "logger.info",
            "logger.warning",
        ),
        description="用户可控数据写入日志，导致日志伪造或 CRLF 注入。",
    ),

    # ── 开放重定向 ──────────────────────────────────────────────────────────
    VulnEntry(
        name="Open Redirect",
        cwe="CWE-601",
        cwe_desc="URL Redirection to Untrusted Site ('Open Redirect')",
        category="validation",
        keywords=("open redirect", "url redirect", "redirect injection", "unvalidated redirect"),
        java_sinks=(
            "javax.servlet.http.HttpServletResponse#sendRedirect",
            "org.springframework.web.servlet.view.RedirectView#<init>",
        ),
        python_sinks=(
            "flask.redirect",
            "django.http.HttpResponseRedirect",
            "django.shortcuts.redirect",
        ),
        javascript_sinks=(
            "res.redirect",
            "window.location",
            "location.href",
        ),
        description="用户可控 URL 未经白名单校验直接用于重定向，导致钓鱼攻击。",
    ),
]

# ---------------------------------------------------------------------------
# 查询接口
# ---------------------------------------------------------------------------

# 名称 → VulnEntry 索引（精确查找）
_BY_NAME: dict[str, VulnEntry] = {e.name.lower(): e for e in VULN_CATALOG}

# 关键字 → VulnEntry 索引（模糊匹配）
_BY_KEYWORD: dict[str, VulnEntry] = {}
for _entry in VULN_CATALOG:
    for _kw in _entry.keywords:
        _BY_KEYWORD[_kw.lower()] = _entry


def find(vuln_type: str) -> Optional[VulnEntry]:
    """
    按漏洞类型名称查找 VulnEntry，支持精确匹配和关键字模糊匹配。

    Args:
        vuln_type: 用户输入的漏洞类型字符串，大小写不敏感。

    Returns:
        匹配的 VulnEntry，未匹配时返回 None。
    """
    key = vuln_type.lower().strip()

    # 精确匹配
    if key in _BY_NAME:
        return _BY_NAME[key]

    # 关键字子串匹配
    for kw, entry in _BY_KEYWORD.items():
        if kw in key or key in kw:
            return entry

    return None


def get_sink_hints(vuln_type: str, language: str) -> str:
    """
    返回指定漏洞类型和语言的 Sink 方法提示字符串。

    Args:
        vuln_type: 漏洞类型名称。
        language: 目标语言（java / python / javascript / go）。

    Returns:
        Sink 方法列表字符串，供 Agent-Q Prompt 使用。
        未匹配时返回通用提示。
    """
    entry = find(vuln_type)
    if entry is None:
        return "（未在漏洞目录中找到，请根据漏洞类型推断常见 Sink 方法）"

    lang = language.lower()
    sinks: tuple[str, ...] = ()
    if lang == "java":
        sinks = entry.java_sinks
    elif lang == "python":
        sinks = entry.python_sinks
    elif lang in ("javascript", "js", "typescript", "ts"):
        sinks = entry.javascript_sinks
    elif lang == "go":
        sinks = entry.go_sinks

    if not sinks:
        return f"（{entry.name} 暂无 {language} Sink 列表，请根据漏洞类型推断）"

    lines = "\n".join(f"  - {s}" for s in sinks)
    return f"CWE: {entry.cwe}（{entry.cwe_desc}）\n已知 Sink 方法：\n{lines}"


def list_all() -> list[str]:
    """返回所有漏洞类型名称列表。"""
    return [e.name for e in VULN_CATALOG]
