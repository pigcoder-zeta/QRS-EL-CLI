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
    category: str                   # 分类：injection / auth / config / validation / crypto / memory / kernel
    keywords: tuple[str, ...]       # 用于模糊匹配的关键字（小写）
    java_sinks: tuple[str, ...]     # Java Sink 方法提示
    python_sinks: tuple[str, ...]   # Python Sink 方法提示
    javascript_sinks: tuple[str, ...] = field(default_factory=tuple)
    go_sinks: tuple[str, ...] = field(default_factory=tuple)
    cpp_sinks: tuple[str, ...] = field(default_factory=tuple)  # C/C++ / Kernel Sink 提示
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

    # =====================================================================
    #  非 Web 漏洞领域（v2.3 新增）
    # =====================================================================

    # ── 硬编码凭证 ────────────────────────────────────────────────────────
    VulnEntry(
        name="Hardcoded Credentials",
        cwe="CWE-798",
        cwe_desc="Use of Hard-coded Credentials",
        category="crypto",
        keywords=("hardcoded password", "hardcoded credential", "hardcoded secret",
                  "hardcoded key", "hard-coded", "embedded password", "password in code"),
        java_sinks=(
            "java.sql.DriverManager#getConnection",
            "javax.crypto.spec.SecretKeySpec#<init>",
        ),
        python_sinks=(
            "connect", "login", "authenticate",
        ),
        javascript_sinks=(
            "createConnection", "jwt.sign",
        ),
        description="密码/密钥/Token 直接硬编码在源代码中，泄露后无法撤销。查询模式：pattern-match",
    ),

    # ── 不安全的随机数 ───────────────────────────────────────────────────
    VulnEntry(
        name="Insecure Randomness",
        cwe="CWE-330",
        cwe_desc="Use of Insufficiently Random Values",
        category="crypto",
        keywords=("weak random", "insecure random", "math.random", "predictable random",
                  "insufficient randomness", "prng"),
        java_sinks=(
            "java.util.Random#nextInt",
            "java.util.Random#nextLong",
            "java.lang.Math#random",
        ),
        python_sinks=(
            "random.random", "random.randint", "random.choice",
        ),
        javascript_sinks=(
            "Math.random",
        ),
        description="在安全场景（Token/密钥/验证码）中使用可预测的伪随机数生成器。查询模式：pattern-match",
    ),

    # ── 敏感信息泄露 ─────────────────────────────────────────────────────
    VulnEntry(
        name="Information Exposure",
        cwe="CWE-200",
        cwe_desc="Exposure of Sensitive Information to an Unauthorized Actor",
        category="info-leak",
        keywords=("information exposure", "info leak", "sensitive data exposure",
                  "data exposure", "information disclosure", "stack trace exposure"),
        java_sinks=(
            "javax.servlet.http.HttpServletResponse#getWriter",
            "java.io.PrintWriter#println",
            "java.lang.Exception#printStackTrace",
        ),
        python_sinks=(
            "traceback.print_exc", "flask.jsonify",
        ),
        javascript_sinks=(
            "res.json", "res.send", "console.log",
        ),
        description="敏感信息（堆栈、内部路径、数据库错误）泄露给外部用户。",
    ),

    # ── 不安全的 TLS/SSL 配置 ────────────────────────────────────────────
    VulnEntry(
        name="Insecure TLS Configuration",
        cwe="CWE-295",
        cwe_desc="Improper Certificate Validation",
        category="crypto",
        keywords=("insecure tls", "insecure ssl", "certificate validation",
                  "ssl verify", "tls verification", "trust all certificates"),
        java_sinks=(
            "javax.net.ssl.HttpsURLConnection#setHostnameVerifier",
            "javax.net.ssl.SSLContext#init",
            "org.apache.http.conn.ssl.NoopHostnameVerifier",
        ),
        python_sinks=(
            "requests.get[verify=False]",
            "ssl._create_unverified_context",
            "urllib3.disable_warnings",
        ),
        javascript_sinks=(
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED",
            "rejectUnauthorized: false",
        ),
        go_sinks=(
            "tls.Config{InsecureSkipVerify: true}",
        ),
        description="禁用 TLS 证书验证或使用不安全的 SSL 配置，导致中间人攻击。查询模式：pattern-match",
    ),

    # ── C/C++ 缓冲区溢出 ────────────────────────────────────────────────
    VulnEntry(
        name="Buffer Overflow",
        cwe="CWE-120",
        cwe_desc="Buffer Copy without Checking Size of Input",
        category="memory",
        keywords=("buffer overflow", "buffer overrun", "stack overflow", "heap overflow",
                  "strcpy", "strcat", "sprintf", "gets"),
        java_sinks=(),
        python_sinks=(),
        javascript_sinks=(),
        go_sinks=(),
        description="未检查输入大小直接复制到固定大小缓冲区，导致内存破坏和代码执行。查询模式：pattern-match (C/C++)",
    ),

    # ── Use-After-Free ──────────────────────────────────────────────────
    VulnEntry(
        name="Use After Free",
        cwe="CWE-416",
        cwe_desc="Use After Free",
        category="memory",
        keywords=("use after free", "uaf", "dangling pointer", "double free", "memory corruption"),
        java_sinks=(),
        python_sinks=(),
        description="释放内存后继续使用指向该内存的指针，导致任意代码执行。查询模式：local-flow (C/C++)",
    ),

    # ── 整数溢出 ────────────────────────────────────────────────────────
    VulnEntry(
        name="Integer Overflow",
        cwe="CWE-190",
        cwe_desc="Integer Overflow or Wraparound",
        category="memory",
        keywords=("integer overflow", "integer wraparound", "integer underflow",
                  "signed overflow", "arithmetic overflow"),
        java_sinks=(),
        python_sinks=(),
        description="整数运算溢出导致缓冲区分配不足或逻辑错误。查询模式：local-flow (C/C++)",
    ),

    # ── 格式化字符串漏洞 ────────────────────────────────────────────────
    VulnEntry(
        name="Format String Vulnerability",
        cwe="CWE-134",
        cwe_desc="Use of Externally-Controlled Format String",
        category="memory",
        keywords=("format string", "printf vulnerability", "format string attack",
                  "uncontrolled format string"),
        java_sinks=(
            "java.lang.String#format",
            "java.io.PrintStream#printf",
        ),
        python_sinks=(
            "str.format", "f-string",
        ),
        description="用户可控数据作为格式化字符串，在 C/C++ 中可导致内存读写。查询模式：taint (C/C++)",
    ),

    # ── 资源泄露 ────────────────────────────────────────────────────────
    VulnEntry(
        name="Resource Leak",
        cwe="CWE-772",
        cwe_desc="Missing Release of Resource after Effective Lifetime",
        category="resource",
        keywords=("resource leak", "file handle leak", "connection leak",
                  "socket leak", "memory leak", "unclosed resource"),
        java_sinks=(
            "java.io.FileInputStream#<init>",
            "java.sql.Connection",
            "java.net.Socket#<init>",
        ),
        python_sinks=(
            "open", "socket.socket",
        ),
        description="打开的资源（文件/连接/Socket）未在所有路径上正确关闭。查询模式：pattern-match",
    ),

    # ── 竞态条件 ────────────────────────────────────────────────────────
    VulnEntry(
        name="Race Condition",
        cwe="CWE-362",
        cwe_desc="Concurrent Execution using Shared Resource with Improper Synchronization",
        category="concurrency",
        keywords=("race condition", "toctou", "time of check time of use",
                  "concurrent access", "data race", "thread safety"),
        java_sinks=(
            "java.io.File#exists",
            "java.io.File#delete",
            "java.util.HashMap",
        ),
        python_sinks=(
            "os.path.exists", "os.remove",
        ),
        go_sinks=(
            "sync.Map", "map access",
        ),
        description="检查与使用之间的时间窗口被利用，导致权限绕过或数据不一致。查询模式：pattern-match",
    ),

    # =====================================================================
    #  移动安全（v2.3 新增）
    # =====================================================================

    VulnEntry(
        name="Android Intent Injection",
        cwe="CWE-927",
        cwe_desc="Use of Implicit Intent for Sensitive Communication",
        category="mobile",
        keywords=("intent injection", "implicit intent", "android intent",
                  "intent hijack", "exported component", "intent redirection"),
        java_sinks=(
            "android.content.Context#sendBroadcast",
            "android.content.Context#startActivity",
            "android.content.Context#startService",
            "android.content.Intent#<init>",
        ),
        python_sinks=(),
        description="隐式 Intent 或导出组件未做权限校验，导致敏感通信被劫持。",
    ),

    VulnEntry(
        name="Android Insecure Storage",
        cwe="CWE-312",
        cwe_desc="Cleartext Storage of Sensitive Information",
        category="mobile",
        keywords=("insecure storage", "shared preferences", "cleartext storage",
                  "android storage", "world readable", "world writable"),
        java_sinks=(
            "android.content.SharedPreferences.Editor#putString",
            "android.database.sqlite.SQLiteDatabase#execSQL",
            "java.io.FileOutputStream#write",
        ),
        python_sinks=(),
        description="敏感数据（密码/Token）以明文存储在 SharedPreferences 或 SQLite 中。查询模式：pattern-match",
    ),

    VulnEntry(
        name="Android WebView Vulnerability",
        cwe="CWE-749",
        cwe_desc="Exposed Dangerous Method or Function",
        category="mobile",
        keywords=("webview", "javascript interface", "addjavascriptinterface",
                  "webview rce", "setjavascriptenabled", "file access"),
        java_sinks=(
            "android.webkit.WebView#addJavascriptInterface",
            "android.webkit.WebSettings#setJavaScriptEnabled",
            "android.webkit.WebSettings#setAllowFileAccess",
            "android.webkit.WebView#loadUrl",
        ),
        python_sinks=(),
        description="WebView 启用 JavaScript 接口或文件访问，导致远程代码执行或数据泄露。",
    ),

    VulnEntry(
        name="Android Content Provider Leak",
        cwe="CWE-926",
        cwe_desc="Improper Export of Android Application Components",
        category="mobile",
        keywords=("content provider", "exported provider", "provider leak",
                  "content resolver", "android export"),
        java_sinks=(
            "android.content.ContentResolver#query",
            "android.content.ContentResolver#insert",
            "android.content.ContentResolver#delete",
        ),
        python_sinks=(),
        description="ContentProvider 未限制导出权限，外部应用可读取/修改敏感数据。查询模式：pattern-match",
    ),

    # =====================================================================
    #  供应链安全（v2.3 新增）
    # =====================================================================

    VulnEntry(
        name="Known Vulnerable Dependency",
        cwe="CWE-1395",
        cwe_desc="Dependency on Vulnerable Third-Party Component",
        category="supply-chain",
        keywords=("vulnerable dependency", "known vulnerability", "cve dependency",
                  "outdated library", "dependency vulnerability", "sca"),
        java_sinks=(),
        python_sinks=(),
        description="项目依赖包含已知 CVE 漏洞的第三方组件。检测方式：包元数据分析",
    ),

    VulnEntry(
        name="Typosquatting Package",
        cwe="CWE-1357",
        cwe_desc="Reliance on Insufficiently Trustworthy Component",
        category="supply-chain",
        keywords=("typosquatting", "malicious package", "name confusion",
                  "dependency confusion", "supply chain attack"),
        java_sinks=(),
        python_sinks=(),
        description="依赖名称与知名包高度相似，可能为恶意仿冒包。检测方式：包名相似度分析",
    ),

    # =====================================================================
    #  智能合约安全（v2.3 新增）
    # =====================================================================

    VulnEntry(
        name="Reentrancy Attack",
        cwe="CWE-841",
        cwe_desc="Improper Enforcement of Behavioral Workflow",
        category="smart-contract",
        keywords=("reentrancy", "reentrancy attack", "recursive call",
                  "solidity reentrancy", "smart contract reentrancy"),
        java_sinks=(),
        python_sinks=(),
        description="合约在外部调用前未更新状态，允许攻击者递归调用提取资金。查询模式：pattern-match (Solidity)",
    ),

    VulnEntry(
        name="Unchecked External Call",
        cwe="CWE-252",
        cwe_desc="Unchecked Return Value",
        category="smart-contract",
        keywords=("unchecked call", "unchecked send", "unchecked transfer",
                  "low level call", "solidity call"),
        java_sinks=(),
        python_sinks=(),
        description="低层调用（call/send/transfer）的返回值未被检查，可能导致资金丢失。查询模式：pattern-match (Solidity)",
    ),

    VulnEntry(
        name="Smart Contract Integer Overflow",
        cwe="CWE-190",
        cwe_desc="Integer Overflow or Wraparound",
        category="smart-contract",
        keywords=("solidity overflow", "solidity underflow", "smart contract overflow",
                  "uint overflow", "arithmetic overflow solidity"),
        java_sinks=(),
        python_sinks=(),
        description="Solidity 0.8 之前的版本无内置溢出检查，算术运算可导致资金异常。",
    ),

    # =====================================================================
    #  Linux 内核安全（v2.4 新增 —— Agent-T kernel_module 专用）
    # =====================================================================

    VulnEntry(
        name="Kernel UAF",
        cwe="CWE-416",
        cwe_desc="Use After Free",
        category="kernel",
        keywords=("kernel uaf", "kernel use after free", "kfree uaf",
                  "linux uaf", "slab uaf", "rcu uaf"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "kfree", "vfree", "kvfree", "kfree_rcu",
            "kmem_cache_free", "put_device", "kobject_put",
        ),
        description="内核对象释放（kfree/vfree）后指针仍被引用，可导致权限提升或代码执行。",
    ),

    VulnEntry(
        name="Kernel OOB",
        cwe="CWE-787",
        cwe_desc="Out-of-bounds Write",
        category="kernel",
        keywords=("kernel oob", "kernel out of bounds", "kernel buffer overflow",
                  "kernel heap overflow", "kernel stack overflow", "slab overflow"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "memcpy", "__memcpy", "memmove", "memset",
            "copy_from_user", "__copy_from_user",
            "strncpy", "strlcpy", "sprintf", "snprintf",
            "kmalloc", "kzalloc",
        ),
        description="内核缓冲区越界读写（堆/栈/slab），通常由 copy_from_user 长度未校验引起。",
    ),

    VulnEntry(
        name="Kernel Race Condition",
        cwe="CWE-362",
        cwe_desc="Concurrent Execution using Shared Resource with Improper Synchronization",
        category="kernel",
        keywords=("kernel race", "kernel race condition", "kernel toctou",
                  "kernel data race", "lock missing", "rcu race"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "spin_lock", "spin_unlock", "mutex_lock", "mutex_unlock",
            "rcu_read_lock", "rcu_read_unlock", "rcu_dereference",
            "atomic_read", "atomic_set", "refcount_dec_and_test",
        ),
        description="内核共享数据结构在未持有正确锁的情况下被并发访问，导致数据不一致或权限提升。",
    ),

    VulnEntry(
        name="Kernel Privilege Escalation",
        cwe="CWE-269",
        cwe_desc="Improper Privilege Management",
        category="kernel",
        keywords=("kernel privesc", "kernel privilege escalation", "kernel capability",
                  "ioctl privilege", "capability check missing"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "capable", "ns_capable", "inode_permission",
            "security_file_permission", "cred_alloc_blank",
            "commit_creds", "prepare_kernel_cred",
        ),
        description="内核特权操作缺少 capable()/权限检查，非特权用户可执行特权操作。",
    ),

    VulnEntry(
        name="Kernel Null Pointer Dereference",
        cwe="CWE-476",
        cwe_desc="NULL Pointer Dereference",
        category="kernel",
        keywords=("kernel null deref", "kernel null pointer", "kmalloc null",
                  "kzalloc null", "null dereference kernel"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "kmalloc", "kzalloc", "kcalloc", "vmalloc", "vzalloc",
            "kmalloc_array", "devm_kzalloc", "devm_kmalloc",
        ),
        description="kmalloc/kzalloc 返回值未判空直接解引用，在内存压力下导致内核崩溃（DoS）。",
    ),

    VulnEntry(
        name="Kernel Integer Overflow",
        cwe="CWE-190",
        cwe_desc="Integer Overflow or Wraparound",
        category="kernel",
        keywords=("kernel integer overflow", "kernel int overflow", "kernel arithmetic overflow",
                  "size_t overflow", "kmalloc size overflow"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "kmalloc", "kzalloc", "kcalloc", "vmalloc",
            "kmalloc_array", "array_size", "struct_size",
            "check_mul_overflow", "check_add_overflow",
        ),
        description="算术运算溢出导致 kmalloc 分配不足的内存，后续写入引发堆溢出。",
    ),

    VulnEntry(
        name="Kernel Information Leak",
        cwe="CWE-200",
        cwe_desc="Exposure of Sensitive Information to an Unauthorized Actor",
        category="kernel",
        keywords=("kernel info leak", "kernel information leak", "kernel infoleak",
                  "uninitialized memory leak", "stack leak kernel", "heap leak kernel"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "copy_to_user", "__copy_to_user", "put_user", "__put_user",
            "nla_put", "skb_put", "simple_read_from_buffer",
        ),
        description="未初始化的栈/堆内存通过 copy_to_user 泄露到用户态，暴露内核地址或敏感数据。",
    ),

    VulnEntry(
        name="Kernel Double Free",
        cwe="CWE-415",
        cwe_desc="Double Free",
        category="kernel",
        keywords=("kernel double free", "double kfree", "linux double free"),
        java_sinks=(),
        python_sinks=(),
        cpp_sinks=(
            "kfree", "vfree", "kvfree", "kmem_cache_free",
        ),
        description="同一内核内存区域被释放两次，破坏 slab 分配器元数据，可导致任意写入。",
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
    elif lang in ("cpp", "c", "kernel"):
        sinks = entry.cpp_sinks

    if not sinks:
        return f"（{entry.name} 暂无 {language} Sink 列表，请根据漏洞类型推断）"

    lines = "\n".join(f"  - {s}" for s in sinks)
    return f"CWE: {entry.cwe}（{entry.cwe_desc}）\n已知 Sink 方法：\n{lines}"


def list_all() -> list[str]:
    """返回所有漏洞类型名称列表。"""
    return [e.name for e in VULN_CATALOG]
