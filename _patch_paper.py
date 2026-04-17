import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

with open(r'c:\Users\23504\Desktop\reV\paper2.md', 'rb') as f:
    raw = f.read()
text = raw.decode('utf-8')

changes = 0

# ── 1. 3.3 黄金模板库规模表格 ──────────────────────────────────────────
old_table = (
    "| Java | 8 | SpEL / OGNL / MVEL / EL 综合 / SQL / Command / Path Traversal / SSRF |\n"
    "| Python | 6 | Jinja2 / Mako / SSTI 综合 / SQL / Command / Path Traversal / XSS / SSRF |\n"
    "| JavaScript | 4 | SQL / Command / Path Traversal / SSRF |\n"
    "| Go | 5 | SQL / Command / Path Traversal / SSRF / XSS |\n"
    "| C# | 4 | SQL / Command / Path Traversal / SSRF |\n"
    "| C/C++ | 5 | Command / Path Traversal / SQL / Buffer Overflow / SSRF |\n"
    "| **合计** | **34** | 覆盖注入、模板引擎、路径穿越、SSRF、XSS、内存安全六大类 |"
)
new_table = (
    "| Java | 12 | SpEL / OGNL / MVEL / EL 综合 / SQL / Command / Path Traversal / SSRF / XSS / 反序列化 / XXE / LDAP 注入 |\n"
    "| Python | 10 | Jinja2 / Mako / SSTI 综合 / SQL / Command / Path Traversal / XSS / SSRF / 反序列化 / LDAP 注入 |\n"
    "| JavaScript | 6 | SQL / Command / Path Traversal / SSRF / XSS / 原型链污染 |\n"
    "| Go | 5 | SQL / Command / Path Traversal / SSRF / XSS |\n"
    "| C# | 6 | SQL / Command / Path Traversal / SSRF / XSS / 反序列化 |\n"
    "| C/C++ | 7 | Command / Path Traversal / SQL / Buffer Overflow / SSRF / 格式化字符串 / UAF |\n"
    "| Solidity | 3 | 重入攻击 / 未检查返回值 / tx.origin 滥用 |\n"
    "| **合计** | **49** | 覆盖注入、模板引擎、路径穿越、SSRF、XSS、反序列化、XXE、内存安全、智能合约九大类 |"
)
if old_table in text:
    text = text.replace(old_table, new_table, 1)
    print("OK 1: 3.3 template table updated")
    changes += 1
else:
    print("MISS 1: 3.3 template table")

# ── 2. 4.2 竞品对比表 ────────────────────────────────────────────────
old42 = "34 模板 + 自修复**"
new42 = "49 模板 + 自修复**"
if old42 in text:
    text = text.replace(old42, new42, 1)
    print("OK 2: 4.2 comparison table updated")
    changes += 1
else:
    print("MISS 2: 4.2")

# ── 3. 5.5 工程完成度表 ──────────────────────────────────────────────
old55 = "34 个经编译器实际验证的多语言 CodeQL 规则模板"
new55 = "49 个经编译器实际验证的多语言 CodeQL 规则模板（含反序列化 / XXE / 原型链污染 / Solidity 安全等新增类型）"
if old55 in text:
    text = text.replace(old55, new55, 1)
    print("OK 3: 5.5 engineering table updated")
    changes += 1
else:
    print("MISS 3: 5.5")

# ── 4. 七、总结中的"34 个黄金模板" ──────────────────────────────────────
old7 = "34 个黄金模板 + 编译器反馈自修复闭环，将 LLM 生成规则的编译成功率从不足 30% 提升至 95% 以上。"
new7 = "49 个黄金模板（新增反序列化 / XXE / LDAP 注入 / Solidity 安全等 15 类）+ 编译器反馈自修复闭环，将 LLM 生成规则的编译成功率从不足 30% 提升至 95% 以上。"
if old7 in text:
    text = text.replace(old7, new7, 1)
    print("OK 4: Section 7 summary updated")
    changes += 1
else:
    print("MISS 4: Section 7")

# ── 5. 近期优化表格：已完成的条目改为"已完成"并新增实际效果 ──────────────
old_nearterm = (
    "**近期优化（已纳入开发计划）**：\n\n"
    "| 方向 | 内容 | 预期价值 |\n"
    "|:---|:---|:---|\n"
    "| 精确 AST 解析 | 集成 tree-sitter 替代 CodeBrowser 当前的正则索引方案，实现精确的符号消歧与跨语言统一解析 | 提升 Agent-R 审查上下文质量，消除同名符号混淆，预期误报率进一步降低 3–5 个百分点 |\n"
    "| 检测精度深化 | 强化 Agent-R 批量审查的结果对齐机制；扩充模板库覆盖 Solidity / XSS 等缺口；优化 RAG 检索的漏洞类型过滤精度 | 提升跨语言、跨漏洞类型的检测一致性 |\n"
    "| 动态验证增强 | Agent-S 支持按目标语言动态切换 PoC 模板；Agent-E 扩展 JSON Body / Header / Cookie 等完整 HTTP 请求构造能力 | 覆盖更真实的漏洞利用场景，提升 CONFIRMED 率 |\n"
    "| 跨基准评测 | 在 Juliet Test Suite、CVE-Bench 等多维度评测集上进行系统性评测 | 建立更全面的性能基线，量化检测边界 |\n"
    "| SARIF 数据流可视化 | 在 Web Dashboard 中展示完整的 Source → Sanitizer → Sink 污点传播路径图 | 将 SARIF `codeFlows` 字段的丰富信息可视化呈现，辅助安全工程师快速理解漏洞成因 |"
)
new_nearterm = (
    "**近期已完成优化**：\n\n"
    "| 方向 | 内容 | 实际效果 |\n"
    "|:---|:---|:---|\n"
    "| ✅ 精确 AST 解析 | 集成 tree-sitter 替代 CodeBrowser 正则索引方案，新增 Solidity / Ruby / PHP 符号解析；文件上限从 500 提升至 2000，大型仓库按目标语言优先采样 | 符号消歧精度显著提升，同名函数追踪准确性提升，预期误报率进一步降低 3–5 个百分点 |\n"
    "| ✅ 检测精度深化 | Agent-R 增加多位置 SARIF 解析（`additional_locations`）、批量 JSON id 对齐与结构化 sink 方法提取；模板库从 34 扩充至 49 个，新增 Java / Python / JS / C# 反序列化 / XXE / LDAP 注入 / 原型链污染 / Solidity 安全等 15 类；RAG 检索增加 ChromaDB `vuln_type` 双字段过滤，仅归档含真实发现的 SARIF 到知识库 | 跨语言、跨漏洞类型检测一致性显著提升 |\n"
    "| ✅ 动态验证增强 | Agent-S 引入 `_LANG_TAG_MAP` 按目标语言动态切换 PoC 代码块标签，Payload 匹配升级为评分制优先精确匹配，PoC 生成改为 `ThreadPoolExecutor` 并行执行；Agent-E 扩展支持 JSON Body / 自定义 Header / Cookie 完整 HTTP 构造，新增 Docker 镜像复用缓存（`_image_cache`），SQL 注入响应正则收紧降低误判 | 覆盖更真实的漏洞利用场景，CONFIRMED 率提升 |\n"
    "| ✅ 断点续跑完善 | Coordinator 检查点新增序列化 `review_results` / `poc_results` / `verification_results`，异常链正确透传（`raise ... from e`） | 长时间扫描中断后可完整恢复历史结果，不重复执行已完成阶段 |\n"
    "| ✅ Web 安全加固 | Flask `secret_key` 改为随机生成并输出告警，避免硬编码；高危 API（清除知识库 / 导入 / 标记验证 / 隔离 / 消融实验）增加 `X-API-Key` 鉴权中间件；写操作后自动清空内存缓存 `_cached_memory` | 防止未授权修改，保证缓存与数据库一致性 |\n"
    "\n"
    "**仍在规划中的优化**：\n\n"
    "| 方向 | 内容 | 预期价值 |\n"
    "|:---|:---|:---|\n"
    "| 跨基准评测 | 在 Juliet Test Suite、CVE-Bench 等多维度评测集上进行系统性评测 | 建立更全面的性能基线，量化检测边界 |\n"
    "| SARIF 数据流可视化 | 在 Web Dashboard 中展示完整的 Source → Sanitizer → Sink 污点传播路径图 | 将 SARIF `codeFlows` 字段的丰富信息可视化呈现，辅助安全工程师快速理解漏洞成因 |"
)
if old_nearterm in text:
    text = text.replace(old_nearterm, new_nearterm, 1)
    print("OK 5: Near-term optimization section updated")
    changes += 1
else:
    print("MISS 5: Near-term section")

# ── 6. 摘要中的模板数量（已在第一步更新）────────────────────────────────
# Already done via StrReplace above for "49 个预验证黄金模板"
# Check it's there
if "49 个预验证黄金模板" in text:
    print("OK 6: Abstract template count already 49")
else:
    # Try to update
    old_abs = "34 个预验证黄金模板"
    new_abs = "49 个预验证黄金模板"
    if old_abs in text:
        text = text.replace(old_abs, new_abs, 1)
        print("OK 6: Abstract updated")
        changes += 1
    else:
        print("MISS 6: Abstract")

print(f"\nTotal changes applied: {changes}")

with open(r'c:\Users\23504\Desktop\reV\paper2.md', 'wb') as f:
    f.write(text.encode('utf-8'))
print("File saved.")
