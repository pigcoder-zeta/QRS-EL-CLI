import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

with open(r'c:\Users\23504\Desktop\reV\paper2.md', 'rb') as f:
    raw = f.read()
text = raw.decode('utf-8')

changes = 0

# ── A. 3.4 节 CodeBrowser 升级描述 ─────────────────────────────────────
old_cb = (
    "Agent-R 的关键差异化能力在于**符号级代码导航引擎**，彻底替代固定行窗口的朴素上下文获取方式。该引擎提供五项导航能力："
)
new_cb = (
    "Agent-R 的关键差异化能力在于**符号级代码导航引擎**，彻底替代固定行窗口的朴素上下文获取方式。引擎底层已集成 tree-sitter 精确 AST 解析（覆盖 Java / Python / JavaScript / Go / C# / C/C++ / Solidity / Ruby / PHP 共 9 种语言），在 tree-sitter 可用时优先基于语法树提取符号，回退至正则时仍可正确处理长尾语言。可索引源文件数量从 500 提升至 2000，大型仓库采用按目标语言优先采样策略。该引擎提供五项导航能力："
)
if old_cb in text:
    text = text.replace(old_cb, new_cb, 1)
    print("OK A: CodeBrowser description updated")
    changes += 1
else:
    print("MISS A: CodeBrowser description")

# ── B. 3.4 节 Agent-R 输出规范描述（补充多位置 SARIF 解析） ──────────────
old_out = (
    "**输出规范**：每条审查结论包含状态标签（`vulnerable / safe / uncertain`）、量化置信度评分、检测引擎标识、推理说明和 Sink 方法签名，形成标准化研判记录。"
)
new_out = (
    "**输出规范**：每条审查结论包含状态标签（`vulnerable / safe / uncertain`）、量化置信度评分、检测引擎标识、推理说明和 Sink 方法签名，形成标准化研判记录。"
    "\n\n"
    "**增强的 SARIF 解析能力**：Agent-R 对 SARIF 的解析已升级为多位置感知模式——每条告警除主发现位置外，还提取所有 `locations` 补充位置和 `relatedLocations` 关联位置，合并为结构化 `additional_locations` 字段；批量审查的 LLM 响应通过 id 对齐验证确保结果与预期告警一一对应，缺失条目自动标记为 `UNCERTAIN`；Sink 方法名从 SARIF 消息中精确提取（匹配反引号包裹的符号名），替代原有的消息截断方式，使 CodeBrowser 符号查询更加准确。"
)
if old_out in text:
    text = text.replace(old_out, new_out, 1)
    print("OK B: Agent-R output spec updated")
    changes += 1
else:
    print("MISS B: Agent-R output spec")

# ── C. 3.5 节 RAG 检索精度描述 ────────────────────────────────────────
old_rag = "存储后端支持五级降级策略（ChromaDB → FAISS → sentence-transformers → TF-IDF → Jaccard），保证在不同部署环境下的可用性。"
new_rag = (
    "存储后端支持五级降级策略（ChromaDB → FAISS → sentence-transformers → TF-IDF → Jaccard），保证在不同部署环境下的可用性。"
    "\n\n"
    "**检索精度增强**：ChromaDB 后端的检索查询已升级为 `language` + `vuln_type` 双字段联合过滤，避免同语言不同漏洞类型的规则相互干扰，提升 Few-Shot 示例的相关性。同时，只有 SARIF 中含真实漏洞发现的扫描结果才会归档至知识库，防止无效扫描污染规则记忆。"
)
if old_rag in text:
    text = text.replace(old_rag, new_rag, 1)
    print("OK C: RAG retrieval description updated")
    changes += 1
else:
    print("MISS C: RAG retrieval")

# ── D. 3.6 节 Agent-S 多语言 PoC 能力 ────────────────────────────────
old_agts = "Agent-S 结合 LLM 对源码的参数推断能力（接口路径、参数名、Content-Type 等），将策略模板实例化为完整的 HTTP 验证请求。"
new_agts = (
    "Agent-S 结合 LLM 对源码的参数推断能力（接口路径、参数名、Content-Type 等），将策略模板实例化为完整的 HTTP 验证请求。"
    "\n\n"
    "**多语言 PoC 去中心化**：Agent-S 不再硬编码 Java 代码块标签，引入 `_LANG_TAG_MAP` 按目标文件扩展名动态选择 Prism.js 语言标签（Java / Python / JavaScript / Go / C# / C++ / Solidity 等），使 PoC 提示中的源码上下文能正确高亮任意语言。Payload 匹配策略由朴素子串检测升级为**评分制**——精确匹配 > 包含匹配 > 被包含匹配，多候选时取最高得分项，降低跨引擎 Payload 混淆概率。PoC 批量生成通过 `ThreadPoolExecutor`（默认 3 并发）并行执行，缩短多漏洞场景的总等待时间。"
)
if old_agts in text:
    text = text.replace(old_agts, new_agts, 1)
    print("OK D: Agent-S multi-lang description updated")
    changes += 1
else:
    print("MISS D: Agent-S")

# ── E. 3.6 节 Agent-E 能力描述 ──────────────────────────────────────
old_agte = "Agent-E 自动解析目标项目中的 `Dockerfile` / `docker-compose.yml`，动态构建镜像并拉起隔离沙箱。验证判定采用**双层分析机制**："
new_agte = (
    "Agent-E 自动解析目标项目中的 `Dockerfile` / `docker-compose.yml`，动态构建镜像并拉起隔离沙箱。新增 Docker 镜像复用缓存（`_image_cache`）——相同仓库路径的后续验证直接复用已构建镜像，避免重复 `docker build` 开销，在同一扫描任务中的 PoC 迭代场景下效果显著。HTTP 请求构造能力已全面扩展：支持 JSON Body（`application/json`）、自定义 Header（`X-Custom-*` 等）与 Cookie 的完整构造，覆盖现代 API 的真实调用场景。验证判定采用**双层分析机制**："
)
if old_agte in text:
    text = text.replace(old_agte, new_agte, 1)
    print("OK E: Agent-E description updated")
    changes += 1
else:
    print("MISS E: Agent-E")

# ── F. 七、展望部分更新（展望中"近期优化"已实现，需对应调整） ────────────────
old_outlook = (
    "Argus 当前版本已具备完整的工程可用性。后续迭代分为**近期优化**（已规划实施路径）与**中长期演进**两个层次："
)
new_outlook = (
    "Argus 当前版本已具备完整的工程可用性，并在最近一轮迭代中完成了多项核心增强（详见下文"近期已完成优化"）。后续迭代分为**仍在规划中的近期优化**与**中长期演进**两个层次："
)
if old_outlook in text:
    text = text.replace(old_outlook, new_outlook, 1)
    print("OK F: Outlook intro updated")
    changes += 1
else:
    print("MISS F: Outlook intro")

print(f"\nTotal changes applied: {changes}")

with open(r'c:\Users\23504\Desktop\reV\paper2.md', 'wb') as f:
    f.write(text.encode('utf-8'))
print("File saved.")
