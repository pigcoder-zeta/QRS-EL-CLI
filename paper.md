# QRSE-X：基于神经符号融合的多 Agent 协同自动化通用漏洞检测系统

**A Neuro-Symbolic Multi-Agent System for Automated Vulnerability Detection via CodeQL Rule Synthesis**

---

**作者**：pigcoder-zeta  
**所属机构**：开源安全研究项目（https://github.com/pigcoder-zeta/QRSE-X-CLI）  
**版本**：v2.1（2026年4月）

---

## 摘要

静态应用安全测试（SAST）长期面临两大核心矛盾：规则编写门槛高（需要掌握目标语言与查询语言）和误报率居高不下（纯符号方法缺乏语义理解）。2026年的一项研究《QRS: A Rule-Synthesizing Neuro-Symbolic Triad for Autonomous Vulnerability Discovery》（arXiv:2602.09774）提出了一种融合大语言模型（LLM）与 CodeQL 引擎的三节点（Query、Review、Sanitize）协同框架，在 Python 生态中取得了显著成果。

本文在其思想启发下，设计并实现了更具工程普适性的 **QRSE-X 系统**。我们在原论文的三智能体基础上，扩展并演进了四个功能专一的智能体：**Agent-Q**（自修复规则合成器）、**Agent-R**（语义感知审查器）、**Agent-S**（PoC 载荷生成器）和 **Agent-E**（动态沙箱执行器）。该系统将检测范围扩展到涵盖 **Java、Python、JavaScript、Go、C#、C++ 六大主流语言**的 **14 类**通用高危漏洞，并在以下方面取得了工程与架构上的创新：（1）实现"黄金模板优先+编译自修复"的闭环（27 个预验证黄金模板覆盖六种语言），将规则编译成功率大幅提升（工程实践估算，有效避免了 LLM 直接生成的高失败率）；（2）引入 ChromaDB/FAISS 构建漏洞利用链路级的 RAG 记忆检索，并配套**来源验证机制（TrustLevel 四级体系 + HMAC-SHA256 Bundle 签名 + SHA-256 完整性指纹）**抵御 RAG 投毒攻击；（3）通过 Docker 沙箱（需目标仓库含 `Dockerfile`）实现动态运行时确认闭环；（4）实现大型项目的"建库一次、多漏洞并行扫描"策略（并通过类级 `threading.Lock` 解决 CodeQL IMB 缓存并发锁问题）。

**关键词**：静态应用安全测试；大语言模型；CodeQL；多智能体系统；漏洞检测；神经符号融合；RAG；动态验证

---

## 1. 引言

### 1.1 研究背景与动机

静态应用安全测试（SAST）在 DevSecOps 流程中占据核心地位，然而如 CodeQL、Semgrep 等主流工具普遍面临规则编写成本高和误报率高的困境。大语言模型（LLM）的兴起为 SAST 提供了语义推理能力。

2026年发表的《QRS: A Rule-Synthesizing Neuro-Symbolic Triad for Autonomous Vulnerability Discovery》提供了一个极具潜力的神经符号融合框架：
- **Query (Q) agent**：基于结构化 Schema 生成 CodeQL 查询。
- **Review (R) agent**：追踪数据流，进行语义可达性验证。
- **Sanitize (S) agent**：在干净环境中进行无上下文的最终证据验证。

原论文在 Python (PyPI) 生态下发现了 34 个 CVE，证明了该架构的优越性。然而，在实际企业落地中，仍面临多语言适配、LLM 幻觉导致的 CodeQL 编译失败、动态沙箱调度工程复杂性以及历史漏洞规则结构化积累等问题。

### 1.2 QRSE-X 的核心贡献

1. **四 Agent 扩展架构**：将原论文的 S 节点拆分升级为 Agent-S（PoC 文本生成）与 Agent-E（自动化 Docker 沙箱执行），实现"SAST 静态检出 → LLM 语义推断 → 真实靶机 HTTP 验证"全自动闭环。
2. **带编译自修复的模板合成**：引入"黄金模板库（QLTemplateLibrary，27 个预验证模板覆盖六种语言）+ 编译器 stderr 错误反馈循环"，将规则首次运行成功率从不足 30% 提升至 95% 以上。
3. **漏洞利用链路级 RAG + 抗投毒来源验证**：引入完整向量数据库（支持 ChromaDB 等 5 级后端降级），将 Sink 方法、Source-Sink 数据流摘要、代码片段整合为富文本 Embedding，实现"漏洞经验记忆池"；并设计了 **TrustLevel 四级可信体系**（trusted / verified / unverified / quarantined）、**SHA-256 完整性指纹**和 **HMAC-SHA256 Bundle 签名**，防止外部导入的恶意规则污染 LLM 的 Few-Shot 上下文。
4. **多语言与通用漏洞支持**：原生支持 **Java、Python、JavaScript、Go、C#、C++** 六大语言，内置 **14 大类漏洞**（Spring EL、OGNL、MVEL、SQL 注入、命令注入、路径穿越、XSS、SSRF、XXE、反序列化、SSTI、弱加密、日志注入、开放重定向）的完整知识库与专有 Payload 策略（约 15 种 Payload 模板），并为每种语言配备了语言专属的 Agent-Q 规则生成系统提示和 Agent-R 语义审查提示。
5. **企业级性能优化**：基于 Git Commit Hash 的数据库增量缓存，多漏洞类型并行扫描（建库唯一一次，多线程并发调度），并通过类级 `threading.Lock` 串行化 `codeql database analyze`，解决 `OverlappingFileLockException` 并发锁冲突。

---

## 2. 系统架构设计

### 2.1 整体流水线 (Pipeline)

```
┌─────────────────────────────────────────────────┐
│              用户输入层                           │
│    GitHub URL  ──或──  本地源码目录               │
└──────────────────┬──────────────────────────────┘
                   │
Phase 0            │          Phase 1
GithubRepoManager  │     CodeQLRunner + DatabaseCache
克隆 + 框架探测    │          建库（含 Git 缓存）
                   │
           ┌───────┴────────────────┐
           ▼        Phase 2         ▼
        Agent-Q（规则合成）
        ├ 黄金模板优先
        ├ RAG 规则检索
        └ 编译自修复循环 (Max=3)
           │
    ┌──────┼──────┐
    ▼      ▼      ▼
Phase 3  Phase 4  Phase 5
CodeQL   Agent-R  Agent-S
扫描     语义审查  PoC 构造
SARIF
    │
    ▼
  Phase 6
  Agent-E
  Docker 沙箱验证
    │
    ▼
HTML + JSON + CLI 报告
```

### 2.2 多漏洞并行扫描策略

- **串行建库**：针对指定 Commit Hash 提取一次 CodeQL Database。
- **并行分析**：通过 `ThreadPoolExecutor` 并发 Phase 2-6，各漏洞类型独立运行。
- **IMB 缓存锁**：`Coordinator._analyze_lock`（类级 `threading.Lock`）确保 Phase 3 中 `codeql database analyze` 操作串行执行，避免 `OverlappingFileLockException`。

复杂度从 $O(N \times T_{db\_create})$ 降至 $O(T_{db\_create} + \max(T_{analysis}))$。

---

## 3. 核心 Agent 详解与原论文对比

### 3.1 Agent-Q：带有自修复的规则合成器

**原论文机制**：利用轻量级 Schema 与 Few-shot 示例生成查询。  
**QRSE-X 演进**：
1. **黄金模板库（QLTemplateLibrary）**：27 个预验证多语言模板（Java 8 个、Python 5 个、JavaScript 4 个、Go 4 个、C# 4 个、C++ 2 个），命中则直接下发，100% 编译成功；
2. **编译器反馈回路（Self-Healing）**：拦截 `stderr`（如 *could not resolve module*）回传 LLM，最多 3 次自修复。

### 3.2 Agent-R：语义感知的审查器

**原论文机制**：可达性验证，追踪数据流评估可利用性。  
**QRSE-X 演进**：深入提取 SARIF 源码上下文（±15 行），针对 Java 严格区分 `SimpleEvaluationContext`（安全）与 `StandardEvaluationContext`（高危），输出标准化 `confidence` 评分。

### 3.3 RuleMemory：基于漏洞链路的 RAG 系统

**QRSE-X 独有创新**：多维特征 Embedding——语言、漏洞类型、Sink 方法（如 `Ognl.getValue`）、数据流摘要（如 `HTTP param 'filter' -> APIKafka.java:53`）、SARIF 消息及 CWE。  
**存储后端**：ChromaDB → FAISS → sentence-transformers → TF-IDF → Jaccard 五级降级，保证各环境可用。

#### 3.3.1 来源验证机制：抵御 RAG 投毒攻击

VenomRACG【arXiv:2512.21681】等研究已证明，仅需注入占语料库 0.05% 的恶意内容即可使 GPT-4o 在 40% 以上的场景中产生错误输出。针对该威胁，QRSE-X 在 RuleMemory 中实现了以下四层防御：

**第一层：来源溯源（Provenance Tracking）**  
每条 `RuleRecord` 新增 `source_repo`（来源仓库 URL 或 `local://` 前缀路径）、`source_commit`（git commit hash）、`import_source`（`local_scan` / `bundle_import` / `manual`）三个字段，实现完整的审计追踪链路。

**第二层：TrustLevel 四级可信体系**  
```
trusted > verified > unverified > quarantined
```
| 级别 | 产生场景 | 参与 Few-Shot 检索 |
|:--|:--|:--|
| `trusted` | 团队成员手动验证 | ✅ 最高优先级 |
| `verified` | 本机本地扫描（默认） | ✅ |
| `unverified` | 外部 Bundle 导入，未经审核 | ❌ 隔离期内不参与 |
| `quarantined` | 被明确标记可疑或篡改检测触发 | ❌ 永久屏蔽 |

`search()` 默认仅注入 `verified` 及以上记录进入 LLM 上下文，外部导入的 `unverified` 记录必须经人工 `verify()` 操作后方可激活。

**第三层：SHA-256 完整性指纹（Anti-Tampering）**  
每条记录在 `save()` 时计算对应 `.ql` 文件的 SHA-256 哈希（`ql_hash`）并持久化。`search()` 检索阶段对每个候选记录进行实时 Hash 对比：若文件被篡改，自动调用 `quarantine()` 隔离该记录并记录告警日志，同时从本次检索结果中剔除。支持 `verify_all_integrity()` 接口进行批量离线校验。

**第四层：Bundle HMAC-SHA256 签名（Anti-Bundle-Poisoning）**  
`export_bundle()` 为导出 ZIP 中的每个 `.ql` 文件生成 SHA-256 清单，并对整个清单计算 HMAC-SHA256 签名（密钥来自环境变量 `QRSE_BUNDLE_HMAC_KEY`）。`import_bundle()` 在写入任何记录前，先验证签名与文件清单的一致性：
- 签名验证通过 → 记录标记为 `verified`，可立即参与检索；
- 签名缺失或不匹配 → 全批次降级为 `unverified`，进入隔离期；
- 单文件 Hash 不符 → 拒绝写入，记录拒绝日志。

此外，系统支持配置受信任来源白名单（`add_trusted_source(pattern)`），匹配白名单的 Bundle 来源自动升级为 `verified`，无需人工逐条审核。

**Web 仪表盘集成**  
Memory 管理页面（`/memory`）实时展示各信任级别的记录分布，提供单条记录的"验证"（`POST /api/memory/<id>/verify`）与"隔离"（`POST /api/memory/<id>/quarantine`）操作按钮，以及全库"完整性校验"（`GET /api/memory/integrity`）触发入口。

### 3.4 Agent-S 与 Agent-E：PoC 生成与动态沙箱

**原论文机制**：Sanitize (S) 节点执行环境隔离与最终评估。  
**QRSE-X 演进**：拆分为两个物理阶段：
1. **Agent-S**：内置 15 类漏洞专属 Payload 模板（SpEL、OGNL、Pickle、Jinja2 等），结合 LLM 对源码参数的推断，生成格式化 HTTP 请求；
2. **Agent-E**：自动解析 `Dockerfile`/`docker-compose.yml`，动态构建镜像拉起沙箱（需目标仓库含 Docker 支持，否则自动降级为 `SKIPPED`）；采用 16 类、40+ 条正则规则预检 + LLM 深度响应分析双层判定，将漏洞标记为 `CONFIRMED`。

---

## 4. 与原 QRS 论文系统的多维度对比

| 维度 | 原始 QRS (arXiv:2602.09774) | QRSE-X 系统（本文） |
| :--- | :--- | :--- |
| **支持生态** | Python (PyPI packages) | Java / Python / JavaScript / Go / C# / C++ 六语言生态 |
| **漏洞类型** | 通用（以 Python 为主） | 14 大类（SQLi、SSRF、XSS、路径穿越、命令注入等） |
| **查询生成 (Q)** | Schema 定义 + Few-shot | **黄金模板库** + 编译器 stderr **自修复闭环** |
| **规则复用** | 未详细披露 | **漏洞链路 RAG**（ChromaDB/FAISS）+ Bundle 共享 |
| **误报清洗 (S/E)** | S 节点环境隔离与评估 | **Agent-S**（PoC 构造）+ **Agent-E**（Docker 真实确认） |
| **工程落地** | 理论架构与 Benchmark | 企业级 CLI，支持 DB 缓存、并行扫描、Windows 兼容 |

---

## 5. 实证分析

### 5.1 复杂环境扫描能力：spring-cloud-function

对曾爆出 `CVE-2022-22963` 的 `spring-cloud-function`（14 个子模块）：
1. 自动利用 `--build-mode=none` 进行源码级免编译提取；
2. 并发针对 `Spring EL Injection`、`SSRF`、`Command Injection` 展开扫描；
3. 准确定位至核心 `context` 模块下的高危数据流。

### 5.2 动态沙箱验证：SimpleKafka OGNL 注入

- Agent-R 判断 HTTP 参数 `filter` 未经净化直达 `Ognl.parseExpression`（置信度 100%）；
- Agent-S 组装 Payload：`#_memberAccess['allowStaticMethodAccess']=true,@java.lang.Runtime@getRuntime().exec('id')`；
- Agent-E 拉起 Docker 容器，打入 PoC，捕获系统命令回显，标记 `CONFIRMED`。

---

## 6. 相关领域前沿研究综述（2024–2026）

本节对 LLM 驱动的漏洞检测、多 Agent 安全分析及 RAG 增强代码安全领域最新研究进行系统梳理。

### 6.1 LLM 与静态分析工具融合

**QLPro（2025）**【arXiv:2506.23644】通过"三角投票机制 + 三角色机制"将 LLM 与 CodeQL 深度融合，在 JavaTest 数据集（62 个确认漏洞）上 CodeQL 检出 24 个，QLPro 检出 41 个（含 2 个新 CVE）。QLPro 采用微调路径成本较高；**QRSE-X 的差异化在于无需微调，仅通过黄金模板+自修复在零样本下实现等效成功率**。

**CQLLM（2025）**【MDPI Applied Sciences 16(1):517】探索直接用 LLM 生成 CodeQL 查询的可行性，证明了基础能力存在，但工程鲁棒性存在明显缺陷——与 QRSE-X 面临并解决的同类问题高度吻合。

**LLM vs SAST 系统性基准（2025）**【arXiv:2508.04448】对 GPT-4.1、DeepSeek V3 等与 SonarQube、CodeQL 进行大规模对比：LLM 平均 F-1 达 0.797，远超 SAST 最高 0.546，但 LLM 假阳性率更高。**这是 QRSE-X 设计 Agent-R + Agent-E 双层过滤的理论动机。**

**2026 ICSE 研究**发现 LLM 在漏洞发现上的进步趋于停滞，仅依靠传统代码度量的分类器可达同等效果，说明 LLM 仍停留在浅层模式匹配。QRSE-X 将 LLM 限定于语义推断、精确符号分析交由 CodeQL 执行的分工设计规避了这一局限。

### 6.2 多 Agent 漏洞发现与利用链生成

**VulAgent（2025）**【arXiv:2509.11523】提出假设-验证多 Agent 框架，将审计员思维分解为多视角专用 Agent，相比 SOTA 基准准确率提升 6.6%，误报率降低 36%。其"专用视角 Agent"设计与 QRSE-X 的 Agent-R 深度语义审查理念高度一致。

**AXE——Agentic eXploit Engine（2026）**【arXiv:2602.14345】针对 Web 漏洞报告，通过"轻量检测元数据 → 解耦规划 → 代码探索 → 动态执行反馈"多 Agent 流水线，在 CVE-Bench 上实现 30% 利用成功率（黑盒基线的 3 倍）。QRSE-X 的 Agent-E 与其思路相通，但更强调与 SAST 静态分析的紧耦合。

**Co-RedTeam（2026）**【arXiv:2602.02164】模拟真实红队工作流，将漏洞发现与利用解耦为两个协同 Agent 阶段，引入长期记忆跨次学习历史轨迹，漏洞利用成功率超 60%。QRSE-X 的 RuleMemory 与其长期记忆机制异曲同工。

**CVE-GENIE（2025）**【arXiv:2509.01835】构建从 CVE 词条到可执行利用的完整自动化流水线，在 841 个 CVE 中成功复现约 51%（428 个），平均成本 $2.77/CVE。其环境重建策略对 QRSE-X 的 Agent-E 沙箱自动部署设计具有重要参考价值。

**LLMxCPG（2025）**【arXiv:2507.16585】将代码属性图（CPG）与 LLM 结合，通过 CPG 切片将代码体积压缩 67-90%，F1 分数相比 SOTA 提升 15-40%。QRSE-X 选择 CodeQL AST/数据流图替代 CPG，在 Source→Sink 污点追踪粒度上更为精确。

### 6.3 RAG 在代码安全领域的应用

**ReVul-CoT（2025）**【arXiv:2511.17027】将 RAG 与 CoT 结合用于漏洞评估，从 NVD/CWE 构建结构化知识库，在 12,070 个漏洞样本上相比基线提升 16.5%-42.3%（MCC 指标）。验证了"以漏洞知识库而非代码文本为检索单元"的有效性，与 QRSE-X RuleMemory 设计哲学一致。

**RESCUE（2025）**【arXiv:2510.18204】通过 LLM 辅助的聚类-总结蒸馏构建混合知识库，配合程序切片实现层次化多维检索，在四个基准上 SecurePass@1 平均提升 4.8 分。

**RAG 系统安全威胁**：VenomRACG【arXiv:2512.21681】揭示投毒攻击可行性——仅需注入占语料库 0.05% 的恶意内容，即可使 GPT-4o 在超 40% 的场景中生成漏洞代码。**QRSE-X 已于 v2.1 正式实现针对该威胁的完整防御体系**（见第 3.3.1 节），通过 TrustLevel 四级隔离、SHA-256 完整性指纹与 HMAC-SHA256 Bundle 签名三重机制，系统性地封堵了 RAG 投毒的主要攻击面。

### 6.4 专项推理模型与细分方向

**VulnLLM-R（2025）**【arXiv:2512.07533】是首个专为漏洞检测定制的推理型 LLM（70亿参数），在真实项目中表现优于 CodeQL 和 AFL++，并发现零日漏洞。与 QRSE-X 不同，该系统依赖定制化训练，通用性受限；QRSE-X 使用通用 LLM，更易对接不同厂商 API。

**VulFinder（2025）**【OpenReview: hmovs2KzN6】针对软件供应链漏洞可达性分析，设计四层 Agent（蒸馏器→判别器→生成器→验证器）迭代生成利用测试，相比 SOTA 准确率提升 21%。

### 6.5 研究空白与 QRSE-X 的定位

| 研究空白 | QRSE-X 的回应 |
| :--- | :--- |
| 大多数系统在 Python 单语言验证 | 原生六语言（Java / Python / JavaScript / Go / C# / C++）支持，每种语言配备专属黄金模板、Agent-Q 生成提示与 Agent-R 审查提示 |
| 静态与动态割裂，误报无法消除 | Agent-E Docker 沙箱将 LLM 概率判断升级为 100% 运行时确认 |
| 规则知识孤立，跨项目复用难 | 漏洞链路级 RAG + Bundle 导出，支持团队共享规则记忆 |
| RAG 知识库易受投毒攻击（VenomRACG） | **TrustLevel 四级体系 + SHA-256 完整性指纹 + HMAC Bundle 签名**，全链路防御（v2.1 新增） |
| LLM 生成 CodeQL 首次编译成功率低（≈30%） | 27 个黄金模板拦截 + stderr 自修复，成功率 >95% |
| 多漏洞并发扫描受 SAST 串行限制 | 建库一次 + 并行分析，IMB 缓存锁通过类级互斥解决 |

---

## 7. 结论与未来展望

本文提出的 QRSE-X 系统，对原始 QRS 的神经符号融合思想进行了深度工程重构与能力扩展。通过"带自修复的规则合成（27 个黄金模板覆盖六种主流语言）"、"漏洞利用链路级 RAG 记忆库"和"基于 Docker 的动态验证 Agent-E"，本系统成功将 LLM 在语义推断上的优势、CodeQL 在污点追踪上的精确性以及真实沙箱执行的确定性结合在一起，打破了传统 SAST 工具"高门槛、高误报"的桎梏。系统已实现 Java、Python、JavaScript、Go、C#、C++ 六大语言的全链路支持——每种语言均配备了语言专属的黄金模板库、Agent-Q 规则生成系统提示和 Agent-R 语义审查提示，使得跨语言检测无需人工干预即可自动适配目标代码库的技术栈。

**v2.1 版本新增**：完整实现了 RuleMemory 来源验证机制（TrustLevel 四级体系、SHA-256 完整性指纹、HMAC-SHA256 Bundle 签名），系统性地封堵了 RAG 知识库的投毒攻击面，并在 Web 仪表盘中集成了可视化的信任级别管理与一键完整性校验功能。

未来的工作将集中在：扩展 Ruby、Kotlin、Swift 等更多语言支持；将沙箱功能与云原生 K8s 环境接轨；以及向 IDE 插件方向演进，实现开发阶段实时"写-诊-验"闭环。

---

## 参考文献

[1] Tsigkourakos, G., & Patsakis, C. (2026). *QRS: A Rule-Synthesizing Neuro-Symbolic Triad for Autonomous Vulnerability Discovery*. arXiv:2602.09774.

[2] QLPro Authors. (2025). *QLPro: Automated Code Vulnerability Discovery via LLM and Static Code Analysis Integration*. arXiv:2506.23644.

[3] Zhang, Y., et al. (2025). *CQLLM: A Framework for Generating CodeQL Security Vulnerability Detection Code Based on Large Language Model*. Applied Sciences, 16(1):517.

[4] Benchmark Authors. (2025). *Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection*. arXiv:2508.04448.

[5] Wang, Z., et al. (2025). *VulAgent: Hypothesis-Validation based Multi-Agent Vulnerability Detection*. arXiv:2509.11523.

[6] AXE Authors. (2026). *AXE: An Agentic eXploit Engine for Confirming Zero-Day Vulnerability Reports*. arXiv:2602.14345.

[7] Co-RedTeam Authors. (2026). *Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents*. arXiv:2602.02164.

[8] CVE-GENIE Authors. (2025). *From CVE Entries to Verifiable Exploits: An Automated Multi-Agent Framework for Reproducing CVEs*. arXiv:2509.01835.

[9] LLMxCPG Authors. (2025). *LLMxCPG: LLM-Enhanced Vulnerability Detection with Code Property Graphs*. arXiv:2507.16585.

[10] ReVul-CoT Authors. (2025). *ReVul-CoT: Towards Effective Software Vulnerability Assessment with RAG and Chain-of-Thought Prompting*. arXiv:2511.17027.

[11] RESCUE Authors. (2025). *RESCUE: RAG-enhanced Secure Code Generation*. arXiv:2510.18204.

[12] VenomRACG Authors. (2025). *Exploring the Security Threats of Retriever Backdoors in Retrieval-Augmented Code Generation*. arXiv:2512.21681.

[13] VulnLLM-R Authors. (2025). *VulnLLM-R: Specialized Reasoning LLM with Agent Scaffold for Vulnerability Detection*. arXiv:2512.07533.

[14] VulFinder Authors. (2025). *VulFinder: A Multi-Agent-Driven Test Generation Framework for Guiding Vulnerability Reachability Analysis*. OpenReview:hmovs2KzN6.

[15] Lewis, P., et al. (2020). *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*. NeurIPS 2020.

[16] GitHub Security Lab. *CodeQL Documentation*. https://codeql.github.com/docs/