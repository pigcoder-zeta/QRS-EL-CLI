# QRSE-X 系统架构文档

**版本**: v2.0  
**更新日期**: 2026-03-28  
**论文来源**: arXiv:2602.09774 《QRS: A Rule-Synthesizing Neuro-Symbolic Triad for Autonomous Vulnerability Discovery》

---

## 1. 系统概述

QRSE-X 是一个**多 Agent 协同的自动化漏洞检测系统**，专门针对 Java / Python 环境中的**表达式注入漏洞（EL Injection / SSTI）**。

系统将大语言模型（LLM）的语义理解能力与 CodeQL 静态分析引擎的精确性深度融合，实现从「输入 GitHub URL」到「输出漏洞研判报告」的全自动闭环，无需手动编写任何检测规则。

### 1.1 核心设计原则

| 原则 | 说明 |
|---|---|
| **神经符号融合** | LLM 负责语义理解与代码生成，CodeQL 负责精确的污点追踪 |
| **自修复闭环** | 编译失败时将报错信息反馈给 LLM 自动修复，最多重试 3 次 |
| **模板优先** | 已验证的 QL 模板优先于 LLM 生成，大幅提升首次成功率 |
| **增量缓存** | 基于 Git commit hash 跳过重复建库，节省 2-3 分钟 |

---

## 2. 系统架构

### 2.1 完整工作流

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户输入                                 │
│            GitHub URL  or  本地源码目录                          │
└─────────────────────┬───────────────────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │     Coordinator          │  调度中心，驱动五个阶段
          └────────────┬────────────┘
                       │
    ┌──────────────────┼──────────────────────┐
    │                  │                      │
    ▼                  ▼                      ▼
┌───────┐      ┌──────────────┐      ┌──────────────┐
│Phase 0│      │   Phase 1    │      │   Phase 2    │
│克隆仓库│      │  建CodeQL库  │      │  Agent-Q     │
│探测构建│      │（缓存命中跳过）│      │  生成.ql规则 │
└───────┘      └──────────────┘      └──────────────┘
                                              │
                              ┌───────────────┼──────────────────┐
                              │               │                  │
                              ▼               ▼                  ▼
                    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
                    │ 模板知识库   │  │  LLM 生成    │  │  自修复循环  │
                    │ (优先命中)  │  │  (未命中时)  │  │  (最多3次)  │
                    └──────────────┘  └──────────────┘  └──────────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │      Phase 3         │
                                    │   CodeQL 扫描        │
                                    │   输出 SARIF         │
                                    └──────────┬──────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │      Phase 4         │
                                    │     Agent-R          │
                                    │   语义审查误报过滤    │
                                    └──────────┬──────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │      Phase 5         │
                                    │     Agent-S          │
                                    │   PoC 生成（规划中） │
                                    └─────────────────────┘
```

### 2.2 数据流向

```
GitHub URL
  → [GithubRepoManager]   克隆仓库（depth=1），探测 pom.xml / build.gradle
  → [DatabaseCache]       查询 Git Hash 缓存，命中则跳过建库
  → [CodeQLRunner]        codeql database create（Maven/Gradle/autobuild）
  → [QLTemplateLibrary]   查询已验证 QL 模板（命中直接使用）
  → [AgentQ + LLM]        生成/修复 .ql 规则 → codeql query compile
  → [CodeQLRunner]        codeql database analyze → SARIF
  → [AgentR + LLM]        解析 SARIF → 读取源码上下文 → 语义研判
  → 最终报告（漏洞状态 / 置信度 / 推理说明）
```

---

## 3. 模块详细说明

### 3.1 `src/utils/codeql_runner.py` — CodeQL CLI 封装

| 方法 | 说明 |
|---|---|
| `create_database(source_dir, db_path, language, build_command?)` | 建立 CodeQL 数据库，可选传入构建命令 |
| `install_query_pack(query_dir)` | `codeql pack install`，下载 qlpack 依赖 |
| `compile_query(query_path)` | 编译验证 .ql 文件，返回 `(success, stderr)` |
| `analyze(db_path, query_path, output_sarif)` | 运行扫描，输出 SARIF |

**关键设计**：所有调用通过私有 `_run()` 方法统一处理超时（`subprocess.TimeoutExpired`）、可执行文件缺失（`FileNotFoundError`）、OS 错误三类异常。

---

### 3.2 `src/utils/repo_manager.py` — 仓库管理器

| 方法 | 说明 |
|---|---|
| `clone_repo(repo_url, dest_dir)` | 浅克隆（depth=1），线程超时控制，幂等设计 |
| `detect_build_command(repo_path, language)` | 探测 pom.xml / build.gradle，返回构建命令 |
| `get_repo_head_hash(repo_path)` | 返回 HEAD commit 的前 12 位 hash |
| `cleanup(repo_path)` | 安全删除克隆目录 |

**构建探测规则**：

| 文件 | 返回命令 |
|---|---|
| `pom.xml` | `mvn clean install -DskipTests` |
| `build.gradle` / `build.gradle.kts` | `gradle build -x test` |
| 均无 / Python | `""` （CodeQL autobuild） |

---

### 3.3 `src/utils/db_cache.py` — 数据库增量缓存

**缓存键**：`<repo_url>#<commit_hash>`  
**存储格式**：`data/databases/cache_index.json`

```json
{
  "https://github.com/xxx/yyy#a1b2c3d4e5f6": "data/databases/db_20260328_173639_1f33d6"
}
```

**命中条件**：相同 URL + 相同 commit hash + 数据库目录仍存在。重复扫描同一版本代码时，**Phase 1 直接跳过**，节省 Maven/Gradle 构建时间。

---

### 3.4 `src/utils/ql_template_library.py` — QL 模板知识库

存储经过本地 `codeql query compile` 实际验证的黄金模板。Agent-Q 优先命中此库，LLM 仅在无模板匹配时才从零生成。

**已内置模板**：

| 模板 Key | 漏洞类型 | 覆盖 Sink |
|---|---|---|
| `java/spring-el-injection` | Spring SpEL | `ExpressionParser.parseExpression` |
| `java/ognl-injection` | OGNL | `Ognl.getValue` / `Ognl.parseExpression` |
| `java/mvel-injection` | MVEL | `MVEL.eval` / `MVEL.executeExpression` |
| `java/el-injection` | 通用 EL（综合） | 以上三种 Sink 合并 |

**关键依赖**（已验证路径，基于 `codeql/java-all@9.0.2`）：
```ql
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources   ← RemoteFlowSource 在此
```

---

### 3.5 `src/agents/agent_q.py` — 规则合成 Agent

**核心算法：模板优先 + 自修复循环**

```
generate_and_compile(language, vuln_type)
  │
  ├─ 1. 查询 QLTemplateLibrary
  │      命中 → 直接使用已验证代码（跳过 LLM 初始生成）
  │      未命中 → LLM 基于黄金模板 Prompt 生成
  │
  ├─ 2. 写入 data/queries/<language>/<filename>.ql
  │      + 自动创建 qlpack.yml（声明 codeql/java-all 依赖）
  │      + 自动执行 codeql pack install
  │
  └─ 3. 自修复循环（最多 MAX_RETRIES=3 次）
         codeql query compile
           成功 → 返回文件路径 ✅
           失败 → stderr 反馈给 LLM → 覆写文件 → 再次编译
```

**Prompt 策略**：System Prompt 内嵌经过验证的「黄金模板」和 6 条关键规则（正确 import 路径、禁用废弃 API、正确类型名等），将 LLM 自由度限定在 Sink 逻辑的填充上。

---

### 3.6 `src/agents/agent_r.py` — 语义审查 Agent

**工作流**：
1. 解析 SARIF JSON，提取每条发现的文件路径 + 行号 + 消息
2. 读取发现行前后各 15 行源码上下文
3. 发送给 LLM 进行多维度审查
4. 解析返回的结构化 JSON 研判结论

**EL 注入专有审查维度**：

| 维度 | 说明 |
|---|---|
| 执行上下文 | `SimpleEvaluationContext`（安全）vs `StandardEvaluationContext`（危险） |
| 净化器识别 | 是否存在正则白名单、黑名单关键词过滤 |
| 执行逻辑 | 用户输入是被完整求值，还是仅作字面量安全拼接 |
| 权限控制 | 接口是否需要高权限访问（影响风险等级） |

**输出结构**：

```json
{
  "status": "vulnerable | safe | uncertain",
  "confidence": 0.95,
  "engine_detected": "Spring EL",
  "reasoning": "输入未净化直接进入 StandardEvaluationContext...",
  "sink_method": "org.springframework.expression.ExpressionParser.parseExpression"
}
```

---

### 3.7 `src/agents/agent_s.py` — PoC 生成 Agent（规划中）

**内置 Payload 策略库**（Phase 5 实现）：

| 引擎 | Payload 示例 |
|---|---|
| SpEL | `T(java.lang.Runtime).getRuntime().exec(...)` |
| OGNL | `@java.lang.Runtime@getRuntime().exec("id")` |
| Jinja2 | `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}` |
| Mako | `${__import__('os').popen('id').read()}` |

---

### 3.8 `src/orchestrator/coordinator.py` — 调度中心

```python
PipelineConfig(
    github_url = "https://github.com/...",   # 或 source_dir
    language   = "java",
    vuln_type  = "Spring EL Injection",
    enable_agent_r = True,                   # 是否启用语义审查
    agent_r_min_confidence = 0.6,            # 置信度过滤阈值
    cleanup_workspace = True,                # 扫描后清理克隆目录
)
```

`PipelineState` 记录每个阶段的产物：

| 字段 | 说明 |
|---|---|
| `run_id` | 时间戳 + UUID，格式 `20260328_172659_671445` |
| `commit_hash` | 仓库 HEAD commit 短 hash |
| `db_from_cache` | 是否命中数据库缓存 |
| `sarif_path` | SARIF 结果文件路径 |
| `review_results` | Agent-R 审查结论列表 |
| `vulnerable_findings` | 筛选后的真实漏洞列表（属性） |

---

## 4. 项目目录结构

```
reV/
├── architecture.md              ← 本文档
├── requirements.txt             ← Python 依赖
├── .env                         ← API Key（不入 Git）
├── .env.example                 ← 配置模板
├── .gitignore
│
├── src/
│   ├── main.py                  ← CLI 入口（argparse）
│   │
│   ├── utils/
│   │   ├── codeql_runner.py     ← CodeQL CLI 封装
│   │   ├── repo_manager.py      ← GitHub 克隆 + 构建探测
│   │   ├── db_cache.py          ← 数据库增量缓存
│   │   └── ql_template_library.py ← 已验证 QL 模板知识库
│   │
│   ├── agents/
│   │   ├── agent_q.py           ← 规则合成（模板优先 + 自修复）
│   │   ├── agent_r.py           ← 语义审查（SARIF → LLM 研判）
│   │   └── agent_s.py           ← PoC 生成（Phase 5 规划中）
│   │
│   └── orchestrator/
│       └── coordinator.py       ← 工作流调度（5 阶段 Pipeline）
│
└── data/
    ├── databases/               ← CodeQL 数据库
    │   └── cache_index.json     ← 增量缓存索引
    ├── workspaces/              ← GitHub 克隆临时目录（自动清理）
    ├── queries/
    │   └── java/
    │       ├── qlpack.yml       ← CodeQL 包依赖声明
    │       └── *.ql             ← 生成的查询文件
    └── results/                 ← SARIF 扫描结果
```

---

## 5. 技术栈

| 层次 | 技术 |
|---|---|
| 核心语言 | Python 3.10+ |
| LLM 编排 | LangChain（`langchain`, `langchain-openai`, `langchain-core`） |
| 大语言模型 | 任意 OpenAI 兼容接口（Gemini / GPT-4o / Claude 等） |
| 静态分析引擎 | CodeQL CLI v2.15+（已测试 v2.23.7） |
| CodeQL 标准库 | `codeql/java-all@9.0.2` |
| 数据交换格式 | SARIF（CodeQL 标准输出）、JSON |
| Git 操作 | GitPython 3.1+ |
| 数据模型 | Pydantic v2 |

---

## 6. 快速开始

### 6.1 环境准备

```bash
# 1. 安装 Python 依赖
pip install -r requirements.txt

# 2. 配置 API Key
cp .env.example .env
# 编辑 .env，填写 OPENAI_API_KEY / OPENAI_BASE_URL / OPENAI_MODEL

# 3. 确认 CodeQL CLI 已安装
codeql --version
```

### 6.2 运行（GitHub 模式）

```powershell
# 自动克隆 + 建库 + 生成规则 + 扫描 + 语义审查
python -m src.main `
  --github-url https://github.com/j3ers3/Hello-Java-Sec `
  --language java `
  --vuln-type "Spring EL Injection"

# 跳过 Agent-R（节省 LLM 费用）
python -m src.main `
  --github-url https://github.com/xxx/yyy `
  --language java `
  --vuln-type "Spring EL Injection" `
  --no-agent-r

# 第二次扫描同一仓库（自动命中数据库缓存）
python -m src.main `
  --github-url https://github.com/j3ers3/Hello-Java-Sec `
  --language java `
  --vuln-type "OGNL Injection"
```

### 6.3 运行（本地目录模式）

```powershell
python -m src.main `
  --source-dir C:\path\to\project `
  --language java `
  --vuln-type "Spring EL Injection"
```

### 6.4 全部 CLI 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--github-url` / `--source-dir` | — | 输入源（必填，二选一） |
| `--language` | — | 目标语言（必填） |
| `--vuln-type` | — | 漏洞类型描述（必填） |
| `--sink-hints` | 内置 | 自定义 Sink 方法列表 |
| `--codeql-path` | `codeql` | CodeQL 可执行文件路径 |
| `--max-retries` | `3` | Agent-Q 自修复最大次数 |
| `--no-agent-r` | 关闭 | 跳过 Agent-R 语义审查 |
| `--min-confidence` | `0.6` | Agent-R 置信度过滤阈值 |
| `--no-cleanup` | 关闭 | 保留克隆目录（调试用） |
| `--workspace-dir` | `data/workspaces` | 克隆临时目录 |
| `--db-dir` | `data/databases` | 数据库目录 |
| `--results-dir` | `data/results` | SARIF 结果目录 |
| `--verbose` | 关闭 | 输出 DEBUG 级别日志 |

---

## 7. 实测结果

**目标仓库**：[j3ers3/Hello-Java-Sec](https://github.com/j3ers3/Hello-Java-Sec)（Java 漏洞靶场）

| 阶段 | 耗时 | 结果 |
|---|---|---|
| Phase 0：克隆仓库 | ~4 秒 | 探测到 pom.xml → Maven 构建 |
| Phase 1：创建 CodeQL 数据库 | ~2 分钟 | 成功，第二次命中缓存跳过 |
| Phase 2：Agent-Q 生成规则 | ~8 秒（模板命中） | 首次编译通过 |
| Phase 3：CodeQL 扫描 | ~28 秒 | 发现 **3 处** SpEL 注入 |
| Phase 4：Agent-R 审查 | ~25 秒 | 3 条发现语义研判完成 |

**发现的漏洞位置**：

```
SpEL.java:42   ← 第 1 处 Spring EL 注入
SpEL.java:63   ← 第 2 处 Spring EL 注入
SpEL.java:75   ← 第 3 处 Spring EL 注入
```

---

## 8. 开发路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| Phase 1 | CodeQL CLI 封装、基础设施搭建 | ✅ 完成 |
| Phase 2 | Agent-Q 规则合成 + 自修复循环 | ✅ 完成 |
| Phase 3 | GitHub 自动克隆 + 构建探测 | ✅ 完成 |
| Phase 3+ | QL 模板知识库 + 数据库增量缓存 | ✅ 完成 |
| Phase 4 | Agent-R 语义审查 + 误报过滤 | ✅ 完成 |
| Phase 5 | Agent-S PoC 生成与验证 | 🔧 规划中 |
| Phase 6 | 向量化规则记忆库（成功 .ql → Embedding） | 🔧 规划中 |
| Phase 7 | 多漏洞类型并行扫描 | 🔧 规划中 |
| Phase 8 | WebGoat / Vulhub 端到端测试与调优 | ⏳ 待开始 |
