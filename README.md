# Argus

Argus 是一个面向代码安全检测的多 Agent 协同系统，核心目标是将静态分析（CodeQL）与大模型语义审查、PoC 生成与动态验证结合，提升漏洞检测的准确率与可解释性。

## 核心能力

- 多 Agent 协同流水线：`Agent-Q`（规则生成）→ `Agent-R`（语义审查）→ `Agent-S`（PoC 生成）→ `Agent-E`（动态验证）。
- 支持本地目录与 GitHub 仓库两种输入模式。
- 支持单漏洞、多漏洞并行、自主模式（`--auto`）。
- 支持外部 SARIF 导入（可跳过 CodeQL 规则生成与扫描阶段）。
- 支持规则记忆库（Rule Memory）与可选 RAG 向量后端。
- 提供 Web API 服务用于任务调度、进度流式输出、结果查询与基准评估。

## 技术栈

- Python 3.10+
- CodeQL CLI
- Flask
- LangChain / OpenAI API
- scikit-learn（含 TF-IDF 回退向量能力）

## 快速开始

### 1) 环境准备

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

> 可选：安装更高性能向量后端（已在 `requirements.txt` 中给出）。

### 2) 配置环境变量

创建 `.env`（可参考 `.env.example`）：

```env
OPENAI_API_KEY=your_api_key
FLASK_SECRET_KEY=your_secret_key
ARGUS_API_KEY=optional_for_sensitive_api
```

### 3) 健康检查

```powershell
python -m src.main --check
```

### 4) 最小扫描示例

```powershell
python -m src.main --source-dir ./target --language java --vuln-type "Spring EL Injection"
```

### 5) GitHub 仓库扫描

```powershell
python -m src.main --github-url https://github.com/WebGoat/WebGoat --language java --vuln-type "Spring EL Injection"
```

### 6) 自主模式

```powershell
python -m src.main --source-dir ./target --auto
```

## Web API 服务

启动服务：

```powershell
python -m src.web.app --port 5001
```

常用接口（示例）：

- `GET /api/system/health`：系统健康状态
- `POST /api/scan/start`：启动扫描任务
- `GET /api/scan/stream/<task_id>`：SSE 流式日志/进度
- `GET /api/scan/status/<task_id>`：任务状态
- `GET /api/results`：历史结果列表
- `GET /api/templates`：模板库
- `GET /api/memory`：规则记忆库
- `GET /api/benchmark/presets`：评测预设

> 说明：服务已内置速率限制与基础安全响应头；部分敏感 API 可通过 `ARGUS_API_KEY` 保护。

## 常用 CLI 参数

- 基础模式
  - `--source-dir` / `--github-url`
  - `--language`
  - `--vuln-type` / `--vuln-types`
- 模式控制
  - `--auto`
  - `--external-sarif`
  - `--sca`
- 质量与性能
  - `--parallel-workers`
  - `--agent-r-workers`
  - `--agent-r-batch`
  - `--min-confidence`
- 规则记忆库
  - `--show-memory`
  - `--search-memory`
  - `--export-memory`
  - `--import-memory`

## 目录结构

```text
reV/
├─ src/
│  ├─ agents/            # Agent-Q/R/S/E 等
│  ├─ orchestrator/      # Coordinator 与事件总线
│  ├─ utils/             # CodeQL/记忆库/仓库管理等工具
│  ├─ web/               # Flask API 服务与前端资源
│  └─ main.py            # CLI 入口
├─ data/                 # 数据库、查询、结果、记忆库
├─ scripts/              # 辅助脚本（评测/处理）
├─ tests/                # 测试用例
├─ requirements.txt
└─ pyproject.toml
```

## 输出与产物

- CodeQL 数据库：`data/databases/`
- 规则查询文件：`data/queries/`
- 扫描结果：`data/results/`
- 规则记忆库：`data/rule_memory/`

## 测试

```powershell
pytest
```

支持标记：

- `requires_codeql`：需要本地安装 CodeQL CLI
- `requires_llm`：需要真实 LLM API Key

## 常见问题

- `OPENAI_API_KEY` 未设置：请检查 `.env` 或命令行 `--openai-api-key`。
- `codeql` 未找到：请将 CodeQL CLI 加入 `PATH`。
- 首次扫描慢：会创建数据库与初始化规则，属正常现象。
- Web 接口 429：命中限流，稍后重试或调整 `ARGUS_RATE_LIMIT`。

## 许可证

MIT

