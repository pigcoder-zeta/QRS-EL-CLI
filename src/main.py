"""
QRSE-X 系统 CLI 入口。

支持四种扫描模式：
  # 本地目录 · 单漏洞类型
  python -m src.main --source-dir ./target --language java --vuln-type "Spring EL Injection"

  # GitHub URL（自动克隆 + 构建探测）
  python -m src.main --github-url https://github.com/WebGoat/WebGoat `
      --language java --vuln-type "Spring EL Injection"

  # 多漏洞并行扫描（建库一次，共享数据库）
  python -m src.main --github-url https://github.com/WebGoat/WebGoat `
      --language java --vuln-types "Spring EL Injection" "OGNL Injection" "MVEL Injection"

  # Agent-P 自主模式（自动侦察 → 规划 → 执行 → 评估）
  python -m src.main --source-dir ./target --auto

  # 环境健康检查
  python -m src.main --check
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from dotenv import load_dotenv
from rich.console import Console

if TYPE_CHECKING:
    from src.orchestrator.coordinator import PipelineConfig, PipelineState
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

load_dotenv()

console = Console()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 日志配置（rich 处理器）
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool) -> None:
    """配置日志：非 verbose 时隐藏 DEBUG，并屏蔽 rich 的重复输出。"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )
    # 降低第三方库的日志噪音
    for noisy in ("httpx", "openai", "httpcore", "git"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# 环境健康检查
# ---------------------------------------------------------------------------


def _list_templates() -> None:
    """列出所有内置 QL 模板，以富文本表格展示。"""
    from src.utils.ql_template_library import _ALL_TEMPLATES

    table = Table(
        title="[bold cyan]QRSE-X 内置 QL 规则模板[/bold cyan]",
        box=box.ROUNDED, show_header=True, header_style="bold magenta",
    )
    table.add_column("Key",         style="cyan",  no_wrap=True)
    table.add_column("语言",        width=10)
    table.add_column("漏洞类型关键词", width=14)
    table.add_column("描述",        style="dim")

    for tmpl in _ALL_TEMPLATES:
        lang_color = "green" if tmpl.language == "java" else "blue"
        table.add_row(
            tmpl.key,
            f"[{lang_color}]{tmpl.language}[/{lang_color}]",
            tmpl.vuln_type,
            tmpl.description,
        )

    console.print(table)
    console.print(
        f"\n  共 [bold]{len(_ALL_TEMPLATES)}[/bold] 个内置模板。"
        "使用 [cyan]--vuln-type[/cyan] 指定漏洞类型时，"
        "系统会自动匹配最合适的模板。\n"
    )


def _apply_yaml_config(args: argparse.Namespace) -> None:
    """
    从 YAML 配置文件加载参数，仅覆盖 CLI 中未显式设置的项。

    YAML 示例（qrs-el.yml）：
      language: java
      vuln_type: Spring EL Injection
      github_url: https://github.com/WebGoat/WebGoat
      max_retries: 5
      min_confidence: 0.7
      no_agent_s: true
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        console.print("[yellow]警告：未安装 PyYAML，忽略 --config 参数。"
                      "运行 pip install pyyaml 安装。[/yellow]")
        return

    config_path = Path(args.config)
    if not config_path.exists():
        console.print(f"[red]配置文件不存在: {args.config}[/red]")
        sys.exit(1)

    try:
        with open(config_path, encoding="utf-8") as fh:
            cfg: dict = yaml.safe_load(fh) or {}
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]配置文件解析失败: {exc}[/red]")
        sys.exit(1)

    # 只覆盖默认值（CLI 显式传入的参数优先）
    _yaml_to_arg(args, cfg, "language",          "language")
    _yaml_to_arg(args, cfg, "vuln_type",         "vuln_type")
    _yaml_to_arg(args, cfg, "vuln_types",        "vuln_types")
    _yaml_to_arg(args, cfg, "source_dir",        "source_dir")
    _yaml_to_arg(args, cfg, "github_url",        "github_url")
    _yaml_to_arg(args, cfg, "sink_hints",        "sink_hints")
    _yaml_to_arg(args, cfg, "max_retries",       "max_retries")
    _yaml_to_arg(args, cfg, "min_confidence",    "min_confidence")
    _yaml_to_arg(args, cfg, "parallel_workers",  "parallel_workers")
    _yaml_to_arg(args, cfg, "output_json",       "output_json")
    _yaml_to_arg(args, cfg, "no_agent_r",        "no_agent_r")
    _yaml_to_arg(args, cfg, "no_agent_s",        "no_agent_s")
    _yaml_to_arg(args, cfg, "no_rule_memory",    "no_rule_memory")
    _yaml_to_arg(args, cfg, "codeql_path",       "codeql_path")
    logger.info("[Config] 已从 %s 加载配置", args.config)


def _yaml_to_arg(
    args: argparse.Namespace, cfg: dict, yaml_key: str, arg_key: str
) -> None:
    """若 args 中对应属性仍为默认值（None / False），则从 cfg 中覆盖。"""
    if yaml_key not in cfg:
        return
    current = getattr(args, arg_key, None)
    if current is None or current is False:
        setattr(args, arg_key, cfg[yaml_key])


def _run_check() -> None:
    """检查运行 QRSE-X 所需的关键依赖是否就绪。"""
    console.print(Panel("[bold cyan]QRSE-X 环境健康检查[/bold cyan]", expand=False))

    checks: list[tuple[str, bool, str]] = []

    # Python 版本
    major, minor = sys.version_info[:2]
    ok = major >= 3 and minor >= 10
    checks.append(("Python ≥ 3.10", ok, f"{major}.{minor}.{sys.version_info.micro}"))

    # CodeQL CLI
    codeql_bin = shutil.which("codeql")
    ok = codeql_bin is not None
    detail = codeql_bin or "未找到（请将 CodeQL CLI 目录加入 PATH）"
    checks.append(("CodeQL CLI", ok, detail))

    if codeql_bin:
        try:
            result = subprocess.run(
                ["codeql", "version", "--format=terse"],
                capture_output=True, text=True, timeout=10,
            )
            ver = result.stdout.strip().splitlines()[0] if result.returncode == 0 else "未知"
        except Exception:
            ver = "版本获取失败"
        checks.append(("  └ CodeQL 版本", True, ver))

    # Git
    git_bin = shutil.which("git")
    checks.append(("Git", git_bin is not None, git_bin or "未找到"))

    # API Key
    api_key = os.environ.get("OPENAI_API_KEY", "")
    key_ok = bool(api_key)
    checks.append((
        "OPENAI_API_KEY",
        key_ok,
        f"已设置（...{api_key[-6:]}）" if key_ok else "未设置（需在 .env 中配置）",
    ))

    # Python 包检查（核心包）
    for pkg, import_name in [
        ("langchain-openai", "langchain_openai"),
        ("GitPython",        "git"),
        ("scikit-learn",     "sklearn"),
        ("rich",             "rich"),
    ]:
        try:
            __import__(import_name)
            checks.append((f"  pkg: {pkg}", True, "已安装"))
        except ImportError:
            checks.append((f"  pkg: {pkg}", False, "未安装（pip install " + pkg + "）"))

    # RAG 向量后端检查（可选，自动降级）
    rag_backend_name = "tfidf（默认回退）"
    for rag_pkg, rag_import, rag_label in [
        ("chromadb",              "chromadb",             "ChromaDB"),
        ("faiss-cpu",             "faiss",                "FAISS"),
        ("sentence-transformers", "sentence_transformers","sentence-transformers"),
    ]:
        try:
            __import__(rag_import)
            rag_backend_name = rag_label
            break  # 找到最优后端即停止
        except ImportError:
            pass
    checks.append(("  RAG 向量后端", True, f"当前最优: {rag_backend_name}（可 pip install chromadb 升级）"))

    # data 目录
    for d in ["data/databases", "data/queries", "data/results", "data/rule_memory"]:
        exists = Path(d).exists()
        checks.append((f"  dir: {d}", exists, "存在" if exists else "不存在（将在首次运行时自动创建）"))

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("检查项", style="cyan", no_wrap=True)
    table.add_column("状态", justify="center")
    table.add_column("详情", style="dim")

    all_pass = True
    for name, ok, detail in checks:
        icon = "[green]✔[/green]" if ok else "[red]✘[/red]"
        if not ok:
            all_pass = False
        table.add_row(name, icon, detail)

    console.print(table)

    # 显示历史扫描统计
    try:
        from src.utils.scan_history import ScanHistory
        hist = ScanHistory()
        if hist.count() > 0:
            s = hist.stats()
            console.print(
                f"\n  [dim]历史扫描记录: {s['total_runs']} 次 | "
                f"成功 {s['success_runs']} | "
                f"累计发现漏洞 {s['total_vulnerabilities_found']} 处 | "
                f"缓存命中 {s['db_cache_hits']} 次[/dim]"
            )
    except Exception:  # noqa: BLE001
        pass

    # 显示规则记忆库统计
    try:
        from src.utils.rule_memory import RuleMemory
        mem = RuleMemory()
        count = mem.count()
        backend = mem.get_backend_name()
        if count > 0:
            console.print(
                f"  [dim]规则记忆库: {count} 条规则已归档 | "
                f"向量后端: [bold]{backend}[/bold][/dim]"
            )
        else:
            console.print(
                f"  [dim]规则记忆库: 空（首次扫描成功后自动填充）| "
                f"向量后端: [bold]{backend}[/bold][/dim]"
            )
    except Exception:  # noqa: BLE001
        pass

    if all_pass:
        console.print("[bold green]所有检查通过，环境就绪！[/bold green]")
    else:
        console.print("[bold red]部分检查未通过，请按提示修复后再运行扫描。[/bold red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# 规则记忆库管理命令
# ---------------------------------------------------------------------------


def _show_memory(memory_dir: str = "data/rule_memory") -> None:
    """展示规则记忆库中所有已归档的规则。"""
    from src.utils.rule_memory import RuleMemory

    mem = RuleMemory(memory_dir=memory_dir)
    console.print(
        Panel(
            f"[bold cyan]QRSE-X 规则记忆库[/bold cyan]  "
            f"[dim]共 {mem.count()} 条规则 | 向量后端: {mem.get_backend_name()}[/dim]",
            expand=False,
        )
    )

    if mem.count() == 0:
        console.print("[dim]记忆库为空。完成第一次成功扫描后规则将自动归档。[/dim]")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta", expand=True)
    table.add_column("#",         style="dim",   width=4,  no_wrap=True)
    table.add_column("语言",       style="cyan",  width=8,  no_wrap=True)
    table.add_column("漏洞类型",   style="yellow", width=22, no_wrap=True)
    table.add_column("Sink 方法",  style="green",  width=28, no_wrap=True)
    table.add_column("数据流摘要", style="dim",    min_width=20)
    table.add_column("CWE",        style="red",   width=9,  no_wrap=True)
    table.add_column("归档时间",   style="dim",   width=20, no_wrap=True)

    for i, record in enumerate(mem._records.values(), 1):
        flow = record.data_flow_summary
        if len(flow) > 60:
            flow = flow[:57] + "..."
        table.add_row(
            str(i),
            record.language,
            record.vuln_type,
            record.sink_method or "—",
            flow or "—",
            record.cwe or "—",
            record.created_at[:16].replace("T", " "),
        )

    console.print(table)
    console.print(
        f"\n[dim]规则文件目录: {memory_dir}/rules/  "
        f"索引文件: {memory_dir}/rule_memory_index.json[/dim]"
    )


def _search_memory(query: str, memory_dir: str = "data/rule_memory") -> None:
    """
    对规则记忆库执行语义搜索。

    查询格式示例：
      "SQL Injection java"
      "命令注入 python eval"
    """
    from src.utils.rule_memory import RuleMemory

    mem = RuleMemory(memory_dir=memory_dir)
    console.print(
        Panel(
            f"[bold cyan]语义搜索规则记忆库[/bold cyan]  "
            f"[dim]查询: \"{query}\" | 后端: {mem.get_backend_name()}[/dim]",
            expand=False,
        )
    )

    if mem.count() == 0:
        console.print("[dim]记忆库为空，无可搜索内容。[/dim]")
        return

    # 从查询中推断语言
    lang_tokens = {"java", "python", "javascript", "go", "csharp", "cpp"}
    detected_lang = ""
    for tok in query.lower().split():
        if tok in lang_tokens:
            detected_lang = tok
            break

    results = mem.search(
        language=detected_lang,
        vuln_type=query,
        top_k=5,
    )

    if not results:
        console.print("[yellow]未找到匹配规则。[/yellow]")
        return

    console.print(f"找到 [bold]{len(results)}[/bold] 条相似规则：\n")
    for rank, (record, score) in enumerate(results, 1):
        score_color = "green" if score > 0.7 else "yellow" if score > 0.4 else "dim"
        console.print(
            f"  [{rank}] [{score_color}]相似度 {score:.2%}[/{score_color}]  "
            f"[cyan]{record.language}[/cyan] / [yellow]{record.vuln_type}[/yellow]"
        )
        if record.sink_method:
            console.print(f"       Sink: [green]{record.sink_method}[/green]")
        if record.data_flow_summary:
            summary = record.data_flow_summary[:100] + ("..." if len(record.data_flow_summary) > 100 else "")
            console.print(f"       数据流: [dim]{summary}[/dim]")
        if record.cwe:
            console.print(f"       CWE: [red]{record.cwe}[/red]")
        console.print(f"       文件: [dim]{record.query_path}[/dim]\n")


def _clear_memory(memory_dir: str = "data/rule_memory") -> None:
    """清空规则记忆库（需要用户二次确认）。"""
    import shutil as _shutil

    mem_path = Path(memory_dir)
    if not mem_path.exists():
        console.print("[dim]规则记忆库目录不存在，无需清空。[/dim]")
        return

    console.print(
        f"[bold red]警告：即将删除规则记忆库目录 {memory_dir} 及其所有内容！[/bold red]"
    )
    confirm = console.input("确认清空？输入 [bold]yes[/bold] 继续，其他任意键取消: ")
    if confirm.strip().lower() != "yes":
        console.print("[dim]已取消。[/dim]")
        return

    _shutil.rmtree(mem_path, ignore_errors=True)
    console.print("[green]规则记忆库已清空。[/green]")


def _export_memory(output_path: str, memory_dir: str = "data/rule_memory") -> None:
    """将规则记忆库打包为 ZIP Bundle。"""
    from src.utils.rule_memory import RuleMemory

    mem = RuleMemory(memory_dir=memory_dir)
    if mem.count() == 0:
        console.print("[yellow]规则记忆库为空，无需导出。[/yellow]")
        return

    out = mem.export_bundle(output_path)
    console.print(
        f"[green]导出成功！[/green] 共 [bold]{mem.count()}[/bold] 条规则 → [cyan]{out}[/cyan]"
    )
    console.print("[dim]可在其他机器上使用 --import-memory 导入此 Bundle。[/dim]")


def _import_memory(bundle_path: str, memory_dir: str = "data/rule_memory") -> None:
    """从 ZIP Bundle 导入规则记忆库（合并模式）。"""
    from src.utils.rule_memory import RuleMemory

    mem = RuleMemory(memory_dir=memory_dir)
    try:
        count = mem.import_bundle(bundle_path, merge=True)
        console.print(
            f"[green]导入成功！[/green] 新增 [bold]{count}[/bold] 条规则，"
            f"库中共 [bold]{mem.count()}[/bold] 条。"
        )
    except FileNotFoundError as exc:
        console.print(f"[red]错误：{exc}[/red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI 参数解析
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qrs-el",
        description="QRSE-X：多 Agent 协同的 CodeQL 规则自动生成与表达式注入漏洞检测系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  python -m src.main --check
  python -m src.main --source-dir ./target --language java --vuln-type "Spring EL Injection"
  python -m src.main --github-url https://github.com/WebGoat/WebGoat \\
      --language java --vuln-types "Spring EL Injection" "OGNL Injection"
        """,
    )

    # ── 特殊模式 ─────────────────────────────────────────────────────────
    parser.add_argument(
        "--check",
        action="store_true",
        help="运行环境健康检查后退出（不执行扫描）",
    )
    parser.add_argument(
        "--list-templates",
        action="store_true",
        help="列出所有内置 QL 规则模板后退出",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="从 YAML 配置文件加载参数（会被 CLI 参数覆盖）",
    )

    # ── 输入源（二选一）──────────────────────────────────────────────────
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--source-dir", metavar="PATH",
        help="本地源码根目录路径",
    )
    input_group.add_argument(
        "--github-url", metavar="URL",
        help="GitHub 仓库 URL（自动克隆 + 构建探测）",
    )

    # ── 分析参数 ─────────────────────────────────────────────────────────
    parser.add_argument(
        "--language",
        choices=["java", "python", "javascript", "go", "csharp", "cpp"],
        help="目标编程语言",
    )
    vuln_group = parser.add_mutually_exclusive_group()
    vuln_group.add_argument(
        "--vuln-type", metavar="TYPE",
        help='单漏洞类型，如 "Spring EL Injection"',
    )
    vuln_group.add_argument(
        "--vuln-types", nargs="+", metavar="TYPE",
        help='多漏洞并行扫描，空格分隔',
    )

    # ── 可选参数 ─────────────────────────────────────────────────────────
    parser.add_argument("--sink-hints", default=None, metavar="HINTS")
    parser.add_argument("--codeql-path", default="codeql", metavar="PATH")
    parser.add_argument("--workspace-dir", default="data/workspaces", metavar="DIR")
    parser.add_argument("--db-dir", default="data/databases", metavar="DIR")
    parser.add_argument("--results-dir", default="data/results", metavar="DIR")
    parser.add_argument("--queries-dir", default="data/queries", metavar="DIR")
    parser.add_argument("--rule-memory-dir", default="data/rule_memory", metavar="DIR")
    parser.add_argument("--max-retries", type=int, default=3, metavar="N")
    parser.add_argument("--parallel-workers", type=int, default=3, metavar="N")
    parser.add_argument("--min-confidence", type=float, default=0.6, metavar="FLOAT")
    parser.add_argument(
        "--output-json", default=None, metavar="PATH",
        help="将扫描结果导出为 JSON 文件（如 data/results/report.json）",
    )
    parser.add_argument(
        "--output-html", default=None, metavar="PATH",
        help="将扫描结果导出为 HTML 报告（如 data/results/report.html）",
    )
    parser.add_argument("--no-cleanup", action="store_true")
    parser.add_argument("--no-agent-r", action="store_true")
    parser.add_argument("--no-agent-s", action="store_true")
    parser.add_argument("--no-agent-e", action="store_true",
                        help="禁用 Agent-E 动态沙箱验证（默认开启）")
    parser.add_argument(
        "--agent-e-host", default=None, metavar="URL",
        help="已运行目标的地址（如 http://localhost:8080），使用 Remote 模式而非 Docker 沙箱",
    )
    parser.add_argument("--no-rule-memory", action="store_true")
    parser.add_argument(
        "--no-build", action="store_true",
        help="跳过项目编译（CodeQL --build-mode=none），适合构建环境不完整或大型 Java 项目",
    )
    parser.add_argument(
        "--codeql-db", default=None, metavar="PATH",
        help="指定已存在的 CodeQL 数据库路径，跳过建库阶段（如 data/databases/benchmark_db）",
    )
    parser.add_argument(
        "--agent-r-workers", type=int, default=1, metavar="N",
        help="Agent-R 并发线程数（默认 1 串行，建议 2~4）",
    )
    parser.add_argument(
        "--agent-r-batch", type=int, default=1, metavar="N",
        help="Agent-R 每次 LLM 调用包含的 finding 数（默认 1 逐条，建议 5~10 可大幅加速）",
    )
    # ── 外部 SARIF 导入（IaC/第三方工具结果）──────────────────────────
    parser.add_argument(
        "--external-sarif", default=None, metavar="PATH",
        help="导入外部 SARIF 文件（Checkov/tfsec/Trivy/Semgrep 等输出），跳过 Agent-Q + CodeQL 阶段，直接进入 Agent-R 审查",
    )
    # ── 供应链安全分析 ──────────────────────────────────────────────
    parser.add_argument(
        "--sca", action="store_true",
        help="启用供应链安全分析（SCA）：解析依赖 → OSV漏洞查询 → Typosquatting检测",
    )
    # ── 二进制/固件分析 ─────────────────────────────────────────────
    parser.add_argument(
        "--firmware", default=None, metavar="PATH",
        help="固件镜像路径，启用 Binwalk 解包 + 二进制分析流水线",
    )
    parser.add_argument(
        "--ghidra-home", default=None, metavar="PATH",
        help="Ghidra 安装目录（用于二进制反编译分析）",
    )
    # ── Agent-P 自主模式 ──────────────────────────────────────────────
    parser.add_argument(
        "--auto", action="store_true",
        help="启用 Agent-P 自主模式：自动侦察仓库 → 规划扫描策略 → 多轮执行 → 评估自适应。无需指定 --vuln-type",
    )
    # ── Patch-Aware 模式（受 K-REPRO 启发）──────────────────────────
    parser.add_argument(
        "--patch-commit", default=None, metavar="HASH",
        help="修复补丁的 commit hash，自动切换到漏洞版本扫描（Patch-Aware 模式）",
    )
    parser.add_argument(
        "--no-code-browser", action="store_true",
        help="禁用 Agent-R 的 CodeBrowser 智能上下文（降级为固定 ±15 行窗口）",
    )

    parser.add_argument("--openai-api-key", default=None, metavar="KEY")
    parser.add_argument("--verbose", action="store_true")

    # ── 规则记忆库管理 ────────────────────────────────────────────────
    parser.add_argument(
        "--show-memory",
        action="store_true",
        help="展示规则记忆库中所有已归档的规则（含漏洞链路摘要）",
    )
    parser.add_argument(
        "--search-memory",
        metavar="QUERY",
        default=None,
        help='语义搜索规则记忆库，如 --search-memory "SQL Injection java"',
    )
    parser.add_argument(
        "--clear-memory",
        action="store_true",
        help="清空规则记忆库（谨慎使用，将删除所有已归档规则）",
    )
    parser.add_argument(
        "--export-memory",
        metavar="PATH",
        default=None,
        help="将规则记忆库导出为 ZIP Bundle（如 data/memory_bundle.zip）",
    )
    parser.add_argument(
        "--import-memory",
        metavar="PATH",
        default=None,
        help="从 ZIP Bundle 导入规则记忆库（默认合并模式）",
    )

    return parser


# ---------------------------------------------------------------------------
# 主函数
# ---------------------------------------------------------------------------


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    _configure_logging(args.verbose)

    # ── 健康检查模式 ──────────────────────────────────────────────────
    if args.check:
        _run_check()
        return

    # ── 列出模板 ──────────────────────────────────────────────────────
    if args.list_templates:
        _list_templates()
        return

    # ── 规则记忆库：展示所有规则 ──────────────────────────────────────
    if args.show_memory:
        _show_memory(args.rule_memory_dir)
        return

    # ── 规则记忆库：语义搜索 ──────────────────────────────────────────
    if args.search_memory:
        _search_memory(args.search_memory, args.rule_memory_dir)
        return

    # ── 规则记忆库：清空 ──────────────────────────────────────────────
    if args.clear_memory:
        _clear_memory(args.rule_memory_dir)
        return

    # ── 规则记忆库：导出 Bundle ───────────────────────────────────────
    if args.export_memory:
        _export_memory(args.export_memory, args.rule_memory_dir)
        return

    # ── 规则记忆库：导入 Bundle ───────────────────────────────────────
    if args.import_memory:
        _import_memory(args.import_memory, args.rule_memory_dir)
        return

    # ── YAML 配置文件（优先级低于 CLI 参数）──────────────────────────
    if args.config:
        _apply_yaml_config(args)

    # ── 常规扫描：校验必填参数 ────────────────────────────────────────
    if not args.source_dir and not args.github_url:
        parser.error("扫描模式下必须提供 --source-dir 或 --github-url")
    if not args.language and not getattr(args, "auto", False):
        parser.error("必须提供 --language（或使用 --auto 自动推断）")
    if not args.vuln_type and not args.vuln_types and not getattr(args, "auto", False):
        parser.error("必须提供 --vuln-type 或 --vuln-types（或使用 --auto 自主模式）")

    # ── API Key ───────────────────────────────────────────────────────
    if args.openai_api_key:
        os.environ["OPENAI_API_KEY"] = args.openai_api_key
    if not os.environ.get("OPENAI_API_KEY"):
        console.print(
            "[red]错误：未设置 OPENAI_API_KEY，请在 .env 文件中配置或"
            "通过 --openai-api-key 传入。[/red]"
        )
        sys.exit(1)

    # ── 本地目录校验 ──────────────────────────────────────────────────
    if args.source_dir:
        source_path = Path(args.source_dir)
        if not source_path.is_dir():
            console.print(f"[red]错误：本地源码目录不存在: {args.source_dir}[/red]")
            sys.exit(1)
        resolved_source = str(source_path.resolve())
    else:
        resolved_source = None

    # ── 延迟导入（确保 env 已就绪）───────────────────────────────────
    from src.orchestrator.coordinator import Coordinator, PipelineConfig
    from src.utils.result_exporter import export_json
    from src.utils.html_reporter import export_html
    from src.utils.scan_history import ScanHistory

    is_auto_mode = getattr(args, "auto", False)
    vuln_types: list[str] = args.vuln_types or ([args.vuln_type] if args.vuln_type else ["_auto_"])

    base_config = PipelineConfig(
        language=args.language or "java",
        vuln_type=vuln_types[0],
        source_dir=resolved_source,
        github_url=getattr(args, "github_url", None),
        workspace_dir=args.workspace_dir,
        db_base_dir=args.db_dir,
        results_dir=args.results_dir,
        queries_dir=args.queries_dir,
        rule_memory_dir=args.rule_memory_dir,
        sink_hints=args.sink_hints,
        codeql_executable=args.codeql_path,
        max_retries=args.max_retries,
        cleanup_workspace=not args.no_cleanup,
        enable_agent_r=not args.no_agent_r,
        agent_r_min_confidence=args.min_confidence,
        enable_agent_s=not args.no_agent_s,
        enable_rule_memory=not args.no_rule_memory,
        build_mode="none" if args.no_build else "",
        enable_agent_e=not args.no_agent_e,
        agent_e_host=getattr(args, "agent_e_host", None),
        patch_commit=getattr(args, "patch_commit", None),
        enable_code_browser=not getattr(args, "no_code_browser", False),
        prebuilt_db=getattr(args, "codeql_db", None),
        agent_r_workers=getattr(args, "agent_r_workers", 1),
        agent_r_batch=getattr(args, "agent_r_batch", 1),
        external_sarif=getattr(args, "external_sarif", None),
    )

    import time
    _t_start = time.monotonic()

    if is_auto_mode:
        # ── Agent-P 自主模式 ──────────────────────────────────────────
        console.print(Panel(
            "[bold cyan]Agent-P 自主模式[/bold cyan]\n"
            "侦察 → 规划 → 执行 → 评估 → 自适应循环",
            title="QRSE-X Auto",
        ))
        try:
            auto_result = Coordinator.run_with_planner(base_config)
            states = auto_result.get("all_states", [])
            # 输出侦察报告、Agent-T 分类和扫描计划
            recon = auto_result.get("recon_report")
            profile = auto_result.get("codebase_profile")
            plan = auto_result.get("scan_plan")
            if recon:
                console.print(Panel(recon.to_summary(), title="侦察报告"))
            if profile:
                console.print(Panel(profile.to_summary(), title="Agent-T 代码库分类"))
            if plan:
                plan_table = Table(title="扫描计划", box=box.SIMPLE)
                plan_table.add_column("优先级", width=6)
                plan_table.add_column("漏洞类型", min_width=20)
                plan_table.add_column("理由")
                plan_table.add_column("状态", width=8)
                plan_table.add_column("发现", width=6)
                for t in plan.tasks:
                    plan_table.add_row(
                        str(t.priority), t.vuln_type, t.reason,
                        t.status, str(t.findings_count),
                    )
                console.print(plan_table)
            console.print(
                f"\n[bold green]自主扫描完成[/bold green] | "
                f"轮次: {auto_result.get('rounds_completed', 0)} | "
                f"漏洞: {auto_result.get('total_vulnerabilities', 0)} | "
                f"PoC: {auto_result.get('total_confirmed_pocs', 0)}"
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]用户中断执行。[/yellow]")
            sys.exit(0)
        except Exception as exc:
            console.print(f"[red]Agent-P 自主模式失败: {exc}[/red]")
            logger.exception("Agent-P 自主模式异常")
            sys.exit(1)
    else:
        try:
            states = _run_with_progress(base_config, vuln_types, args.parallel_workers)
        except KeyboardInterrupt:
            console.print("\n[yellow]用户中断执行。[/yellow]")
            sys.exit(0)

    elapsed = time.monotonic() - _t_start

    # ── 结果展示 ─────────────────────────────────────────────────────
    _print_rich_summary(states)

    # ── 扫描历史记录 ─────────────────────────────────────────────────
    try:
        source_label = base_config.github_url or base_config.source_dir or ""
        history = ScanHistory(history_dir=args.db_dir.replace("databases", "").rstrip("/\\") or "data")
        history.record(states, language=args.language,
                       source=source_label, elapsed_seconds=elapsed)
    except Exception as _he:  # noqa: BLE001
        logger.debug("扫描历史写入失败（非致命）: %s", _he)

    # ── JSON 导出 ─────────────────────────────────────────────────────
    if args.output_json:
        try:
            export_json(states, args.output_json, language=args.language)
            console.print(f"[green]JSON 报告已保存: {args.output_json}[/green]")
        except OSError as exc:
            console.print(f"[red]JSON 导出失败: {exc}[/red]")

    # ── HTML 导出 ─────────────────────────────────────────────────────
    if args.output_html:
        try:
            export_html(states, args.output_html, language=args.language)
            console.print(f"[green]HTML 报告已保存: {args.output_html}[/green]")
        except OSError as exc:
            console.print(f"[red]HTML 导出失败: {exc}[/red]")

    has_error = any(s.error for s in states)
    sys.exit(1 if has_error else 0)


# ---------------------------------------------------------------------------
# 进度条驱动的扫描执行
# ---------------------------------------------------------------------------

# Pipeline 各阶段中文名称（用于进度条描述）
_PHASE_LABELS: dict[str, str] = {
    "clone_repo":      "克隆仓库",
    "create_database": "创建数据库",
    "generate_query":  "生成 QL 规则",
    "analyze":         "CodeQL 扫描",
    "review":          "Agent-R 审查",
    "generate_poc":    "Agent-S PoC",
}
_TOTAL_PHASES = len(_PHASE_LABELS)


def _run_with_progress(
    base_config: "PipelineConfig",
    vuln_types: list[str],
    max_workers: int,
) -> "list[PipelineState]":
    """
    在 rich 进度条界面下执行扫描，支持单次和并行两种模式。

    进度追踪策略：
    - 在后台线程中运行 Coordinator，主线程每 300ms 轮询
      `state.completed_phases`，按已完成阶段数推进进度条。
    - 并行模式下为每种漏洞类型创建独立进度条。
    """
    import dataclasses
    import threading

    from src.orchestrator.coordinator import Coordinator, PipelineState

    console.print(Panel(
        f"[bold green]QRSE-X 启动[/bold green]\n"
        f"语言: [cyan]{base_config.language}[/cyan]  "
        f"漏洞类型数: [cyan]{len(vuln_types)}[/cyan]  "
        f"模式: [cyan]{'GitHub' if base_config.github_url else '本地'}[/cyan]",
        expand=False,
    ))

    def _run_in_thread(fn) -> tuple[PipelineState | None, Exception | None]:
        """在后台线程运行 fn()，返回 (result, error)。"""
        holder: list = []
        err_holder: list = []

        def _target():
            try:
                holder.append(fn())
            except Exception as exc:  # noqa: BLE001
                err_holder.append(exc)

        t = threading.Thread(target=_target, daemon=True)
        t.start()
        return t, holder, err_holder

    def _poll_phase_progress(
        progress: Progress,
        task_id,
        thread: threading.Thread,
        state_ref: list,
        poll_interval: float = 0.3,
    ) -> None:
        """轮询 state.completed_phases，实时推进进度条。"""
        last_count = 0
        while thread.is_alive():
            thread.join(timeout=poll_interval)
            if state_ref:
                current = len(state_ref[0].completed_phases)
                if current > last_count:
                    phase_keys = list(_PHASE_LABELS.keys())
                    new_phase = phase_keys[min(current - 1, len(phase_keys) - 1)]
                    label = _PHASE_LABELS.get(new_phase, new_phase)
                    progress.update(task_id, completed=current, description=f"[cyan]{label}[/cyan]")
                    last_count = current

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description:<20}"),
        BarColumn(bar_width=28),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        if len(vuln_types) == 1:
            # ── 单漏洞：单进度条 + 阶段级实时追踪 ─────────────────────
            vt = vuln_types[0]
            task = progress.add_task("[dim]初始化…[/dim]", total=_TOTAL_PHASES)

            cfg = dataclasses.replace(base_config, vuln_type=vt)
            coordinator = Coordinator(config=cfg)

            # coordinator.active_state 在 run() 进入后立即被设置（见 coordinator.py），
            # 主线程轮询它的 completed_phases 即可实现阶段级进度追踪。
            thread, holder, err_holder = _run_in_thread(coordinator.run)

            # 等待 coordinator 创建 active_state（通常 < 50ms）
            _waited = 0
            while coordinator.active_state is None and thread.is_alive() and _waited < 40:
                thread.join(timeout=0.05)
                _waited += 1

            # 实时轮询阶段进度
            last_count = 0
            phase_keys = list(_PHASE_LABELS.keys())
            while thread.is_alive():
                thread.join(timeout=0.3)
                s = coordinator.active_state
                if s is not None:
                    current = len(s.completed_phases)
                    if current > last_count:
                        idx = min(current - 1, len(phase_keys) - 1)
                        label = _PHASE_LABELS.get(phase_keys[idx], phase_keys[idx])
                        progress.update(task, completed=current,
                                        description=f"[cyan]{label}[/cyan]")
                        last_count = current

            thread.join()

            if err_holder:
                raise err_holder[0]

            result = holder[0] if holder else None
            if result is None:
                s = PipelineState(vuln_type=vt)
                s.error = "Pipeline 未返回结果"
                result = s

            progress.update(task, completed=_TOTAL_PHASES,
                            description=f"[green]{vt[:30]}[/green]")
            return [result]

        else:
            # ── 多漏洞：每个漏洞类型一条进度条 + 整体汇总进度 ──────────
            overall_task = progress.add_task(
                "[bold cyan]整体进度[/bold cyan]", total=len(vuln_types)
            )
            sub_tasks: dict[str, int] = {}
            for vt in vuln_types:
                tid = progress.add_task(f"[dim]{vt[:30]}[/dim]", total=_TOTAL_PHASES)
                sub_tasks[vt] = tid

            all_states: list[PipelineState | None] = [None] * len(vuln_types)
            locks = [threading.Event() for _ in vuln_types]

            # 先串行完成建库（Phase 0+1），所有子任务共享同一数据库
            # 此工作由 run_parallel 内部完成，这里通过线程包裹整个调用
            completed_count = 0

            def _parallel_runner():
                return Coordinator.run_parallel(
                    base_config=base_config,
                    vuln_types=vuln_types,
                    max_workers=max_workers,
                )

            thread, holder, err_holder = _run_in_thread(_parallel_runner)

            # 简单轮询：每 500ms 更新一次整体进度（子进度无法从外部精确追踪并行线程）
            while thread.is_alive():
                thread.join(timeout=0.5)

            if err_holder:
                raise err_holder[0]

            states = holder[0] if holder else []
            for idx, (vt, state) in enumerate(zip(vuln_types, states)):
                tid = sub_tasks[vt]
                if state.error:
                    progress.update(tid, completed=_TOTAL_PHASES,
                                    description=f"[red]{vt[:30]}[/red]")
                else:
                    progress.update(tid, completed=_TOTAL_PHASES,
                                    description=f"[green]{vt[:30]}[/green]")
                progress.advance(overall_task)

            return states


# ---------------------------------------------------------------------------
# Rich 格式化结果摘要
# ---------------------------------------------------------------------------


def _print_rich_summary(states: "list[PipelineState]") -> None:
    from src.agents.agent_r import VulnStatus

    # ── 总体统计面板 ──────────────────────────────────────────────────
    total_vuln = sum(len(s.vulnerable_findings) for s in states)
    total_find = sum(len(s.review_results) for s in states)
    total_poc = sum(len(s.poc_results) for s in states)
    total_dyn_confirmed = sum(len(s.confirmed_poc_results) for s in states)
    failed = sum(1 for s in states if s.error)

    dyn_label = (
        f"  动态确认: [bold green]{total_dyn_confirmed}[/bold green]"
        if total_poc > 0 else ""
    )
    summary_text = (
        f"扫描任务: [cyan]{len(states)}[/cyan]  "
        f"发现总计: [yellow]{total_find}[/yellow]  "
        f"LLM确认: [red]{total_vuln}[/red]  "
        f"PoC: [magenta]{total_poc}[/magenta]"
        + dyn_label +
        f"  失败: [red]{failed}[/red]"
    )
    console.print(Panel(summary_text, title="[bold]QRSE-X 扫描完成[/bold]", expand=False))

    for state in states:
        vuln_label = state.vuln_type or "未知"
        if state.error:
            console.print(f"[red]✘ {vuln_label}[/red] — {state.error}")
            continue

        cache_tag = " [dim](缓存命中)[/dim]" if state.db_from_cache else ""
        console.print(
            f"\n[bold cyan]{vuln_label}[/bold cyan]"
            + (f"  [dim]run_id={state.run_id}[/dim]")
        )
        console.print(f"  数据库: {state.db_path}{cache_tag}")
        console.print(f"  查询:   {state.query_path}")
        console.print(f"  SARIF:  {state.sarif_path}")

        if not state.review_results:
            console.print("  [dim]Agent-R 未产生结果（可能已禁用或无发现）[/dim]")
            continue

        # Agent-R 结果表格
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("#",        width=3)
        table.add_column("状态",     width=8)
        table.add_column("置信度",   width=7)
        table.add_column("引擎",     width=10)
        table.add_column("位置",     no_wrap=False)
        table.add_column("推理摘要", no_wrap=False)

        for i, r in enumerate(state.review_results, 1):
            if r.status == VulnStatus.VULNERABLE:
                status_str = "[red]漏洞[/red]"
            elif r.status == VulnStatus.SAFE:
                status_str = "[green]安全[/green]"
            else:
                status_str = "[yellow]可疑[/yellow]"

            table.add_row(
                str(i),
                status_str,
                f"{r.confidence:.0%}",
                r.engine_detected,
                f"{r.finding.file_uri}:{r.finding.start_line}",
                r.reasoning[:60] + ("…" if len(r.reasoning) > 60 else ""),
            )
        console.print(table)

        # Agent-S PoC + Agent-E 验证摘要
        if state.poc_results:
            console.print(f"  [magenta]PoC 报告（{len(state.poc_results)} 份）[/magenta]")
            for poc in state.poc_results:
                sev_color = "red" if poc.severity == "critical" else (
                    "yellow" if poc.severity == "high" else "dim"
                )
                # Agent-E 动态验证结果标记
                vr = poc.verification_result
                if vr is not None and hasattr(vr, "status"):
                    from src.agents.agent_e import VerificationStatus as _VS
                    if vr.status == _VS.CONFIRMED:
                        dyn_tag = " [bold green]✅ 动态验证 100% 确认[/bold green]"
                    elif vr.status == _VS.UNCONFIRMED:
                        dyn_tag = " [yellow]⚠ 动态验证未命中[/yellow]"
                    elif vr.status == _VS.SKIPPED:
                        dyn_tag = " [dim]（跳过动态验证）[/dim]"
                    else:
                        dyn_tag = " [red]（验证出错）[/red]"
                else:
                    dyn_tag = ""

                console.print(
                    f"    [{sev_color}]{poc.severity.upper()}[/{sev_color}]"
                    f"  {poc.file_location}{dyn_tag}"
                )
                if poc.payloads:
                    console.print(f"    Payload: [magenta]{poc.payloads[0][:70]}[/magenta]")
                if poc.http_trigger:
                    m = poc.http_trigger.get("method", "?")
                    p = poc.http_trigger.get("path", "?")
                    param = poc.http_trigger.get("param", "?")
                    console.print(f"    触发:    {m} {p}  param={param}")
                if vr is not None and hasattr(vr, "evidence") and vr.evidence:
                    console.print(f"    证据:    [green]{vr.evidence[:100]}[/green]")

    console.print()


if __name__ == "__main__":
    main()
