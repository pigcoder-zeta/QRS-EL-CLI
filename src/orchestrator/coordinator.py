"""
Coordinator：QRSE-X 系统的工作流调度中心（全功能版）。

Pipeline 阶段：
  Phase 0: （GitHub 模式）克隆仓库 + 探测构建命令
  Phase 1: 创建 CodeQL 数据库（命中缓存时跳过）
  Phase 2: Agent-Q 规则生成与编译（优先模板知识库 + 规则记忆库 Few-Shot）
  Phase 3: CodeQL 扫描，输出 SARIF
  Phase 4: Agent-R 语义审查，过滤误报（LLM 概率判断）
  Phase 5: Agent-S PoC 生成（针对确认漏洞生成 HTTP 载荷）
  Phase 6: Agent-E 动态沙箱验证（Docker/Remote 执行 PoC，升级为 100%% 确认）

扩展能力：
  - run_parallel()：多漏洞类型并行扫描，利用 ThreadPoolExecutor
  - RuleMemory：成功规则自动归档，下次作为 Few-Shot 示例提供给 Agent-Q
"""

from __future__ import annotations

import concurrent.futures
import datetime
import logging
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.agents.agent_e import AgentE, VerificationResult, VerificationStatus
from src.agents.agent_q import AgentQ
from src.agents.agent_r import AgentR, ReviewResult, VulnStatus
from src.agents.agent_s import AgentS, PoCResult
from src.utils.codeql_runner import CodeQLRunner
from src.utils.db_cache import DatabaseCache
from src.utils.repo_manager import GithubRepoManager
from src.utils.rule_memory import RuleMemory

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 配置数据类
# ---------------------------------------------------------------------------


@dataclass
class PipelineConfig:
    """
    一次 Pipeline 执行的配置参数。

    Attributes:
        language: 目标语言（java / python / ...）。
        vuln_type: 漏洞类型描述（如 Spring EL Injection）。
        source_dir: 本地源码目录（与 github_url 二选一）。
        github_url: GitHub 仓库 URL（与 source_dir 二选一）。
        workspace_dir: 克隆仓库的临时工作目录根路径。
        db_base_dir: CodeQL 数据库存放根目录。
        results_dir: SARIF 结果存放目录。
        queries_dir: 生成的 .ql 文件存放目录。
        rule_memory_dir: 规则记忆库根目录。
        sink_hints: 自定义 Sink 提示（逗号分隔方法名）。
        codeql_executable: codeql 可执行文件路径。
        max_retries: Agent-Q 自修复最大次数。
        cleanup_workspace: 扫描后是否删除克隆目录。
        enable_agent_r: 是否启用 Agent-R 语义审查（默认开启）。
        agent_r_min_confidence: Agent-R 结果过滤阈值，低于此置信度的发现忽略。
        enable_agent_s: 是否启用 Agent-S PoC 生成（默认开启，仅对确认漏洞执行）。
        enable_rule_memory: 是否启用规则记忆库（成功规则自动归档）。
    """

    language: str
    vuln_type: str
    source_dir: Optional[str] = None
    github_url: Optional[str] = None
    workspace_dir: str = "data/workspaces"
    db_base_dir: str = "data/databases"
    results_dir: str = "data/results"
    queries_dir: str = "data/queries"
    rule_memory_dir: str = "data/rule_memory"
    sink_hints: Optional[str] = None
    codeql_executable: str = "codeql"
    max_retries: int = 3
    cleanup_workspace: bool = True
    enable_agent_r: bool = True
    agent_r_min_confidence: float = 0.6
    enable_agent_s: bool = True
    enable_rule_memory: bool = True
    build_mode: str = ""   # "none" = 跳过编译直接做源码提取（适合构建环境不完整时）
    enable_agent_e: bool = True   # 是否启用 Agent-E 动态沙箱验证
    agent_e_host: Optional[str] = None   # 已运行目标地址（如 http://localhost:8080）

    def __post_init__(self) -> None:
        if not self.source_dir and not self.github_url:
            raise ValueError("必须提供 source_dir 或 github_url 之一。")
        if self.source_dir and self.github_url:
            raise ValueError("source_dir 与 github_url 不可同时指定。")


# ---------------------------------------------------------------------------
# 状态数据类
# ---------------------------------------------------------------------------


@dataclass
class PipelineState:
    """记录 Pipeline 各阶段的中间状态与最终结果。"""

    run_id: str = field(
        default_factory=lambda: (
            datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            + "_" + uuid.uuid4().hex[:6]
        )
    )
    vuln_type: str = ""                         # 本次扫描的漏洞类型（并行时区分）
    cloned_repo_path: Optional[str] = None
    source_dir: Optional[str] = None
    commit_hash: str = ""
    build_command: str = ""
    detected_frameworks: set[str] = field(default_factory=set)  # Phase 0 检测到的框架
    db_path: Optional[str] = None
    db_from_cache: bool = False                 # True 表示命中缓存，跳过重建
    query_path: Optional[str] = None
    sarif_path: Optional[str] = None
    review_results: list[ReviewResult] = field(default_factory=list)
    poc_results: list[PoCResult] = field(default_factory=list)
    verification_results: list[VerificationResult] = field(default_factory=list)
    completed_phases: list[str] = field(default_factory=list)
    error: Optional[str] = None                 # 非空时表示该次扫描失败

    @property
    def vulnerable_findings(self) -> list[ReviewResult]:
        """返回 Agent-R 判定为真实漏洞的发现列表。"""
        return [r for r in self.review_results if r.status == VulnStatus.VULNERABLE]

    @property
    def confirmed_poc_results(self) -> list[PoCResult]:
        """返回经 Agent-E 动态验证确认的 PoC 列表。"""
        return [p for p in self.poc_results if p.is_dynamically_confirmed]

    @property
    def success(self) -> bool:
        return self.error is None


# ---------------------------------------------------------------------------
# Coordinator 主类
# ---------------------------------------------------------------------------


class Coordinator:
    """
    QRSE-X 工作流协调器（全功能版）。

    支持单次扫描（run）和多漏洞并行扫描（run_parallel）。
    """

    # CodeQL analyze 命令独占数据库 IMB 缓存，同一时刻只能有一个线程执行 analyze。
    # 此类级锁确保并行扫描时 Phase 3 串行化，避免 OverlappingFileLockException。
    _analyze_lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        config: PipelineConfig,
        agent_q: Optional[AgentQ] = None,
        agent_r: Optional[AgentR] = None,
        agent_s: Optional[AgentS] = None,
        runner: Optional[CodeQLRunner] = None,
        repo_manager: Optional[GithubRepoManager] = None,
    ) -> None:
        self.config = config
        self.runner = runner or CodeQLRunner(
            codeql_executable=config.codeql_executable
        )
        self.agent_q = agent_q or AgentQ(
            runner=self.runner,
            output_dir=config.queries_dir,
            max_retries=config.max_retries,
        )
        self.agent_r = agent_r or AgentR()
        self.agent_s = agent_s or AgentS()
        self.agent_e = AgentE(
            target_host=config.agent_e_host,
            enable_docker=config.enable_agent_e,
        )
        self.repo_manager = repo_manager or GithubRepoManager()
        self.db_cache = DatabaseCache(db_base_dir=config.db_base_dir)
        self.rule_memory = (
            RuleMemory(memory_dir=config.rule_memory_dir)
            if config.enable_rule_memory
            else None
        )
        # 进度追踪：run() 开始后立即设置，外部可安全轮询 completed_phases
        self.active_state: Optional[PipelineState] = None

    # ------------------------------------------------------------------
    # 各阶段私有方法
    # ------------------------------------------------------------------

    def _phase_clone_repo(self, state: PipelineState) -> None:
        """Phase 0（GitHub 模式）：克隆仓库 + 探测构建命令 + 获取 commit hash。"""
        assert self.config.github_url

        workspace = Path(self.config.workspace_dir) / state.run_id
        workspace.mkdir(parents=True, exist_ok=True)

        logger.info("[Phase 0] 正在克隆仓库: %s", self.config.github_url)
        local_path = self.repo_manager.clone_repo(
            repo_url=self.config.github_url,
            dest_dir=str(workspace / "repo"),
        )

        commit_hash = self.repo_manager.get_repo_head_hash(local_path)
        if commit_hash:
            logger.info("[Phase 0] Commit Hash: %s", commit_hash)

        logger.info("[Phase 0] 探测构建方式（语言: %s）...", self.config.language)
        build_cmd = self.repo_manager.detect_build_command(
            repo_path=local_path, language=self.config.language
        )

        logger.info("[Phase 0] 检测项目框架依赖...")
        frameworks = self.repo_manager.detect_frameworks(local_path)

        state.cloned_repo_path = local_path
        state.source_dir = local_path
        state.commit_hash = commit_hash
        state.build_command = build_cmd
        state.detected_frameworks = frameworks
        state.completed_phases.append("clone_repo")

        logger.info(
            "[Phase 0] 完成 | 构建命令: %s | 检测框架: %s",
            build_cmd or "autobuild",
            ", ".join(sorted(frameworks)) if frameworks else "未知",
        )

    def _phase_create_database(self, state: PipelineState) -> None:
        """Phase 1：创建 CodeQL 数据库（优先命中缓存）。"""
        assert state.source_dir

        if self.config.github_url and state.commit_hash:
            cached = self.db_cache.get(self.config.github_url, state.commit_hash)
            if cached:
                state.db_path = cached
                state.db_from_cache = True
                state.completed_phases.append("create_database")
                logger.info("[Phase 1] 数据库缓存命中，跳过重建: %s", cached)
                return

        db_path = str(Path(self.config.db_base_dir) / f"db_{state.run_id}")
        build_hint = state.build_command or "autobuild"
        logger.info(
            "[Phase 1] 创建 CodeQL 数据库 | 构建方式: %s | 路径: %s",
            build_hint, db_path,
        )

        success = self.runner.create_database(
            source_dir=state.source_dir,
            db_path=db_path,
            language=self.config.language,
            build_command=state.build_command or None,
            build_mode=self.config.build_mode,
        )
        if not success:
            raise RuntimeError(f"CodeQL 数据库创建失败。源码路径: {state.source_dir}")

        if self.config.github_url and state.commit_hash:
            self.db_cache.put(self.config.github_url, state.commit_hash, db_path)

        state.db_path = db_path
        state.completed_phases.append("create_database")
        logger.info("[Phase 1] 数据库创建成功: %s", db_path)

    @staticmethod
    def _extract_sarif_context(sarif_path: str, repo_root: str) -> dict:
        """
        从 SARIF 文件提取漏洞链路上下文，用于丰富 RuleMemory 向量。

        提取内容：
          - data_flow_summary: Source → Sink 数据流路径的自然语言摘要
          - sarif_message:     CodeQL 发现消息
          - sink_method:       Sink 方法名（从消息中推断）
          - code_snippet:      漏洞所在代码片段（前后各 5 行）

        Args:
            sarif_path: SARIF 文件路径。
            repo_root:  源码根目录，用于读取代码片段。

        Returns:
            含以上字段的字典，缺失时值为空字符串。
        """
        import json as _json

        ctx: dict = {
            "data_flow_summary": "",
            "sarif_message": "",
            "sink_method": "",
            "code_snippet": "",
        }
        try:
            sarif = _json.loads(Path(sarif_path).read_text(encoding="utf-8"))
        except Exception:
            return ctx

        runs = sarif.get("runs", [])
        if not runs:
            return ctx

        results = runs[0].get("results", [])
        if not results:
            return ctx

        # 取第一个发现（最具代表性）
        first = results[0]
        msg = first.get("message", {}).get("text", "")
        ctx["sarif_message"] = msg[:500]

        # 尝试从消息推断 Sink 方法（通常包含在 ` ` 或 [] 中）
        import re
        sink_match = re.search(r"`([A-Za-z0-9_.]+\([^`]{0,60}\))`", msg)
        if sink_match:
            ctx["sink_method"] = sink_match.group(1)

        # 解析 codeFlows（数据流路径）
        code_flows = first.get("codeFlows", [])
        if code_flows:
            thread_flows = code_flows[0].get("threadFlows", [])
            if thread_flows:
                steps = thread_flows[0].get("locations", [])
                flow_parts = []
                for step in steps:
                    loc = step.get("location", {})
                    phys = loc.get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    region = phys.get("region", {})
                    line = region.get("startLine", 0)
                    step_msg = loc.get("message", {}).get("text", "")
                    if uri:
                        flow_parts.append(f"{uri}:{line} — {step_msg}")
                if flow_parts:
                    ctx["data_flow_summary"] = " → ".join(flow_parts[:8])  # 最多 8 步

        # 读取漏洞位置的代码片段
        locations = first.get("locations", [])
        if locations:
            phys = locations[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            start_line = region.get("startLine", 0)
            if uri and start_line:
                # CodeQL URI 通常以 "file:///..." 或相对路径表示
                file_uri = uri.replace("file:///", "").replace("%20", " ")
                candidates = [
                    Path(repo_root) / file_uri,
                    Path(file_uri),
                ]
                for fp in candidates:
                    if fp.exists():
                        try:
                            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
                            lo = max(0, start_line - 6)
                            hi = min(len(lines), start_line + 5)
                            ctx["code_snippet"] = "\n".join(
                                f"{lo + i + 1:>4} | {lines[lo + i]}" for i in range(hi - lo)
                            )
                        except Exception:
                            pass
                        break

        return ctx

    def _phase_generate_query(self, state: PipelineState) -> None:
        """Phase 2：Agent-Q 规则生成与编译（优先模板知识库 + 规则记忆 Few-Shot）。"""
        logger.info("[Phase 2] Agent-Q 生成规则 | 漏洞类型: %s", self.config.vuln_type)

        # 从规则记忆库检索 Few-Shot 示例代码（语义检索含 Sink 提示）
        few_shot_examples: list[str] = []
        if self.rule_memory and self.rule_memory.count() > 0:
            hits = self.rule_memory.search(
                language=self.config.language,
                vuln_type=self.config.vuln_type,
                sink_hint=self.config.sink_hints or "",
                top_k=2,
            )
            for record, score in hits:
                if score > 0.3:
                    try:
                        code = self.rule_memory.load_query_code(record)
                        few_shot_examples.append(code)
                        logger.info(
                            "[Phase 2] 规则记忆命中 | 相似度=%.2f | sink=%s | %s",
                            score, record.sink_method or "N/A", record.vuln_type,
                        )
                    except FileNotFoundError:
                        pass

        query_file = self.agent_q.generate_and_compile(
            language=self.config.language,
            vuln_type=self.config.vuln_type,
            sink_hints=self.config.sink_hints,
            few_shot_examples=few_shot_examples or None,
            detected_frameworks=state.detected_frameworks or None,
        )
        state.query_path = str(query_file)
        state.completed_phases.append("generate_query")
        logger.info("[Phase 2] 规则就绪: %s", state.query_path)

    def _phase_analyze(self, state: PipelineState) -> None:
        """Phase 3：运行 CodeQL 扫描，输出 SARIF。"""
        assert state.db_path and state.query_path

        sarif_path = str(
            Path(self.config.results_dir) / f"results_{state.run_id}.sarif"
        )
        logger.info("[Phase 3] 运行 CodeQL 扫描，输出: %s", sarif_path)

        # CodeQL IMB 缓存不支持并发访问，加锁确保同一时刻只有一个 analyze 运行
        with Coordinator._analyze_lock:
            success = self.runner.analyze(
                db_path=state.db_path,
                query_path=state.query_path,
                output_sarif=sarif_path,
            )
        if not success:
            # analyze 失败通常是因为目标项目不含该框架的依赖（如在非 Spring 项目上
            # 运行 Spring EL 查询）。这种情况视为"0 发现"而非整体失败，
            # 允许其他漏洞类型的并行扫描继续正常完成。
            logger.warning(
                "[Phase 3] CodeQL 扫描未能完成（项目可能不含相关框架依赖）。"
                "将此次扫描视为 0 发现，继续其余流程。"
            )
            # 写入空 SARIF，让后续阶段可以正常读取
            import json as _json
            empty_sarif = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []}}, "results": []}],
            }
            Path(sarif_path).parent.mkdir(parents=True, exist_ok=True)
            Path(sarif_path).write_text(_json.dumps(empty_sarif), encoding="utf-8")

        state.sarif_path = sarif_path
        state.completed_phases.append("analyze")
        logger.info("[Phase 3] 扫描完成: %s", sarif_path)

        # ── Phase 3.5：规则归档（携带 SARIF 漏洞链路上下文写入 RAG 记忆库）────
        if self.rule_memory and state.query_path:
            try:
                from src.utils.vuln_catalog import find as _vuln_find
                entry = _vuln_find(self.config.vuln_type)
                cwe = entry.cwe if entry and entry.cwe else ""

                sarif_ctx = self._extract_sarif_context(
                    sarif_path=sarif_path,
                    repo_root=state.source_dir or "",
                )
                # 构建来源标识：GitHub URL 优先，本地路径用 local:// 前缀
                source_repo = (
                    self.config.github_url
                    if self.config.github_url
                    else f"local://{state.source_dir or ''}"
                )
                self.rule_memory.save(
                    language=self.config.language,
                    vuln_type=self.config.vuln_type,
                    query_path=state.query_path,
                    tags=list(state.detected_frameworks or []),
                    sink_method=sarif_ctx["sink_method"],
                    data_flow_summary=sarif_ctx["data_flow_summary"],
                    sarif_message=sarif_ctx["sarif_message"],
                    code_snippet=sarif_ctx["code_snippet"],
                    cwe=cwe,
                    detected_frameworks=list(state.detected_frameworks or []),
                    # 来源验证字段
                    source_repo=source_repo,
                    source_commit=state.commit_hash or "",
                    import_source="local_scan",
                )
                logger.info(
                    "[Phase 3.5] 规则已归档到 RAG 记忆库 | sink=%s | backend=%s",
                    sarif_ctx["sink_method"] or "N/A",
                    self.rule_memory.get_backend_name(),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("[Phase 3.5] 规则归档失败（不影响扫描结果）: %s", exc)

    def _phase_review(self, state: PipelineState) -> None:
        """Phase 4：Agent-R 语义审查，过滤误报。"""
        if not self.config.enable_agent_r:
            logger.info("[Phase 4] Agent-R 已禁用，跳过语义审查。")
            return

        assert state.sarif_path and state.source_dir

        logger.info("[Phase 4] Agent-R 开始语义审查 (语言: %s)...", self.config.language)
        all_results = self.agent_r.review(
            sarif_path=state.sarif_path,
            repo_root=state.source_dir,
            language=self.config.language,
        )

        filtered = [
            r for r in all_results
            if r.confidence >= self.config.agent_r_min_confidence
        ]
        if len(filtered) < len(all_results):
            logger.info(
                "[Phase 4] 置信度过滤：%d → %d 条（阈值 %.0f%%）",
                len(all_results), len(filtered),
                self.config.agent_r_min_confidence * 100,
            )

        state.review_results = filtered
        state.completed_phases.append("review")

        vuln_count = len(state.vulnerable_findings)
        logger.info(
            "[Phase 4] 审查完成 | 确认漏洞: %d | 总计: %d",
            vuln_count, len(filtered),
        )

    def _phase_generate_poc(self, state: PipelineState) -> None:
        """Phase 5：Agent-S PoC 生成（仅对确认漏洞执行）。"""
        if not self.config.enable_agent_s:
            logger.info("[Phase 5] Agent-S 已禁用，跳过 PoC 生成。")
            return

        vulnerable = state.vulnerable_findings
        if not vulnerable:
            logger.info("[Phase 5] 无确认漏洞，跳过 PoC 生成。")
            return

        logger.info("[Phase 5] Agent-S 开始生成 PoC | 目标漏洞: %d 处", len(vulnerable))
        poc_results = self.agent_s.generate_all(vulnerable)
        state.poc_results = poc_results
        state.completed_phases.append("generate_poc")
        logger.info("[Phase 5] PoC 生成完成 | 共 %d 份", len(poc_results))

    def _phase_verify(self, state: PipelineState) -> None:
        """Phase 6：Agent-E 动态沙箱验证——将 LLM 概率判断升级为运行时确认。"""
        if not self.config.enable_agent_e:
            logger.info("[Phase 6] Agent-E 已禁用，跳过动态验证。")
            return

        if not state.poc_results:
            logger.info("[Phase 6] 无 PoC 需要验证，跳过动态验证。")
            return

        logger.info(
            "[Phase 6] Agent-E 开始动态验证 | PoC 数: %d | 模式: %s",
            len(state.poc_results),
            "Remote" if self.config.agent_e_host else "Docker（沙箱）",
        )

        verification_results: list[VerificationResult] = []
        confirmed_count = 0

        for poc in state.poc_results:
            vr = self.agent_e.verify(
                poc=poc,
                vuln_type=self.config.vuln_type,
                repo_path=state.source_dir or "",
            )
            verification_results.append(vr)
            poc.verification_result = vr   # 注入回 PoC 对象

            if vr.is_confirmed:
                confirmed_count += 1
                logger.info(
                    "[Phase 6] ✅ 100%% 确认真实漏洞 | %s | 证据: %s",
                    poc.file_location,
                    vr.evidence[:80] if vr.evidence else "（LLM 分析确认）",
                )
            else:
                logger.info(
                    "[Phase 6] ⚠ 未能动态确认 | %s | 状态: %s | 原因: %s",
                    poc.file_location,
                    vr.status.value,
                    vr.reason[:80],
                )

        state.verification_results = verification_results
        state.completed_phases.append("verify")
        logger.info(
            "[Phase 6] 动态验证完成 | 确认: %d/%d | 后端: %s",
            confirmed_count, len(state.poc_results),
            "Docker" if not self.config.agent_e_host else "Remote",
        )

    def _cleanup_clone(self, state: PipelineState) -> None:
        """（GitHub 模式）清理克隆的临时目录。"""
        if not self.config.cleanup_workspace or not state.cloned_repo_path:
            return
        self.repo_manager.cleanup(state.cloned_repo_path)

    # ------------------------------------------------------------------
    # 公开接口：单次扫描
    # ------------------------------------------------------------------

    def run(self) -> PipelineState:
        """
        执行完整 Pipeline 并返回最终状态。

        Returns:
            PipelineState，含数据库路径、SARIF 路径、Agent-R 审查结论与 PoC。
        """
        state = PipelineState(vuln_type=self.config.vuln_type)
        self.active_state = state  # 提前暴露，外部进度条可安全轮询
        mode = "GitHub 模式" if self.config.github_url else "本地模式"
        logger.info(
            "=== QRSE-X Pipeline 启动 | %s | run_id=%s | 语言=%s | 漏洞=%s ===",
            mode, state.run_id, self.config.language, self.config.vuln_type,
        )

        if self.config.source_dir:
            state.source_dir = self.config.source_dir
            # 本地模式跳过 Phase 0 克隆，但仍执行框架检测
            state.detected_frameworks = self.repo_manager.detect_frameworks(
                self.config.source_dir
            )

        try:
            if self.config.github_url:
                self._phase_clone_repo(state)

            self._phase_create_database(state)
            self._phase_generate_query(state)
            self._phase_analyze(state)
            self._phase_review(state)
            self._phase_generate_poc(state)
            self._phase_verify(state)

        except Exception as exc:  # noqa: BLE001
            state.error = str(exc)
            logger.error("Pipeline 执行失败: %s", exc)
        finally:
            if self.config.github_url:
                self._cleanup_clone(state)

        dyn_confirmed = len(state.confirmed_poc_results)
        logger.info(
            "=== Pipeline 完成 | 阶段: [%s] | LLM确认漏洞: %d | 动态验证确认: %d ===",
            ", ".join(state.completed_phases),
            len(state.vulnerable_findings),
            dyn_confirmed,
        )
        return state

    # ------------------------------------------------------------------
    # 公开接口：基于已有数据库运行 Phase 2-5
    # ------------------------------------------------------------------

    def run_from_database(
        self,
        db_path: str,
        source_dir: str,
        commit_hash: str = "",
        build_command: str = "",
        db_from_cache: bool = False,
    ) -> PipelineState:
        """
        跳过 Phase 0/1（克隆与建库），直接基于已有数据库运行 Phase 2-5。

        用于并行扫描场景：主 Coordinator 建库后，多个子任务共享同一数据库。

        Args:
            db_path: 已存在的 CodeQL 数据库路径。
            source_dir: 源码目录路径（Agent-R 读取上下文时使用）。
            commit_hash: Git commit hash（可选，仅用于日志展示）。
            build_command: 构建命令（仅用于摘要展示）。
            db_from_cache: 该数据库是否命中缓存（仅用于摘要展示）。

        Returns:
            PipelineState，含查询路径、SARIF 路径、审查结论与 PoC。
        """
        state = PipelineState(vuln_type=self.config.vuln_type)
        state.source_dir = source_dir
        state.db_path = db_path
        state.commit_hash = commit_hash
        state.build_command = build_command
        state.db_from_cache = db_from_cache
        state.completed_phases.append("create_database")   # 标记为已完成（由调用方提供）

        logger.info(
            "=== QRSE-X Phase 2-5 启动 | 漏洞=%s | DB=%s ===",
            self.config.vuln_type, db_path,
        )

        try:
            self._phase_generate_query(state)
            self._phase_analyze(state)
            self._phase_review(state)
            self._phase_generate_poc(state)
            self._phase_verify(state)
        except Exception as exc:  # noqa: BLE001
            state.error = str(exc)
            logger.error("[%s] Phase 2-6 失败: %s", self.config.vuln_type, exc)

        return state

    # ------------------------------------------------------------------
    # 公开接口：多漏洞并行扫描
    # ------------------------------------------------------------------

    @classmethod
    def run_parallel(
        cls,
        base_config: PipelineConfig,
        vuln_types: list[str],
        max_workers: int = 3,
    ) -> list[PipelineState]:
        """
        并行扫描多种漏洞类型。

        优化策略（避免重复建库）：
        1. 先用第一个 vuln_type 完整运行 Phase 0+1，完成克隆 + 建库（或命中缓存）。
        2. 获取数据库路径后，剩余 vuln_types 直接调用 run_from_database()，
           跳过耗时 2-5 分钟的建库步骤，在线程池中并发运行 Phase 2-5。

        Args:
            base_config: 基础配置，vuln_type 字段将被 vuln_types 列表覆盖。
            vuln_types: 需要并行扫描的漏洞类型列表（至少 1 个）。
            max_workers: 线程池最大并发数（默认 3，受 LLM API 速率限制）。

        Returns:
            每种漏洞类型对应的 PipelineState 列表，顺序与 vuln_types 一致。
        """
        import dataclasses

        if not vuln_types:
            raise ValueError("vuln_types 列表不能为空。")

        logger.info(
            "=== QRSE-X 并行扫描启动 | 语言=%s | 漏洞类型数=%d | 并发=%d ===",
            base_config.language, len(vuln_types), max_workers,
        )

        # ── Step 1：串行完成 Phase 0+1（建库唯一一次）────────────────────
        first_cfg = dataclasses.replace(
            base_config,
            vuln_type=vuln_types[0],
            # 并行模式下不在 Phase 0 清理克隆目录，Phase 2-5 还需要 source_dir
            cleanup_workspace=False,
        )
        first_coordinator = cls(config=first_cfg)
        bootstrap_state = PipelineState(vuln_type=vuln_types[0])

        if first_cfg.source_dir:
            bootstrap_state.source_dir = first_cfg.source_dir

        try:
            if first_cfg.github_url:
                first_coordinator._phase_clone_repo(bootstrap_state)
            first_coordinator._phase_create_database(bootstrap_state)
        except Exception as exc:  # noqa: BLE001
            logger.error("并行扫描：Phase 0/1 失败，中止所有任务: %s", exc)
            error_states = []
            for vt in vuln_types:
                s = PipelineState(vuln_type=vt)
                s.error = f"Phase 0/1 失败: {exc}"
                error_states.append(s)
            return error_states

        shared_db_path = bootstrap_state.db_path
        shared_source_dir = bootstrap_state.source_dir
        shared_commit_hash = bootstrap_state.commit_hash
        shared_build_cmd = bootstrap_state.build_command
        db_from_cache = bootstrap_state.db_from_cache

        logger.info("共享数据库路径: %s | 并行启动 %d 个扫描任务...", shared_db_path, len(vuln_types))

        # ── Step 2：并行运行 Phase 2-5（每种漏洞类型独立）─────────────────
        def _run_phase25(vuln_type: str) -> PipelineState:
            cfg = dataclasses.replace(base_config, vuln_type=vuln_type)
            coordinator = cls(config=cfg)
            return coordinator.run_from_database(
                db_path=shared_db_path,
                source_dir=shared_source_dir,
                commit_hash=shared_commit_hash,
                build_command=shared_build_cmd,
                db_from_cache=db_from_cache,
            )

        states: list[PipelineState] = [PipelineState(vuln_type=vt) for vt in vuln_types]

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_run_phase25, vt): idx
                for idx, vt in enumerate(vuln_types)
            }
            for future in concurrent.futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    result = future.result()
                    result.cloned_repo_path = bootstrap_state.cloned_repo_path
                    states[idx] = result
                    logger.info(
                        "并行任务完成 [%d/%d] | 漏洞类型: %s | 确认漏洞: %d 处",
                        idx + 1, len(vuln_types), vuln_types[idx],
                        len(states[idx].vulnerable_findings),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "并行任务失败 [%d/%d] | %s: %s",
                        idx + 1, len(vuln_types), vuln_types[idx], exc,
                    )
                    states[idx] = PipelineState(vuln_type=vuln_types[idx])
                    states[idx].error = str(exc)

        # ── Step 3：清理克隆目录（如需）──────────────────────────────────
        if base_config.cleanup_workspace and bootstrap_state.cloned_repo_path:
            first_coordinator.repo_manager.cleanup(bootstrap_state.cloned_repo_path)
            logger.info("已清理克隆目录: %s", bootstrap_state.cloned_repo_path)

        success_count = sum(1 for s in states if s.success)
        total_vuln = sum(len(s.vulnerable_findings) for s in states)
        logger.info(
            "=== 并行扫描完成 | 成功: %d/%d | 总确认漏洞: %d 处 ===",
            success_count, len(vuln_types), total_vuln,
        )
        return states
