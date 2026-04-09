"""
Coordinator：Argus 系统的工作流调度中心（全功能版）。

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
from typing import Callable, Optional

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
    enable_agent_t: bool = False
    agent_r_min_confidence: float = 0.6
    enable_agent_s: bool = True
    enable_rule_memory: bool = True
    build_mode: str = ""   # "none" = 跳过编译直接做源码提取（适合构建环境不完整时）
    enable_agent_e: bool = True   # 是否启用 Agent-E 动态沙箱验证
    agent_e_host: Optional[str] = None   # 已运行目标地址（如 http://localhost:8080）
    # Patch-Aware 模式（受 K-REPRO arXiv:2602.07287 启发）
    patch_commit: Optional[str] = None   # 修复补丁 commit hash，自动切换到漏洞版本扫描
    enable_code_browser: bool = True     # Agent-R 是否启用 CodeBrowser 智能上下文
    prebuilt_db: Optional[str] = None   # 预先建好的 CodeQL 数据库路径，跳过建库阶段
    agent_r_workers: int = 1            # Agent-R 并发线程数（1=串行，建议 2~4）
    agent_r_batch: int = 1              # Agent-R 每次 LLM 调用包含的 finding 数（建议 5~10）
    external_sarif: Optional[str] = None  # 外部 SARIF 文件路径（Checkov/tfsec/Trivy 等输出），跳过 Agent-Q + CodeQL 阶段
    prompt_preset: str = ""              # Agent-T 指定的 prompt 预设（如 "kernel"），传递给 Agent-R/Q
    agent_r_context_lines: int = 30      # Agent-R 上下文窗口大小（Agent-T 可按代码库类型调整）

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
    # Patch-Aware 模式
    patch_commit: str = ""                      # 修复补丁 commit hash
    hotspot_functions: dict = field(default_factory=dict)  # {文件: [函数名]}
    scan_mode: str = "full"                     # "full" / "patch_aware"

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

    # ------------------------------------------------------------------
    # Checkpoint 持久化
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_dataclass(obj: object) -> dict:
        """将 dataclass 实例递归序列化为 JSON-safe 字典。"""
        from dataclasses import asdict, fields
        import enum
        if hasattr(obj, "__dataclass_fields__"):
            result = {}
            for f in fields(obj):
                val = getattr(obj, f.name)
                result[f.name] = PipelineState._serialize_dataclass(val)
            return result
        if isinstance(obj, enum.Enum):
            return obj.value
        if isinstance(obj, list):
            return [PipelineState._serialize_dataclass(item) for item in obj]
        if isinstance(obj, dict):
            return {k: PipelineState._serialize_dataclass(v) for k, v in obj.items()}
        if isinstance(obj, set):
            return list(obj)
        return obj

    def save_checkpoint(self, checkpoint_dir: str = "data/checkpoints") -> str:
        """将当前状态序列化到 JSON 文件，支持断点续跑。"""
        import json as _json

        Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)
        path = Path(checkpoint_dir) / f"checkpoint_{self.run_id}.json"
        data = {
            "run_id": self.run_id,
            "vuln_type": self.vuln_type,
            "cloned_repo_path": self.cloned_repo_path,
            "source_dir": self.source_dir,
            "commit_hash": self.commit_hash,
            "build_command": self.build_command,
            "detected_frameworks": list(self.detected_frameworks),
            "db_path": self.db_path,
            "db_from_cache": self.db_from_cache,
            "query_path": self.query_path,
            "sarif_path": self.sarif_path,
            "completed_phases": self.completed_phases,
            "error": self.error,
            "patch_commit": self.patch_commit,
            "hotspot_functions": self.hotspot_functions,
            "scan_mode": self.scan_mode,
            "review_results": [self._serialize_dataclass(r) for r in self.review_results],
            "poc_results": [self._serialize_dataclass(p) for p in self.poc_results],
            "verification_results": [self._serialize_dataclass(v) for v in self.verification_results],
        }
        path.write_text(_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.debug("[Checkpoint] 已保存: %s", path)
        return str(path)

    @classmethod
    def load_checkpoint(cls, path: str) -> "PipelineState":
        """从 JSON 文件恢复 Pipeline 状态。"""
        import json as _json

        try:
            data = _json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError) as exc:
            raise RuntimeError(f"无法加载检查点文件: {path}") from exc

        state = cls(
            run_id=data["run_id"],
            vuln_type=data.get("vuln_type", ""),
        )
        state.cloned_repo_path = data.get("cloned_repo_path")
        state.source_dir = data.get("source_dir")
        state.commit_hash = data.get("commit_hash", "")
        state.build_command = data.get("build_command", "")
        state.detected_frameworks = set(data.get("detected_frameworks", []))
        state.db_path = data.get("db_path")
        state.db_from_cache = data.get("db_from_cache", False)
        state.query_path = data.get("query_path")
        state.sarif_path = data.get("sarif_path")
        state.completed_phases = data.get("completed_phases", [])
        state.error = data.get("error")
        state.patch_commit = data.get("patch_commit", "")
        state.hotspot_functions = data.get("hotspot_functions", {})
        state.scan_mode = data.get("scan_mode", "full")

        try:
            from src.agents.agent_r import ReviewResult as _RR, SarifFinding as _SF, VulnStatus as _VS
            for rd in data.get("review_results", []):
                finding_data = rd.get("finding", {})
                finding = _SF(
                    rule_id=finding_data.get("rule_id", ""),
                    message=finding_data.get("message", ""),
                    file_uri=finding_data.get("file_uri", ""),
                    start_line=finding_data.get("start_line", 0),
                    code_context=finding_data.get("code_context", ""),
                    additional_locations=finding_data.get("additional_locations", []),
                )
                status_str = rd.get("status", "UNCERTAIN")
                try:
                    status = _VS(status_str)
                except ValueError:
                    status = _VS.UNCERTAIN
                rr = _RR(
                    finding=finding,
                    status=status,
                    confidence=rd.get("confidence", 0.0),
                    engine_detected=rd.get("engine_detected", ""),
                    reasoning=rd.get("reasoning", ""),
                    sink_method=rd.get("sink_method", ""),
                )
                state.review_results.append(rr)
        except Exception as exc:
            logger.warning("[Checkpoint] review_results 恢复失败: %s", exc)

        try:
            from src.agents.agent_s import PoCResult as _PR
            for pd in data.get("poc_results", []):
                poc = _PR(
                    finding=None,
                    http_trigger=pd.get("http_trigger", {}),
                    payloads=pd.get("payloads", []),
                    raw_llm_output=pd.get("raw_llm_output", ""),
                )
                state.poc_results.append(poc)
        except Exception as exc:
            logger.warning("[Checkpoint] poc_results 恢复失败: %s", exc)

        try:
            from src.agents.agent_e import VerificationResult as _VR, VerificationStatus as _VSt
            for vd in data.get("verification_results", []):
                status_str = vd.get("status", "UNCONFIRMED")
                try:
                    status = _VSt(status_str)
                except ValueError:
                    status = _VSt.UNCONFIRMED
                vr = _VR(
                    status=status,
                    confidence=vd.get("confidence", 0.0),
                    reason=vd.get("reason", ""),
                )
                state.verification_results.append(vr)
        except Exception as exc:
            logger.warning("[Checkpoint] verification_results 恢复失败: %s", exc)

        logger.info("[Checkpoint] 已恢复: %s (已完成阶段: %s)", path, state.completed_phases)
        return state


# ---------------------------------------------------------------------------
# Coordinator 主类
# ---------------------------------------------------------------------------


class Coordinator:
    """
    Argus 工作流协调器（全功能版）。

    支持单次扫描（run）和多漏洞并行扫描（run_parallel）。
    """

    # CodeQL analyze 命令对同一数据库的 IMB 缓存不支持并发访问。
    # 使用 per-database 锁替代全局锁，不同数据库的 analyze 可以并行执行。
    _analyze_locks: dict[str, threading.Lock] = {}
    _analyze_locks_guard: threading.Lock = threading.Lock()

    @classmethod
    def _get_db_lock(cls, db_path: str) -> threading.Lock:
        """获取指定数据库路径的专属锁。"""
        with cls._analyze_locks_guard:
            if db_path not in cls._analyze_locks:
                cls._analyze_locks[db_path] = threading.Lock()
            return cls._analyze_locks[db_path]

    def __init__(
        self,
        config: PipelineConfig,
        agent_q: Optional[AgentQ] = None,
        agent_r: Optional[AgentR] = None,
        agent_s: Optional[AgentS] = None,
        agent_e: Optional[AgentE] = None,
        runner: Optional[CodeQLRunner] = None,
        repo_manager: Optional[GithubRepoManager] = None,
        rule_memory: Optional[RuleMemory] = None,
        _skip_rule_memory_init: bool = False,
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
        self.agent_r = agent_r or AgentR(
            enable_code_browser=config.enable_code_browser,
            context_lines=config.agent_r_context_lines,
        )
        self.agent_s = agent_s or AgentS()
        self.agent_e = agent_e or AgentE(
            target_host=config.agent_e_host,
            enable_docker=config.enable_agent_e,
        )
        self.repo_manager = repo_manager or GithubRepoManager()
        self.db_cache = DatabaseCache(db_base_dir=config.db_base_dir)
        if _skip_rule_memory_init:
            self.rule_memory = rule_memory
        else:
            self.rule_memory = rule_memory or (
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

        # ── Patch-Aware 模式：切换到漏洞版本 + 提取热区函数 ─────────────
        if self.config.patch_commit:
            logger.info("[Phase 0] Patch-Aware 模式：分析修复补丁 %s", self.config.patch_commit)
            try:
                hotspots = self.repo_manager.get_patch_diff(local_path, self.config.patch_commit)
                parent_hash = self.repo_manager.checkout_parent_commit(
                    local_path, self.config.patch_commit
                )
                state.patch_commit = self.config.patch_commit
                state.hotspot_functions = hotspots
                state.commit_hash = parent_hash[:12]
                state.scan_mode = "patch_aware"
                logger.info(
                    "[Phase 0] Patch-Aware 已激活 | 漏洞版本: %s | 热区文件: %d | 热区函数: %d",
                    parent_hash[:12], len(hotspots),
                    sum(len(v) for v in hotspots.values()),
                )
            except Exception as exc:
                logger.warning(
                    "[Phase 0] Patch-Aware 模式失败，降级为全量扫描: %s", exc
                )

        state.completed_phases.append("clone_repo")

        logger.info(
            "[Phase 0] 完成 | 构建命令: %s | 检测框架: %s | 模式: %s",
            build_cmd or "autobuild",
            ", ".join(sorted(frameworks)) if frameworks else "未知",
            state.scan_mode,
        )

    def _phase_triage(self, state: PipelineState) -> None:
        """Phase 0.5（可选）：Agent-T 代码库分类，自动调整扫描策略。"""
        if not self.config.enable_agent_t:
            return
        if not state.source_dir:
            return

        try:
            from src.agents.agent_t import AgentT

            agent_t = AgentT()

            @dataclass
            class _MiniRecon:
                primary_language: str = ""
                frameworks: list = field(default_factory=list)
                has_android: bool = False
                has_solidity: bool = False
                entry_points: list = field(default_factory=list)

            recon = _MiniRecon(
                primary_language=self.config.language,
                frameworks=list(state.detected_frameworks or []),
            )

            profile = agent_t.classify(recon_report=recon, source_dir=state.source_dir)

            if profile.prompt_preset and not self.config.prompt_preset:
                self.config.prompt_preset = profile.prompt_preset
                logger.info("[Phase 0.5] Agent-T 设置 prompt_preset=%s", profile.prompt_preset)

            if profile.context_window and profile.context_window != 30:
                self.config.agent_r_context_lines = profile.context_window
                self.agent_r.context_lines = profile.context_window
                logger.info("[Phase 0.5] Agent-T 调整上下文窗口=%d", profile.context_window)

            state.completed_phases.append("triage")
            logger.info(
                "[Phase 0.5] Agent-T 完成 | 类型=%s | 置信度=%.0f%% | %s",
                profile.codebase_type,
                profile.confidence * 100,
                profile.reasoning[:80],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Phase 0.5] Agent-T 执行失败（不影响后续流程）: %s", exc)

    def _phase_create_database(self, state: PipelineState) -> None:
        """Phase 1：创建 CodeQL 数据库（优先命中缓存）。"""
        assert state.source_dir

        # 优先使用预建数据库（--codeql-db 参数指定）
        if self.config.prebuilt_db:
            prebuilt = Path(self.config.prebuilt_db)
            if prebuilt.exists() and (prebuilt / "codeql-database.yml").exists():
                state.db_path = str(prebuilt)
                state.db_from_cache = True
                state.completed_phases.append("create_database")
                logger.info("[Phase 1] 使用预建 CodeQL 数据库，跳过建库: %s", prebuilt)
                return
            else:
                logger.warning("[Phase 1] 预建数据库路径无效，将重新建库: %s", self.config.prebuilt_db)

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
        mode_label = f" [{state.scan_mode}]" if state.scan_mode != "full" else ""
        logger.info("[Phase 2] Agent-Q 生成规则 | 漏洞类型: %s%s", self.config.vuln_type, mode_label)

        # Patch-Aware 模式下，将热区函数加入 sink_hints 供 Agent-Q 参考
        effective_sink_hints = self.config.sink_hints or ""
        if state.scan_mode == "patch_aware" and state.hotspot_functions:
            all_funcs = []
            for funcs in state.hotspot_functions.values():
                all_funcs.extend(funcs)
            if all_funcs:
                hotspot_hint = ", ".join(all_funcs[:10])
                effective_sink_hints = f"{effective_sink_hints}, {hotspot_hint}" if effective_sink_hints else hotspot_hint
                logger.info("[Phase 2] Patch-Aware 热区函数注入 Sink Hints: %s", hotspot_hint)

        # 从规则记忆库检索 Few-Shot 示例代码（语义检索含 Sink 提示）
        few_shot_examples: list[str] = []
        if self.rule_memory and self.rule_memory.count() > 0:
            hits = self.rule_memory.search(
                language=self.config.language,
                vuln_type=self.config.vuln_type,
                sink_hint=effective_sink_hints,
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
            sink_hints=effective_sink_hints or None,
            few_shot_examples=few_shot_examples or None,
            detected_frameworks=state.detected_frameworks or None,
            prompt_preset=self.config.prompt_preset,
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

        # 同一数据库的 analyze 互斥，不同数据库可并行
        with Coordinator._get_db_lock(state.db_path):
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

        # ── Phase 3.5：规则归档（仅在 SARIF 有真实发现时写入 RAG 记忆库）────
        _has_findings = False
        if sarif_path and Path(sarif_path).exists():
            try:
                import json as _json_check
                _sarif_data = _json_check.loads(Path(sarif_path).read_text(encoding="utf-8"))
                for run in _sarif_data.get("runs", []):
                    if run.get("results"):
                        _has_findings = True
                        break
            except Exception:
                pass
        if self.rule_memory and state.query_path and _has_findings:
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

        logger.info(
            "[Phase 4] Agent-R 开始语义审查 (语言: %s, workers: %d, batch: %d)...",
            self.config.language, self.config.agent_r_workers, self.config.agent_r_batch,
        )
        all_results = self.agent_r.review(
            sarif_path=state.sarif_path,
            repo_root=state.source_dir,
            language=self.config.language,
            parallel_workers=self.config.agent_r_workers,
            batch_size=self.config.agent_r_batch,
            prompt_preset=self.config.prompt_preset,
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

    # 迭代精化最大轮数（受 K-REPRO arXiv:2602.07287 启发：
    # 成功案例平均 4.9 次迭代，5 轮可覆盖绝大多数场景）
    _MAX_POC_ITERATIONS: int = 5

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
        """
        Phase 6：Agent-E 动态沙箱验证 + 迭代 PoC 精化循环。

        受 K-REPRO (arXiv:2602.07287) 启发：LLM Agent 平均需要 4.9 次迭代
        才能生成有效 PoC。本方法实现"生成→验证→反馈→改进"的闭环：
          1. Agent-E 验证当前 PoC
          2. 若已确认 → 终止，标记 CONFIRMED
          3. 若未确认 → 将 HTTP 响应/失败原因反馈给 Agent-S
          4. Agent-S 基于反馈生成改进版 PoC
          5. 重复 1-4，最多 _MAX_POC_ITERATIONS 轮
        """
        if not self.config.enable_agent_e:
            logger.info("[Phase 6] Agent-E 已禁用，跳过动态验证。")
            return

        if not state.poc_results:
            logger.info("[Phase 6] 无 PoC 需要验证，跳过动态验证。")
            return

        mode = "Remote" if self.config.agent_e_host else "Docker（沙箱）"
        logger.info(
            "[Phase 6] Agent-E 开始动态验证（迭代精化模式，最多 %d 轮）| PoC 数: %d | 模式: %s",
            self._MAX_POC_ITERATIONS, len(state.poc_results), mode,
        )

        # 构建 finding → poc 的映射（用于迭代时传回给 Agent-S）
        finding_map: dict[str, ReviewResult] = {}
        for finding in state.vulnerable_findings:
            key = f"{finding.finding.file_uri}:{finding.finding.start_line}"
            finding_map[key] = finding

        verification_results: list[VerificationResult] = []
        confirmed_count = 0

        for poc_idx, poc in enumerate(state.poc_results):
            current_poc = poc
            best_vr = None

            for iteration in range(1, self._MAX_POC_ITERATIONS + 1):
                logger.info(
                    "[Phase 6] PoC %d/%d — 迭代 %d/%d | %s",
                    poc_idx + 1, len(state.poc_results),
                    iteration, self._MAX_POC_ITERATIONS,
                    current_poc.file_location,
                )

                vr = self.agent_e.verify(
                    poc=current_poc,
                    vuln_type=self.config.vuln_type,
                    repo_path=state.source_dir or "",
                )

                if vr.is_confirmed:
                    confirmed_count += 1
                    current_poc.verification_result = vr
                    best_vr = vr
                    logger.info(
                        "[Phase 6] ✅ 第 %d 轮确认真实漏洞 | %s | 证据: %s",
                        iteration, current_poc.file_location,
                        vr.evidence[:80] if vr.evidence else "（LLM 分析确认）",
                    )
                    break

                # 保存最佳结果
                if best_vr is None or (vr.confidence or 0) > (best_vr.confidence or 0):
                    best_vr = vr

                # 最后一轮不再精化
                if iteration >= self._MAX_POC_ITERATIONS:
                    logger.info(
                        "[Phase 6] ⚠ 达到最大迭代轮数 (%d)，终止精化 | %s",
                        self._MAX_POC_ITERATIONS, current_poc.file_location,
                    )
                    break

                # 若 Agent-E 跳过（无 Docker/Remote），不进入精化循环
                if vr.status == VerificationStatus.SKIPPED:
                    logger.info("[Phase 6] Agent-E SKIPPED，不进入迭代精化")
                    break

                # 构造反馈信息，传给 Agent-S 进行精化
                feedback = (
                    f"HTTP 状态码: {vr.response_code}\n"
                    f"响应片段: {vr.response_snippet[:300]}\n"
                    f"失败原因: {vr.reason}\n"
                    f"LLM 分析: {vr.llm_analysis[:200]}"
                )

                finding = finding_map.get(current_poc.file_location)
                if finding and self.config.enable_agent_s:
                    logger.info(
                        "[Phase 6] → Agent-S 迭代精化 (第 %d → %d 轮)...",
                        iteration, iteration + 1,
                    )
                    try:
                        current_poc = self.agent_s.refine_poc(
                            previous_poc=current_poc,
                            error_feedback=feedback,
                            finding=finding,
                            iteration=iteration,
                        )
                    except Exception as exc:
                        logger.warning("[Phase 6] Agent-S 精化失败: %s", exc)
                        break
                else:
                    break

            # 使用最终状态
            if best_vr:
                current_poc.verification_result = best_vr
                verification_results.append(best_vr)
            else:
                verification_results.append(VerificationResult(
                    status=VerificationStatus.SKIPPED,
                    reason="验证过程未产生结果",
                ))

            # 更新 state 中的 poc（可能已被精化替换）
            state.poc_results[poc_idx] = current_poc

        state.verification_results = verification_results
        state.completed_phases.append("verify")
        logger.info(
            "[Phase 6] 动态验证完成（迭代精化模式）| 确认: %d/%d | 后端: %s",
            confirmed_count, len(state.poc_results), mode,
        )

    def _cleanup_clone(self, state: PipelineState) -> None:
        """（GitHub 模式）清理克隆的临时目录。"""
        if not self.config.cleanup_workspace or not state.cloned_repo_path:
            return
        self.repo_manager.cleanup(state.cloned_repo_path)

    # ------------------------------------------------------------------
    # 公开接口：单次扫描
    # ------------------------------------------------------------------

    def run(
        self,
        checkpoint_path: Optional[str] = None,
    ) -> PipelineState:
        """
        执行完整 Pipeline 并返回最终状态。

        Args:
            checkpoint_path: 若提供，则从 checkpoint 恢复，跳过已完成的阶段。

        Returns:
            PipelineState，含数据库路径、SARIF 路径、Agent-R 审查结论与 PoC。
        """
        if checkpoint_path:
            state = PipelineState.load_checkpoint(checkpoint_path)
            logger.info("[Resume] 从 checkpoint 恢复, 已完成阶段: %s", state.completed_phases)
        else:
            state = PipelineState(vuln_type=self.config.vuln_type)

        self.active_state = state
        mode = "GitHub 模式" if self.config.github_url else "本地模式"
        logger.info(
            "=== Argus Pipeline 启动 | %s | run_id=%s | 语言=%s | 漏洞=%s ===",
            mode, state.run_id, self.config.language, self.config.vuln_type,
        )

        if self.config.source_dir:
            state.source_dir = self.config.source_dir
            if "clone_repo" not in state.completed_phases:
                state.detected_frameworks = self.repo_manager.detect_frameworks(
                    self.config.source_dir
                )

        def _run_phase(phase_name: str, phase_fn: Callable) -> None:
            if phase_name in state.completed_phases:
                logger.info("[Skip] 阶段 '%s' 已完成（checkpoint），跳过", phase_name)
                return
            phase_fn(state)
            try:
                state.save_checkpoint(self.config.results_dir)
            except Exception:  # noqa: BLE001
                pass

        try:
            if self.config.external_sarif:
                from pathlib import Path as _P
                ext = _P(self.config.external_sarif)
                if not ext.exists():
                    raise FileNotFoundError(f"外部 SARIF 文件不存在: {ext}")
                state.sarif_path = str(ext)
                for ph in ("clone_repo", "create_database", "generate_query", "analyze"):
                    if ph not in state.completed_phases:
                        state.completed_phases.append(ph)
                logger.info(
                    "[外部 SARIF] 跳过 Phase 0~3，直接进入 Agent-R 审查: %s", ext
                )
                _run_phase("triage", self._phase_triage)
                _run_phase("review", self._phase_review)
                _run_phase("generate_poc", self._phase_generate_poc)
                _run_phase("verify", self._phase_verify)
            else:
                if self.config.github_url:
                    _run_phase("clone_repo", self._phase_clone_repo)

                _run_phase("triage", self._phase_triage)
                _run_phase("create_database", self._phase_create_database)
                _run_phase("generate_query", self._phase_generate_query)
                _run_phase("analyze", self._phase_analyze)
                _run_phase("review", self._phase_review)
                _run_phase("generate_poc", self._phase_generate_poc)
                _run_phase("verify", self._phase_verify)

        except Exception as exc:  # noqa: BLE001
            state.error = str(exc)
            logger.error("Pipeline 执行失败: %s", exc)
            try:
                state.save_checkpoint(self.config.results_dir)
            except Exception:  # noqa: BLE001
                pass
        finally:
            if self.config.github_url and not self.config.external_sarif:
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
            "=== Argus Phase 2-5 启动 | 漏洞=%s | DB=%s ===",
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
            "=== Argus 并行扫描启动 | 语言=%s | 漏洞类型数=%d | 并发=%d ===",
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

        # ── Step 2：并行运行 Phase 2-5（共享无状态 Agent 实例）─────────────
        shared_runner = first_coordinator.runner
        shared_agent_r = first_coordinator.agent_r
        shared_agent_s = first_coordinator.agent_s
        shared_agent_e = first_coordinator.agent_e
        shared_rule_memory = first_coordinator.rule_memory

        def _run_phase25(vuln_type: str) -> PipelineState:
            cfg = dataclasses.replace(base_config, vuln_type=vuln_type)
            coordinator = cls(
                config=cfg,
                agent_r=shared_agent_r,
                agent_s=shared_agent_s,
                agent_e=shared_agent_e,
                runner=shared_runner,
                rule_memory=shared_rule_memory,
                _skip_rule_memory_init=True,
            )
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

    # ------------------------------------------------------------------
    # 公开接口：Agent-P 自主模式
    # ------------------------------------------------------------------

    @classmethod
    def run_with_planner(
        cls,
        base_config: PipelineConfig,
    ) -> dict:
        """
        Agent-P 驱动的自主扫描模式。

        流程：侦察 → 规划 → 多轮执行 → 评估 → 自适应循环。
        用户无需指定 vuln_type，由 Agent-P 自主决策。

        Args:
            base_config: 基础配置（language 可为空，Agent-P 自动推断）。

        Returns:
            包含 recon_report / scan_plan / all_states / 统计信息的字典。
        """
        from src.agents.agent_p import AgentP

        source_dir = base_config.source_dir
        if not source_dir:
            raise ValueError("自主模式需要 source_dir（可通过 Phase 0 克隆后设置）")

        repo_mgr = GithubRepoManager()
        rule_mem = None
        if base_config.enable_rule_memory:
            try:
                rule_mem = RuleMemory(memory_dir=base_config.rule_memory_dir)
            except Exception:
                pass

        planner = AgentP(
            repo_manager=repo_mgr,
            rule_memory=rule_mem,
        )

        return planner.run_autonomous(
            source_dir=source_dir,
            coordinator_factory=cls,
            base_config=base_config,
        )
