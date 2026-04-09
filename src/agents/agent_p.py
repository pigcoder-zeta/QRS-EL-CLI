"""
Agent-P（Planner Agent）：Argus 元决策层。

职责：
1. 侦察（Recon）  — 自动分析目标仓库的语言、框架、依赖、入口点
2. 规划（Plan）    — LLM 基于侦察报告从 vuln_catalog 中选择最优扫描策略
3. 评估（Evaluate）— 每轮扫描后评估结果质量，决定继续/重扫/终止

让系统从"用户必须手动指定漏洞类型"进化为"自主决策扫什么、怎么扫"。
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from src.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class ReconReport:
    """仓库侦察报告。"""

    languages: dict[str, float] = field(default_factory=dict)
    primary_language: str = ""
    frameworks: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    risky_dependencies: list[str] = field(default_factory=list)
    dependency_files: list[str] = field(default_factory=list)
    repo_size_loc: int = 0
    file_count: int = 0
    history_scan_count: int = 0
    has_android: bool = False
    has_solidity: bool = False

    def to_summary(self) -> str:
        """生成供 LLM 阅读的摘要文本。"""
        lines = [
            f"代码规模: {self.repo_size_loc} 行, {self.file_count} 个文件",
            f"主语言: {self.primary_language}",
            f"语言分布: {json.dumps(self.languages, ensure_ascii=False)}",
            f"检测到框架: {', '.join(self.frameworks) or '无'}",
            f"高风险依赖: {', '.join(self.risky_dependencies) or '无'}",
            f"入口点: {', '.join(self.entry_points[:20]) or '未检测到'}",
            f"Android 项目: {'是' if self.has_android else '否'}",
            f"Solidity 项目: {'是' if self.has_solidity else '否'}",
            f"历史扫描次数: {self.history_scan_count}",
        ]
        return "\n".join(lines)


@dataclass
class ScanTask:
    """单个扫描任务。"""

    vuln_type: str
    priority: int = 1
    reason: str = ""
    expected_findings: str = "medium"  # high / medium / low
    status: str = "pending"           # pending / running / done / skipped
    findings_count: int = 0
    confirmed_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "priority": self.priority,
            "reason": self.reason,
            "expected_findings": self.expected_findings,
            "status": self.status,
            "findings_count": self.findings_count,
            "confirmed_count": self.confirmed_count,
        }


@dataclass
class ScanPlan:
    """扫描计划。"""

    tasks: list[ScanTask] = field(default_factory=list)
    parallel_workers: int = 3
    quality_threshold: float = 0.6
    max_rounds: int = 2
    reasoning: str = ""

    @property
    def pending_tasks(self) -> list[ScanTask]:
        return [t for t in self.tasks if t.status == "pending"]

    @property
    def vuln_types(self) -> list[str]:
        return [t.vuln_type for t in self.tasks if t.status != "skipped"]


@dataclass
class EvaluationReport:
    """扫描结果评估报告。"""

    round_number: int = 0
    total_findings: int = 0
    confirmed_vulns: int = 0
    high_confidence_count: int = 0
    false_positive_rate: float = 0.0
    coverage: float = 0.0
    decision: str = "STOP"      # CONTINUE / RESCAN / STOP
    rescan_tasks: list[ScanTask] = field(default_factory=list)
    reasoning: str = ""

    def to_summary(self) -> str:
        lines = [
            f"第 {self.round_number} 轮评估:",
            f"  总发现: {self.total_findings}",
            f"  确认漏洞: {self.confirmed_vulns}",
            f"  高置信度: {self.high_confidence_count}",
            f"  误报率: {self.false_positive_rate:.1%}",
            f"  覆盖率: {self.coverage:.1%}",
            f"  决策: {self.decision}",
            f"  理由: {self.reasoning}",
        ]
        if self.rescan_tasks:
            lines.append(f"  重扫任务: {[t.vuln_type for t in self.rescan_tasks]}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 高风险依赖知识库
# ---------------------------------------------------------------------------

_RISKY_DEPS: dict[str, str] = {
    # Java
    "fastjson": "Deserialization / RCE (CVE-2022-25845 等)",
    "log4j-core": "Log4Shell RCE (CVE-2021-44228)",
    "commons-collections": "Deserialization gadget chain",
    "spring-expression": "SpEL Injection",
    "ognl": "OGNL Injection",
    "xstream": "Deserialization RCE",
    "snakeyaml": "YAML Deserialization",
    "shiro": "Auth bypass / Deserialization",
    "struts2": "OGNL / RCE",
    "jackson-databind": "Polymorphic Deserialization",
    # Python
    "pyyaml": "YAML Deserialization (yaml.load)",
    "jinja2": "SSTI",
    "paramiko": "SSH key handling",
    "pickle": "Insecure Deserialization",
    # JS
    "express": "Middleware misconfiguration",
    "jsonwebtoken": "JWT algorithm confusion",
    "serialize-javascript": "XSS / Prototype Pollution",
}

# 语言后缀映射
_LANG_EXTENSIONS: dict[str, list[str]] = {
    "java": [".java"],
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
    "go": [".go"],
    "csharp": [".cs"],
    "cpp": [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"],
    "solidity": [".sol"],
    "kotlin": [".kt", ".kts"],
}

# ---------------------------------------------------------------------------
# LLM Prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_PLANNER = """\
你是 Argus 安全扫描系统的规划 Agent（Agent-P）。
你的职责是根据目标仓库的侦察报告，从漏洞目录中选择最适合的漏洞类型进行扫描。

你必须输出严格的 JSON 格式，不要附带 markdown 代码块标记或任何解释文字。
"""

_PLAN_TEMPLATE = """\
以下是目标仓库的侦察报告：

{recon_summary}

以下是系统支持的全部漏洞类型（从 vuln_catalog 提取）：

{catalog_summary}

请基于侦察报告，制定扫描计划：
1. 从漏洞目录中选择 3~10 个最适合该仓库的漏洞类型
2. 按风险等级排列优先级（1=最高）
3. 给出选择每个漏洞类型的理由
4. 根据代码规模建议并行度（小项目 1~2，中项目 2~3，大项目 3~4）

输出 JSON：
{{
  "tasks": [
    {{"vuln_type": "漏洞类型名（与目录中 name 完全一致）", "priority": 1, "reason": "选择理由", "expected_findings": "high/medium/low"}},
    ...
  ],
  "parallel_workers": 3,
  "quality_threshold": 0.6,
  "reasoning": "整体规划思路"
}}
"""

_EVALUATE_TEMPLATE = """\
以下是第 {round_number} 轮扫描的结果摘要：

{results_summary}

原始扫描计划包含 {total_planned} 个漏洞类型，已完成 {completed_count} 个。

请评估扫描质量并决定下一步行动：
- STOP：扫描质量足够，结束扫描
- CONTINUE：继续执行尚未完成的扫描任务
- RESCAN：某些漏洞类型结果不佳，需要换策略重扫

输出 JSON：
{{
  "decision": "STOP/CONTINUE/RESCAN",
  "reasoning": "评估理由",
  "rescan_vuln_types": ["需要重扫的漏洞类型名，若无则为空数组"]
}}
"""


# ---------------------------------------------------------------------------
# AgentP 类
# ---------------------------------------------------------------------------


class AgentP(BaseAgent):
    """
    Planner Agent：Argus 元决策层。

    Args:
        llm: LangChain LLM 实例。
        repo_manager: GithubRepoManager 实例（可选，用于框架检测）。
        rule_memory: RuleMemory 实例（可选，用于历史查询）。
    """

    agent_name = "Agent-P"

    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        repo_manager: Any = None,
        rule_memory: Any = None,
        trace_dir: str = "data/results",
    ) -> None:
        super().__init__(llm=llm, temperature=0.2, timeout=120)
        self.repo_manager = repo_manager
        self.rule_memory = rule_memory
        self._trace_dir = trace_dir
        self._trace_records: list[dict] = []

    def _record_trace(self, phase: str, input_text: str, output_text: str) -> None:
        """记录 LLM 交互（用于决策追溯）。"""
        import time as _t
        self._trace_records.append({
            "phase": phase,
            "timestamp": _t.time(),
            "input": input_text[:2000],
            "output": output_text[:2000],
        })

    def save_trace(self, run_id: str = "") -> Optional[str]:
        """将决策追溯记录保存到 JSON 文件。"""
        if not self._trace_records:
            return None
        trace_path = Path(self._trace_dir) / f"agent_p_trace_{run_id or 'unknown'}.json"
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        trace_path.write_text(
            json.dumps(self._trace_records, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("[Agent-P] 决策追溯已保存: %s (%d 条记录)", trace_path, len(self._trace_records))
        return str(trace_path)

    # -----------------------------------------------------------------------
    # Phase 1: 侦察
    # -----------------------------------------------------------------------

    def recon(self, source_dir: str) -> ReconReport:
        """
        对目标仓库执行全面侦察。

        Args:
            source_dir: 源码根目录。

        Returns:
            ReconReport 侦察报告。
        """
        report = ReconReport()
        root = Path(source_dir)

        if not root.exists():
            logger.warning("[Agent-P] 源码目录不存在: %s", source_dir)
            return report

        logger.info("[Agent-P] 开始侦察: %s", source_dir)

        # 1) 语言统计
        report.languages, report.file_count, report.repo_size_loc = (
            self._analyze_languages(root)
        )
        if report.languages:
            report.primary_language = max(report.languages, key=report.languages.get)

        # 2) 框架检测
        if self.repo_manager:
            try:
                report.frameworks = list(
                    self.repo_manager.detect_frameworks(source_dir)
                )
            except Exception as exc:
                logger.debug("[Agent-P] 框架检测失败: %s", exc)
        if not report.frameworks:
            report.frameworks = self._detect_frameworks_simple(root)

        # 3) 依赖分析 — 识别高风险依赖
        report.risky_dependencies, report.dependency_files = (
            self._scan_risky_dependencies(root)
        )

        # 4) 入口点提取
        report.entry_points = self._extract_entry_points(root, report.primary_language)

        # 5) 特殊项目类型
        report.has_android = self._check_android(root)
        report.has_solidity = any(
            root.rglob("*.sol")
        )

        # 6) 历史情报
        if self.rule_memory:
            try:
                report.history_scan_count = self.rule_memory.count()
            except Exception:
                pass

        logger.info(
            "[Agent-P] 侦察完成: %s, %d 行, %d 文件, 主语言=%s, 框架=%s",
            source_dir, report.repo_size_loc, report.file_count,
            report.primary_language, report.frameworks,
        )
        return report

    _MAX_SCAN_FILES = 2000
    _LOC_WORKERS = 8

    def _analyze_languages(
        self, root: Path
    ) -> tuple[dict[str, float], int, int]:
        """统计仓库语言分布（采样 + 并行 I/O 优化）。"""
        from concurrent.futures import ThreadPoolExecutor

        ext_count: Counter[str] = Counter()
        file_count = 0
        sampled_files: list[Path] = []
        skip_dirs = {
            "node_modules", ".git", "__pycache__", "vendor", "build",
            "dist", "target", ".gradle", "bin", "obj",
        }

        for f in root.rglob("*"):
            if f.is_dir():
                continue
            if any(p in f.parts for p in skip_dirs):
                continue
            ext = f.suffix.lower()
            if ext:
                ext_count[ext] += 1
                file_count += 1
                if len(sampled_files) < self._MAX_SCAN_FILES:
                    sampled_files.append(f)

        def _count_lines(fp: Path) -> int:
            try:
                return sum(1 for _ in fp.open("r", encoding="utf-8", errors="ignore"))
            except Exception:
                return 0

        total_loc = 0
        with ThreadPoolExecutor(max_workers=self._LOC_WORKERS) as pool:
            total_loc = sum(pool.map(_count_lines, sampled_files))

        if file_count > self._MAX_SCAN_FILES:
            total_loc = int(total_loc * file_count / self._MAX_SCAN_FILES)

        lang_lines: Counter[str] = Counter()
        for lang, exts in _LANG_EXTENSIONS.items():
            for ext in exts:
                if ext in ext_count:
                    lang_lines[lang] += ext_count[ext]

        total = sum(lang_lines.values()) or 1
        lang_pct = {
            lang: round(count / total, 2)
            for lang, count in lang_lines.most_common()
            if count / total >= 0.01
        }
        return lang_pct, file_count, total_loc

    def _detect_frameworks_simple(self, root: Path) -> list[str]:
        """简易框架检测（不依赖 repo_manager）。"""
        frameworks = []
        indicators = {
            "spring-boot": ["pom.xml", "build.gradle"],
            "django": ["manage.py", "settings.py"],
            "flask": ["requirements.txt"],
            "express": ["package.json"],
            "android": ["AndroidManifest.xml"],
            "react": ["package.json"],
        }
        for fw, files in indicators.items():
            for fname in files:
                if list(root.rglob(fname)):
                    if fw == "flask":
                        req_files = list(root.rglob("requirements.txt"))
                        if any("flask" in f.read_text(errors="ignore").lower() for f in req_files):
                            frameworks.append(fw)
                    elif fw == "express":
                        pkg_files = list(root.rglob("package.json"))
                        for pf in pkg_files:
                            if "node_modules" not in str(pf):
                                try:
                                    data = json.loads(pf.read_text(errors="ignore"))
                                    all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                                    if "express" in all_deps:
                                        frameworks.append(fw)
                                    if "react" in all_deps:
                                        frameworks.append("react")
                                except Exception:
                                    pass
                    elif fw == "react":
                        continue  # handled in express
                    elif fw == "spring-boot":
                        build_files = list(root.rglob(fname))
                        for bf in build_files:
                            content = bf.read_text(errors="ignore").lower()
                            if "spring" in content:
                                frameworks.append("spring-boot")
                                if "mybatis" in content:
                                    frameworks.append("mybatis")
                                if "shiro" in content:
                                    frameworks.append("shiro")
                                break
                    else:
                        frameworks.append(fw)
                    break
        return list(set(frameworks))

    def _scan_risky_dependencies(
        self, root: Path
    ) -> tuple[list[str], list[str]]:
        """扫描高风险依赖。"""
        risky = []
        dep_files = []
        for pattern in ["pom.xml", "build.gradle", "package.json", "requirements*.txt", "go.mod"]:
            for f in root.rglob(pattern):
                if "node_modules" in str(f):
                    continue
                dep_files.append(str(f))
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore").lower()
                    for dep_name, risk_desc in _RISKY_DEPS.items():
                        if dep_name.lower() in content:
                            risky.append(f"{dep_name} ({risk_desc})")
                except Exception:
                    pass
        return list(set(risky)), dep_files

    def _extract_entry_points(self, root: Path, language: str) -> list[str]:
        """提取 HTTP 入口点（基于正则，不调用 LLM）。"""
        entry_points = []
        patterns: dict[str, list[re.Pattern]] = {
            "java": [
                re.compile(r'@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']'),
                re.compile(r'@Path\s*\(\s*["\']([^"\']+)["\']'),
            ],
            "python": [
                re.compile(r'@app\.(?:route|get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']'),
                re.compile(r'path\s*\(\s*["\']([^"\']+)["\']'),
            ],
            "javascript": [
                re.compile(r'(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)["\']'),
            ],
            "go": [
                re.compile(r'\.(?:GET|POST|PUT|DELETE|Handle|HandleFunc)\s*\(\s*["\']([^"\']+)["\']'),
            ],
        }
        lang_patterns = patterns.get(language, [])
        if not lang_patterns:
            return []

        lang_exts = _LANG_EXTENSIONS.get(language, [])
        for ext in lang_exts:
            for f in root.rglob(f"*{ext}"):
                if any(p in f.parts for p in {"node_modules", ".git", "test", "tests"}):
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    for pat in lang_patterns:
                        entry_points.extend(pat.findall(content))
                except Exception:
                    pass
                if len(entry_points) > 100:
                    break

        return list(set(entry_points))[:50]

    def _check_android(self, root: Path) -> bool:
        """检测是否为 Android 项目。"""
        return bool(list(root.rglob("AndroidManifest.xml")))

    # -----------------------------------------------------------------------
    # Phase 2: 规划
    # -----------------------------------------------------------------------

    def plan(self, recon_report: ReconReport, codebase_profile: Any = None) -> ScanPlan:
        """
        基于侦察报告，LLM 制定扫描计划。

        Args:
            recon_report: 侦察报告。
            codebase_profile: Agent-T 的分类结果（CodebaseProfile），可选。
                              若提供则将分类信息注入规划上下文。

        Returns:
            ScanPlan 扫描计划。
        """
        from src.utils.vuln_catalog import VULN_CATALOG

        logger.info("[Agent-P] 开始制定扫描计划...")

        # 如果 Agent-T 提供了分类结果，过滤漏洞目录以突出推荐类型
        recommended_types = set()
        profile_section = ""
        if codebase_profile is not None:
            profile_section = (
                f"\n\n【Agent-T 代码库分类结果】\n"
                f"{codebase_profile.to_summary()}\n"
                f"请优先选择上述推荐的漏洞类型。\n"
            )
            recommended_types = set(
                getattr(codebase_profile, "recommended_vuln_types", [])
            )

        primary_lang = getattr(recon_report, "primary_language", "").lower()
        catalog_lines = []
        for entry in VULN_CATALOG:
            if primary_lang and hasattr(entry, f"{primary_lang}_sinks"):
                if not getattr(entry, f"{primary_lang}_sinks", ()):
                    if entry.category == "injection":
                        continue
            marker = " [推荐]" if entry.name in recommended_types else ""
            catalog_lines.append(
                f"- {entry.name} ({entry.cwe}): 分类={entry.category}, "
                f"描述={entry.description or entry.cwe_desc}{marker}"
            )
        catalog_summary = "\n".join(catalog_lines)

        human_msg = _PLAN_TEMPLATE.format(
            recon_summary=recon_report.to_summary(),
            catalog_summary=catalog_summary,
        ) + profile_section

        chain = self.llm | self._parser
        raw = chain.invoke([
            SystemMessage(content=_SYSTEM_PROMPT_PLANNER),
            HumanMessage(content=human_msg),
        ])
        self._record_trace("plan", human_msg, raw)

        plan = self._parse_plan_response(raw, recon_report, codebase_profile)
        logger.info(
            "[Agent-P] 扫描计划就绪: %d 个任务, 并行度=%d, 理由=%s",
            len(plan.tasks), plan.parallel_workers, plan.reasoning[:80],
        )
        return plan

    def _parse_plan_response(self, raw: str, recon: ReconReport, codebase_profile: Any = None) -> ScanPlan:
        """解析 LLM 的 JSON 规划输出。"""
        from src.utils.vuln_catalog import find as find_vuln

        try:
            text = raw.strip()
            if text.startswith("```"):
                text = re.sub(r"^```\w*\n?", "", text)
                text = re.sub(r"\n?```$", "", text)
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("[Agent-P] LLM 规划输出解析失败，使用默认策略")
            return self._fallback_plan(recon, codebase_profile)

        tasks = []
        for item in data.get("tasks", []):
            vt = item.get("vuln_type", "")
            if find_vuln(vt) is not None:
                tasks.append(ScanTask(
                    vuln_type=vt,
                    priority=item.get("priority", 5),
                    reason=item.get("reason", ""),
                    expected_findings=item.get("expected_findings", "medium"),
                ))

        if not tasks:
            logger.warning("[Agent-P] LLM 未返回有效任务，使用默认策略")
            return self._fallback_plan(recon, codebase_profile)

        tasks.sort(key=lambda t: t.priority)
        return ScanPlan(
            tasks=tasks,
            parallel_workers=data.get("parallel_workers", 3),
            quality_threshold=data.get("quality_threshold", 0.6),
            max_rounds=data.get("max_rounds", 2),
            reasoning=data.get("reasoning", ""),
        )

    def _fallback_plan(self, recon: ReconReport, codebase_profile: Any = None) -> ScanPlan:
        """LLM 不可用时的规则化降级策略。"""
        from src.utils.vuln_catalog import VULN_CATALOG

        lang = recon.primary_language
        tasks = []

        # Agent-T 分类结果可直接指定推荐漏洞类型
        if codebase_profile and getattr(codebase_profile, "recommended_vuln_types", None):
            priority = 1
            for vt_name in codebase_profile.recommended_vuln_types:
                tasks.append(ScanTask(
                    vuln_type=vt_name,
                    priority=priority,
                    reason=f"Agent-T 推荐 ({codebase_profile.codebase_type})",
                ))
                priority += 1
            if tasks:
                return ScanPlan(
                    tasks=tasks,
                    parallel_workers=2,
                    max_rounds=2,
                    reasoning=f"Agent-T 分类 = {codebase_profile.codebase_type}，使用推荐漏洞类型",
                )

        lang_category_map = {
            "java": ["injection", "crypto", "mobile"],
            "python": ["injection", "crypto"],
            "javascript": ["injection", "crypto"],
            "go": ["injection", "crypto"],
            "cpp": ["memory", "injection", "resource"],
            "solidity": ["smart-contract"],
        }
        target_cats = lang_category_map.get(lang, ["injection"])

        priority = 1
        for entry in VULN_CATALOG:
            if entry.category in target_cats:
                has_sinks = bool(getattr(entry, f"{lang}_sinks", ()))
                if has_sinks or entry.category != "injection":
                    tasks.append(ScanTask(
                        vuln_type=entry.name,
                        priority=priority,
                        reason=f"默认策略: {lang} + {entry.category}",
                    ))
                    priority += 1
                if priority > 8:
                    break

        if recon.has_android and lang == "java":
            for entry in VULN_CATALOG:
                if entry.category == "mobile":
                    tasks.append(ScanTask(
                        vuln_type=entry.name,
                        priority=priority,
                        reason="检测到 Android 项目",
                    ))
                    priority += 1

        if not tasks:
            tasks = [
                ScanTask(vuln_type="SQL Injection", priority=1, reason="通用降级"),
                ScanTask(vuln_type="Command Injection", priority=2, reason="通用降级"),
                ScanTask(vuln_type="Cross-Site Scripting", priority=3, reason="通用降级"),
            ]

        return ScanPlan(
            tasks=tasks,
            parallel_workers=min(3, len(tasks)),
            quality_threshold=0.6,
            max_rounds=2,
            reasoning="LLM 不可用，使用基于语言+分类的默认策略",
        )

    # -----------------------------------------------------------------------
    # Phase 3: 评估
    # -----------------------------------------------------------------------

    def evaluate(
        self,
        round_number: int,
        scan_plan: ScanPlan,
        completed_states: list[Any],
    ) -> EvaluationReport:
        """
        评估一轮扫描的结果，决定下一步行动。

        Args:
            round_number: 当前轮次。
            scan_plan: 原始扫描计划。
            completed_states: 已完成的 PipelineState 列表。

        Returns:
            EvaluationReport 评估报告。
        """
        logger.info("[Agent-P] 开始第 %d 轮评估...", round_number)

        total_findings = 0
        confirmed = 0
        high_conf = 0
        safe_count = 0
        uncertain_count = 0
        task_summaries = []

        for state in completed_states:
            n_findings = len(state.review_results) if hasattr(state, "review_results") else 0
            n_vuln = len(state.vulnerable_findings) if hasattr(state, "vulnerable_findings") else 0
            n_poc = len(state.confirmed_poc_results) if hasattr(state, "confirmed_poc_results") else 0

            total_findings += n_findings
            confirmed += n_vuln

            if hasattr(state, "review_results"):
                for r in state.review_results:
                    if hasattr(r, "confidence") and r.confidence >= 0.8:
                        high_conf += 1
                    status_val = getattr(r, "status", None)
                    if status_val is not None:
                        status_name = status_val.value if hasattr(status_val, "value") else str(status_val)
                        if status_name.upper() == "SAFE":
                            safe_count += 1
                        elif status_name.upper() == "UNCERTAIN":
                            uncertain_count += 1

            task_summaries.append(
                f"- {state.vuln_type}: "
                f"findings={n_findings}, confirmed={n_vuln}, poc_verified={n_poc}, "
                f"safe={safe_count}, uncertain={uncertain_count}, "
                f"error={state.error or 'None'}"
            )

            for task in scan_plan.tasks:
                if task.vuln_type == state.vuln_type:
                    task.status = "done"
                    task.findings_count = n_findings
                    task.confirmed_count = n_vuln

        fp_rate = (
            safe_count / total_findings
            if total_findings > 0 else 0.0
        )
        done_count = sum(1 for t in scan_plan.tasks if t.status == "done")
        coverage = done_count / len(scan_plan.tasks) if scan_plan.tasks else 0.0

        results_summary = "\n".join(task_summaries)

        # LLM 评估
        try:
            human_msg = _EVALUATE_TEMPLATE.format(
                round_number=round_number,
                results_summary=results_summary,
                total_planned=len(scan_plan.tasks),
                completed_count=done_count,
            )
            chain = self.llm | self._parser
            raw = chain.invoke([
                SystemMessage(content=_SYSTEM_PROMPT_PLANNER),
                HumanMessage(content=human_msg),
            ])
            self._record_trace("evaluate", human_msg, raw)
            eval_data = self._parse_evaluate_response(raw, scan_plan)
        except Exception as exc:
            logger.warning("[Agent-P] LLM 评估失败，使用规则化决策: %s", exc)
            eval_data = self._fallback_evaluate(scan_plan, coverage)

        report = EvaluationReport(
            round_number=round_number,
            total_findings=total_findings,
            confirmed_vulns=confirmed,
            high_confidence_count=high_conf,
            false_positive_rate=fp_rate,
            coverage=coverage,
            decision=eval_data["decision"],
            rescan_tasks=eval_data.get("rescan_tasks", []),
            reasoning=eval_data.get("reasoning", ""),
        )

        logger.info("[Agent-P] 评估完成: %s", report.to_summary())
        return report

    def _parse_evaluate_response(
        self, raw: str, plan: ScanPlan
    ) -> dict[str, Any]:
        """解析 LLM 评估输出。"""
        try:
            text = raw.strip()
            if text.startswith("```"):
                text = re.sub(r"^```\w*\n?", "", text)
                text = re.sub(r"\n?```$", "", text)
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"decision": "STOP", "reasoning": "LLM 输出解析失败"}

        decision = data.get("decision", "STOP").upper()
        if decision not in ("CONTINUE", "RESCAN", "STOP"):
            decision = "STOP"

        rescan_tasks = []
        for vt in data.get("rescan_vuln_types", []):
            rescan_tasks.append(ScanTask(
                vuln_type=vt,
                priority=1,
                reason="评估建议重扫",
            ))

        return {
            "decision": decision,
            "reasoning": data.get("reasoning", ""),
            "rescan_tasks": rescan_tasks,
        }

    def _fallback_evaluate(
        self, plan: ScanPlan, coverage: float
    ) -> dict[str, Any]:
        """规则化降级评估。"""
        pending = plan.pending_tasks
        if pending:
            return {
                "decision": "CONTINUE",
                "reasoning": f"尚有 {len(pending)} 个任务未完成",
            }

        zero_finding_tasks = [
            t for t in plan.tasks
            if t.status == "done" and t.findings_count == 0
        ]
        if len(zero_finding_tasks) > len(plan.tasks) * 0.5:
            return {
                "decision": "STOP",
                "reasoning": "超过半数任务无发现，可能目标仓库安全性较好或查询不匹配",
            }

        return {
            "decision": "STOP",
            "reasoning": f"全部 {len(plan.tasks)} 个任务已完成，覆盖率 {coverage:.0%}",
        }

    # -----------------------------------------------------------------------
    # 完整自主流程
    # -----------------------------------------------------------------------

    def run_autonomous(
        self,
        source_dir: str,
        coordinator_factory: Any,
        base_config: Any,
    ) -> dict[str, Any]:
        """
        完整自主扫描流程：侦察 → 规划 → 执行 → 评估 → 自适应循环。

        Args:
            source_dir: 源码根目录。
            coordinator_factory: 接受 (config) 返回 Coordinator 的工厂函数。
            base_config: 基础 PipelineConfig（language/vuln_type 将被覆盖）。

        Returns:
            包含所有轮次结果的字典。
        """
        import dataclasses

        logger.info("=" * 60)
        logger.info("[Agent-P] 自主扫描模式启动")
        logger.info("=" * 60)

        # Phase 1: 侦察
        recon_report = self.recon(source_dir)

        # Phase 1.5: 代码库分类（Agent-T）
        codebase_profile = None
        try:
            from src.agents.agent_t import AgentT
            agent_t = AgentT(llm=self.llm)
            codebase_profile = agent_t.classify(recon_report, source_dir)
            logger.info(
                "[Agent-P] Agent-T 分类结果: %s (置信度 %.0f%%)",
                codebase_profile.codebase_type,
                codebase_profile.confidence * 100,
            )
        except Exception as exc:
            logger.warning("[Agent-P] Agent-T 分类失败，继续使用默认策略: %s", exc)

        # 自动推断语言（如果 base_config 未指定）
        language = base_config.language or recon_report.primary_language
        if not language:
            language = "java"
            logger.warning("[Agent-P] 无法推断语言，默认使用 java")

        # Phase 2: 规划（传入分类结果）
        scan_plan = self.plan(recon_report, codebase_profile=codebase_profile)

        all_states = []
        round_number = 0

        while round_number < scan_plan.max_rounds:
            round_number += 1
            pending = scan_plan.pending_tasks
            if not pending:
                logger.info("[Agent-P] 无待执行任务，结束")
                break

            logger.info(
                "[Agent-P] === 第 %d 轮执行: %d 个任务 ===",
                round_number, len(pending),
            )

            vuln_types = [t.vuln_type for t in pending]
            for t in pending:
                t.status = "running"

            # 使用 Coordinator.run_parallel 执行
            _extra_fields = {}
            if codebase_profile and hasattr(base_config, "prompt_preset"):
                _extra_fields["prompt_preset"] = codebase_profile.prompt_preset or ""
                _extra_fields["agent_r_context_lines"] = codebase_profile.context_window
            parallel_config = dataclasses.replace(
                base_config,
                language=language,
                vuln_type=vuln_types[0],
                source_dir=source_dir,
                **_extra_fields,
            )

            try:
                from src.orchestrator.coordinator import Coordinator
                round_states = Coordinator.run_parallel(
                    parallel_config,
                    vuln_types=vuln_types,
                    max_workers=scan_plan.parallel_workers,
                )
                all_states.extend(round_states)
            except Exception as exc:
                logger.error("[Agent-P] 第 %d 轮执行失败: %s", round_number, exc)
                for t in pending:
                    t.status = "done"
                break

            # Phase 3: 评估
            eval_report = self.evaluate(round_number, scan_plan, round_states)

            if eval_report.decision == "STOP":
                logger.info("[Agent-P] 评估决策: 终止扫描")
                break
            elif eval_report.decision == "RESCAN":
                for rt in eval_report.rescan_tasks:
                    existing = [t for t in scan_plan.tasks if t.vuln_type == rt.vuln_type]
                    if existing:
                        existing[0].status = "pending"
                        existing[0].priority = 1
                    else:
                        scan_plan.tasks.append(rt)
                logger.info(
                    "[Agent-P] 评估决策: 重扫 %d 个任务",
                    len(eval_report.rescan_tasks),
                )
            else:
                logger.info("[Agent-P] 评估决策: 继续执行剩余任务")

        # 汇总
        total_vulns = sum(len(s.vulnerable_findings) for s in all_states)
        total_pocs = sum(len(s.confirmed_poc_results) for s in all_states)

        summary = {
            "recon_report": recon_report,
            "codebase_profile": codebase_profile,
            "scan_plan": scan_plan,
            "all_states": all_states,
            "rounds_completed": round_number,
            "total_vulnerabilities": total_vulns,
            "total_confirmed_pocs": total_pocs,
            "language": language,
        }

        logger.info("=" * 60)
        logger.info(
            "[Agent-P] 自主扫描完成 | 轮次=%d | 漏洞=%d | PoC=%d",
            round_number, total_vulns, total_pocs,
        )
        logger.info("=" * 60)

        return summary
