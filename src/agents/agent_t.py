"""
Agent-T（Triage Agent）：代码库类型分类与扫描架构选择。

在 Agent-P 侦察（recon）之后、规划（plan）之前执行，根据代码库特征
自动判断项目类型，并输出 CodebaseProfile 驱动后续扫描策略。

支持的代码库类型：
  - web_app        — Spring Boot / Django / Express / Flask 等 Web 应用
  - kernel_module  — Linux 内核代码（驱动、子系统、模块）
  - system_service — 系统级 C/C++ 服务（守护进程、CLI 工具）
  - library        — 被其他项目引用的库（SDK、中间件）
  - mobile_app     — Android / iOS 应用
  - smart_contract — Solidity 智能合约
  - embedded_firmware — 嵌入式/IoT 固件
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

CODEBASE_TYPES = (
    "web_app",
    "kernel_module",
    "system_service",
    "library",
    "mobile_app",
    "smart_contract",
    "embedded_firmware",
)


@dataclass
class CodebaseProfile:
    """代码库分类结果，驱动后续扫描架构。"""

    codebase_type: str = "web_app"
    attack_surface: list[str] = field(default_factory=list)
    vuln_focus: list[str] = field(default_factory=list)
    prompt_preset: str = ""
    context_window: int = 30
    recommended_vuln_types: list[str] = field(default_factory=list)
    confidence: float = 1.0
    reasoning: str = ""

    def to_summary(self) -> str:
        return (
            f"类型: {self.codebase_type}\n"
            f"攻击面: {', '.join(self.attack_surface) or '通用'}\n"
            f"漏洞重点: {', '.join(self.vuln_focus) or '通用'}\n"
            f"Prompt 预设: {self.prompt_preset or 'default'}\n"
            f"上下文窗口: ±{self.context_window} 行\n"
            f"推荐漏洞类型: {', '.join(self.recommended_vuln_types) or '由 Agent-P 决定'}\n"
            f"置信度: {self.confidence:.0%}\n"
            f"理由: {self.reasoning}"
        )


# ---------------------------------------------------------------------------
# 各类型的策略 Preset
# ---------------------------------------------------------------------------

_PRESETS: dict[str, dict[str, Any]] = {
    "web_app": {
        "attack_surface": [
            "HTTP 参数", "Cookie", "Header", "Request Body",
            "URL 路径", "文件上传",
        ],
        "vuln_focus": [
            "SQL Injection", "Command Injection", "XSS",
            "SSRF", "Path Traversal", "Deserialization",
            "Expression Language Injection",
        ],
        "prompt_preset": "",
        "context_window": 30,
        "recommended_vuln_types": [
            "SQL Injection", "Command Injection", "XSS",
            "SSRF", "Path Traversal", "Deserialization",
        ],
    },
    "kernel_module": {
        "attack_surface": [
            "copy_from_user / get_user",
            "ioctl 参数",
            "sysfs / procfs 输入",
            "netlink 消息",
            "设备文件 read/write",
        ],
        "vuln_focus": [
            "Kernel UAF", "Kernel OOB", "Kernel Race Condition",
            "Kernel Privilege Escalation", "Kernel Null Pointer Dereference",
            "Kernel Integer Overflow", "Kernel Information Leak",
        ],
        "prompt_preset": "kernel",
        "context_window": 50,
        "recommended_vuln_types": [
            "Kernel UAF", "Kernel OOB", "Kernel Race Condition",
            "Kernel Privilege Escalation", "Kernel Integer Overflow",
        ],
    },
    "system_service": {
        "attack_surface": [
            "命令行参数 (argv)", "环境变量 (getenv)",
            "网络输入 (recv/read)", "文件输入 (fgets/scanf)",
            "IPC / 共享内存",
        ],
        "vuln_focus": [
            "Command Injection", "Buffer Overflow",
            "Format String", "Path Traversal",
            "Integer Overflow", "Use After Free",
        ],
        "prompt_preset": "cpp",
        "context_window": 40,
        "recommended_vuln_types": [
            "Command Injection", "Buffer Overflow",
            "Format String", "Path Traversal",
        ],
    },
    "library": {
        "attack_surface": [
            "公共 API 入参", "回调 / 事件处理",
            "配置文件解析", "序列化输入",
        ],
        "vuln_focus": [
            "Deserialization", "Path Traversal",
            "Prototype Pollution", "ReDoS",
        ],
        "prompt_preset": "",
        "context_window": 30,
        "recommended_vuln_types": [
            "Deserialization", "Path Traversal",
        ],
    },
    "mobile_app": {
        "attack_surface": [
            "Intent / Deep Link", "ContentProvider",
            "WebView JavaScript Bridge", "SharedPreferences",
            "网络请求",
        ],
        "vuln_focus": [
            "Intent 劫持", "不安全存储", "WebView RCE",
            "证书校验绕过", "SQL Injection",
        ],
        "prompt_preset": "java",
        "context_window": 30,
        "recommended_vuln_types": [
            "SQL Injection", "Path Traversal",
            "Deserialization", "XSS",
        ],
    },
    "smart_contract": {
        "attack_surface": [
            "external / public 函数", "msg.sender / msg.value",
            "delegatecall", "跨合约调用",
        ],
        "vuln_focus": [
            "Reentrancy", "Integer Overflow",
            "Access Control", "Unchecked Return",
        ],
        "prompt_preset": "solidity",
        "context_window": 40,
        "recommended_vuln_types": [
            "Reentrancy", "Integer Overflow", "Access Control",
        ],
    },
    "embedded_firmware": {
        "attack_surface": [
            "串口输入", "网络接口 (UART/SPI/I2C)",
            "固件更新接口", "Web 管理界面",
        ],
        "vuln_focus": [
            "Command Injection", "Buffer Overflow",
            "Hardcoded Credentials", "Format String",
        ],
        "prompt_preset": "cpp",
        "context_window": 40,
        "recommended_vuln_types": [
            "Command Injection", "Buffer Overflow",
            "Hardcoded Credentials",
        ],
    },
}

# ---------------------------------------------------------------------------
# 内核代码指纹
# ---------------------------------------------------------------------------

_KERNEL_HEADER_PATTERNS = [
    re.compile(r"#include\s+<linux/"),
    re.compile(r"#include\s+<asm/"),
    re.compile(r"module_init\s*\("),
    re.compile(r"module_exit\s*\("),
    re.compile(r"MODULE_LICENSE\s*\("),
    re.compile(r"EXPORT_SYMBOL"),
    re.compile(r"copy_from_user\s*\("),
    re.compile(r"copy_to_user\s*\("),
    re.compile(r"kmalloc\s*\("),
    re.compile(r"kfree\s*\("),
    re.compile(r"printk\s*\("),
    re.compile(r"spin_lock|mutex_lock|rcu_read_lock"),
]

_FIRMWARE_INDICATORS = [
    "Makefile", "CMakeLists.txt", "linker.ld", "startup.s",
    "FreeRTOSConfig.h", "stm32", "esp_idf", "zephyr",
]


# ---------------------------------------------------------------------------
# AgentT 主类
# ---------------------------------------------------------------------------


class AgentT:
    """
    代码库分类 Agent。

    两阶段判定：
      1. 规则引擎（快速确定性判断，覆盖 >90% 场景）
      2. LLM 兜底（规则引擎不确定时调用）
    """

    def __init__(self, llm: Any = None) -> None:
        self._llm = llm

    def _get_llm(self) -> Any:
        if self._llm:
            return self._llm
        from langchain_openai import ChatOpenAI
        self._llm = ChatOpenAI(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
            temperature=0.0,
            base_url=os.environ.get("OPENAI_BASE_URL") or None,
            timeout=60,
            max_tokens=512,
        )
        return self._llm

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def classify(
        self,
        recon_report: Any,
        source_dir: str,
    ) -> CodebaseProfile:
        """
        根据侦察报告和源码目录，判定代码库类型并返回扫描策略。

        Args:
            recon_report: Agent-P 的 ReconReport。
            source_dir: 源码根目录。

        Returns:
            CodebaseProfile 分类结果。
        """
        logger.info("[Agent-T] 开始代码库分类: %s", source_dir)
        root = Path(source_dir)

        ctype, confidence, reasoning = self._rule_classify(recon_report, root)

        if confidence < 0.6:
            logger.info("[Agent-T] 规则引擎置信度不足 (%.0f%%), 调用 LLM", confidence * 100)
            ctype, confidence, reasoning = self._llm_classify(recon_report, root)

        preset = _PRESETS.get(ctype, _PRESETS["web_app"])
        profile = CodebaseProfile(
            codebase_type=ctype,
            attack_surface=preset["attack_surface"],
            vuln_focus=preset["vuln_focus"],
            prompt_preset=preset["prompt_preset"],
            context_window=preset["context_window"],
            recommended_vuln_types=preset["recommended_vuln_types"],
            confidence=confidence,
            reasoning=reasoning,
        )

        logger.info(
            "[Agent-T] 分类完成: type=%s, confidence=%.0f%%, reason=%s",
            ctype, confidence * 100, reasoning[:80],
        )
        return profile

    # ------------------------------------------------------------------
    # 规则引擎
    # ------------------------------------------------------------------

    def _rule_classify(
        self,
        report: Any,
        root: Path,
    ) -> tuple[str, float, str]:
        """基于文件特征和侦察报告进行确定性分类。"""

        primary = getattr(report, "primary_language", "").lower()
        frameworks = [f.lower() for f in getattr(report, "frameworks", [])]
        has_android = getattr(report, "has_android", False)
        has_solidity = getattr(report, "has_solidity", False)

        # 1) Solidity → smart_contract
        if has_solidity or primary == "solidity":
            return ("smart_contract", 0.95, "检测到 Solidity 源码")

        # 2) Android
        if has_android or "android" in frameworks:
            return ("mobile_app", 0.95, "检测到 AndroidManifest.xml 或 Android 框架")

        # 3) Linux Kernel
        kernel_score = self._score_kernel(root)
        if kernel_score >= 0.7:
            return ("kernel_module", kernel_score, f"内核指纹匹配度 {kernel_score:.0%}")

        # 4) Web 框架
        web_frameworks = {
            "spring-boot", "spring", "django", "flask", "express",
            "fastapi", "gin", "echo", "koa", "nestjs", "rails",
            "laravel", "asp.net",
        }
        if any(fw in web_frameworks for fw in frameworks):
            return ("web_app", 0.95, f"检测到 Web 框架: {frameworks}")

        # 5) 嵌入式固件
        if self._check_firmware(root):
            return ("embedded_firmware", 0.8, "检测到固件/嵌入式项目特征")

        # 6) C/C++ 无 Web 框架 → system_service
        if primary in ("cpp", "c"):
            return ("system_service", 0.7, "主语言为 C/C++ 且无 Web 框架")

        # 7) 有入口点（main/app）vs 库
        entry_points = getattr(report, "entry_points", [])
        if not entry_points and primary in ("python", "javascript", "java"):
            return ("library", 0.5, "未检测到明确入口点，可能是库")

        # 8) 默认 web_app（置信度低，触发 LLM）
        if primary in ("java", "python", "javascript", "go", "csharp"):
            return ("web_app", 0.55, f"主语言 {primary}，未匹配特定类型")

        return ("library", 0.4, f"无法确定类型，主语言 {primary}")

    def _score_kernel(self, root: Path) -> float:
        """扫描源文件，计算内核代码指纹匹配度。"""
        # 快速检查标志文件
        kconfig = root / "Kconfig"
        if kconfig.exists():
            return 0.95

        # 检查 Makefile 中的 obj-m / obj-y
        for mf in [root / "Makefile", root / "makefile"]:
            if mf.exists():
                try:
                    text = mf.read_text(encoding="utf-8", errors="ignore")[:4000]
                    if re.search(r"obj-[my]\s*[+:]?=", text):
                        return 0.9
                except OSError:
                    pass

        # 采样 C/H 文件检查内核头文件
        hit_count = 0
        sample_count = 0
        max_sample = 50

        for fp in root.rglob("*"):
            if fp.suffix.lower() not in (".c", ".h"):
                continue
            if any(seg in fp.parts for seg in (".git", "vendor", "node_modules")):
                continue
            sample_count += 1
            if sample_count > max_sample:
                break
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")[:3000]
            except OSError:
                continue
            hits = sum(1 for pat in _KERNEL_HEADER_PATTERNS if pat.search(text))
            if hits >= 3:
                hit_count += 1

        if sample_count == 0:
            return 0.0
        ratio = hit_count / sample_count
        if ratio >= 0.5:
            return 0.9
        if ratio >= 0.2:
            return 0.75
        if ratio >= 0.05:
            return 0.5
        return 0.1

    def _check_firmware(self, root: Path) -> bool:
        """检查是否为嵌入式固件项目。"""
        for name in _FIRMWARE_INDICATORS:
            matches = list(root.rglob(name))
            if matches:
                return True
        for fp in root.rglob("*.ld"):
            return True
        return False

    # ------------------------------------------------------------------
    # LLM 兜底
    # ------------------------------------------------------------------

    def _llm_classify(
        self,
        report: Any,
        root: Path,
    ) -> tuple[str, float, str]:
        """规则引擎不确定时，用 LLM 辅助判断。"""
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_core.output_parsers import StrOutputParser

        sample_files = self._sample_file_listing(root, max_files=40)
        recon_summary = report.to_summary() if hasattr(report, "to_summary") else str(report)

        prompt = f"""\
根据以下信息判断代码库类型。

侦察报告：
{recon_summary}

文件结构样本：
{sample_files}

可选类型: {', '.join(CODEBASE_TYPES)}

输出严格 JSON（不要代码块标记）：
{{"codebase_type": "类型名", "confidence": 0.0~1.0, "reasoning": "判断理由"}}
"""
        try:
            llm = self._get_llm()
            chain = llm | StrOutputParser()
            raw = chain.invoke([
                SystemMessage(content="你是代码库分类专家。只输出 JSON。"),
                HumanMessage(content=prompt),
            ])
            text = raw.strip()
            if "```" in text:
                m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
                if m:
                    text = m.group(1).strip()
            result = json.loads(text)
            ctype = result.get("codebase_type", "web_app")
            if ctype not in CODEBASE_TYPES:
                ctype = "web_app"
            return (
                ctype,
                float(result.get("confidence", 0.7)),
                result.get("reasoning", "LLM 分类"),
            )
        except Exception as exc:
            logger.warning("[Agent-T] LLM 分类失败: %s", exc)
            return ("web_app", 0.5, f"LLM 分类失败，默认 web_app: {exc}")

    def _sample_file_listing(self, root: Path, max_files: int = 40) -> str:
        """生成文件列表样本供 LLM 参考。"""
        skip = {".git", "node_modules", "__pycache__", "vendor", "build", "target"}
        lines: list[str] = []
        count = 0
        for fp in root.rglob("*"):
            if fp.is_dir():
                continue
            if any(seg in fp.parts for seg in skip):
                continue
            try:
                rel = fp.relative_to(root)
            except ValueError:
                continue
            lines.append(str(rel).replace("\\", "/"))
            count += 1
            if count >= max_files:
                lines.append(f"... (共 {sum(1 for _ in root.rglob('*') if _.is_file())}+ 个文件)")
                break
        return "\n".join(lines)
