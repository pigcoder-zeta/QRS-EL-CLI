"""
GitHub 仓库管理器。

负责克隆远程仓库到本地，以及探测项目的构建方式，
为 CodeQLRunner.create_database() 提供正确的 build_command。
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

import threading

import git
from git import GitCommandError, InvalidGitRepositoryError, Repo

logger = logging.getLogger(__name__)

# git clone 网络超时（秒）——通过 GIT_TERMINAL_PROMPT 等环境变量控制
_CLONE_TIMEOUT_S: int = 300

# 各语言对应的"解释型"标识：这些语言不需要编译步骤
_INTERPRETED_LANGUAGES: frozenset[str] = frozenset(
    {"python", "javascript", "typescript", "ruby", "go"}
)

# Java 构建文件优先级（按顺序探测）
# 注意：Gradle Wrapper（gradlew.bat / gradlew）优先于全局 gradle 命令，
# 因为大多数项目自带 wrapper，不依赖系统全局安装。
import sys as _sys
_GRADLE_CMD = "gradlew.bat" if _sys.platform == "win32" else "./gradlew"
_GRADLE_FALLBACK = "gradle"

_JAVA_BUILD_FILES: list[tuple[str, str, str | None]] = [
    # (构建文件, wrapper命令, 全局fallback命令)
    ("pom.xml",          "mvn clean install -DskipTests", "mvn clean install -DskipTests"),
    ("build.gradle",     f"{_GRADLE_CMD} build -x test",  f"{_GRADLE_FALLBACK} build -x test"),
    ("build.gradle.kts", f"{_GRADLE_CMD} build -x test",  f"{_GRADLE_FALLBACK} build -x test"),
]


class RepoCloneError(RuntimeError):
    """仓库克隆失败时抛出。"""


class GithubRepoManager:
    """
    封装 GitHub 仓库的克隆与构建方式探测。

    Attributes:
        clone_timeout: git clone 操作的超时秒数。
    """

    def __init__(self, clone_timeout: int = _CLONE_TIMEOUT_S) -> None:
        self.clone_timeout = clone_timeout

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def clone_repo(self, repo_url: str, dest_dir: str) -> str:
        """
        将 GitHub 仓库克隆到本地目录。

        若目标目录已存在且是合法的 Git 仓库，则跳过克隆直接返回路径
        （幂等行为，便于断点续跑）。

        Args:
            repo_url: 仓库的完整 HTTPS/SSH URL，
                      例如 "https://github.com/WebGoat/WebGoat.git"。
            dest_dir: 本地目标目录路径（父目录必须已存在）。

        Returns:
            克隆成功后的本地仓库根目录绝对路径字符串。

        Raises:
            RepoCloneError: 克隆失败（网络超时、鉴权失败、URL 无效等）时抛出。
        """
        dest_path = Path(dest_dir)

        # ── 幂等检查：目录已是合法 Git 仓库 ────────────────────────────
        if dest_path.exists():
            try:
                Repo(str(dest_path))
                logger.info("目标目录已是 Git 仓库，跳过克隆: %s", dest_path)
                return str(dest_path.resolve())
            except InvalidGitRepositoryError:
                # 目录存在但不是 Git 仓库，清空后重新克隆
                logger.warning("目标目录存在但非 Git 仓库，将清空并重新克隆: %s", dest_path)
                shutil.rmtree(dest_path, ignore_errors=True)

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("正在克隆仓库: %s -> %s", repo_url, dest_path)

        # GitPython 的 clone_from 不支持直接传超时参数；
        # 用 threading.Timer 在后台强制终止超时的克隆进程。
        clone_exc: list[Exception] = []
        result_repo: list[Repo] = []

        def _do_clone() -> None:
            try:
                repo = Repo.clone_from(
                    url=repo_url,
                    to_path=str(dest_path),
                    depth=1,   # 浅克隆，只取最新提交，节省流量
                    # Windows 长路径支持：allow_unsafe_options=True 允许 --config 参数
                    multi_options=["--config", "core.longpaths=true"],
                    allow_unsafe_options=True,
                )
                result_repo.append(repo)
            except Exception as exc:  # noqa: BLE001
                clone_exc.append(exc)

        thread = threading.Thread(target=_do_clone, daemon=True)
        thread.start()
        thread.join(timeout=self.clone_timeout)

        if thread.is_alive():
            # 超时：线程仍在运行，清理目录后抛出异常
            shutil.rmtree(dest_path, ignore_errors=True)
            msg = f"克隆仓库超时（>{self.clone_timeout}s）: {repo_url}"
            logger.error(msg)
            raise RepoCloneError(msg)

        if clone_exc:
            exc = clone_exc[0]
            stderr_raw = getattr(exc, "stderr", str(exc)).strip()

            # ── 容错：Git 有时报告 "Clone succeeded, but checkout failed" ──
            # 这发生在部分文件因 Windows 路径限制无法写出时。
            # 只要仓库对象完整（.git 目录存在），就可以继续扫描——
            # 因为失败的通常是前端 TS 文件，Java 后端代码仍然完好。
            if dest_path.exists():
                try:
                    Repo(str(dest_path))
                    logger.warning(
                        "克隆时部分文件 checkout 失败（Windows 路径过长），"
                        "但 Git 对象库完整，将继续扫描。\n"
                        "建议执行以下命令永久解决此问题：\n"
                        "  git config --global core.longpaths true\n"
                        "  (管理员) reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem "
                        "/v LongPathsEnabled /t REG_DWORD /d 1 /f\n"
                        "首次失败详情（已截断）: %s",
                        stderr_raw[:400],
                    )
                    # 视为成功：目录可用，跳出错误处理
                    logger.info("仓库克隆（部分）完成: %s", dest_path)
                    return str(dest_path.resolve())
                except InvalidGitRepositoryError:
                    pass  # 目录损坏，走正常失败流程

            msg = f"克隆仓库失败 [{repo_url}]: {stderr_raw}"
            logger.error(msg)
            raise RepoCloneError(msg) from exc

        logger.info("仓库克隆完成: %s", dest_path)
        return str(dest_path.resolve())

    def detect_build_command(self, repo_path: str, language: str) -> str:
        """
        探测仓库根目录的构建方式，返回对应的构建命令字符串。

        规则：
        - 解释型语言（Python / JavaScript 等）：直接返回 ""，
          CodeQL 对这类语言不需要 --command 参数。
        - Java：
            按 pom.xml → build.gradle → build.gradle.kts 顺序探测，
            命中则返回对应命令；均未发现则返回 ""（让 CodeQL autobuild 处理）。
        - 其他编译型语言：返回 ""，依赖 CodeQL autobuild。

        Args:
            repo_path: 本地仓库根目录路径。
            language: 目标语言标识（小写），如 "java"、"python"。

        Returns:
            构建命令字符串，例如 "mvn clean install -DskipTests"，
            或空字符串（表示不传 --command 给 CodeQL）。
        """
        lang = language.lower()
        root = Path(repo_path)

        if lang in _INTERPRETED_LANGUAGES:
            logger.info("语言 '%s' 为解释型，无需构建命令。", language)
            return ""

        if lang == "java":
            # 优先使用 Gradle Wrapper（项目自带，不依赖系统全局 gradle）
            gradle_wrapper = _GRADLE_CMD  # gradlew.bat (Windows) 或 ./gradlew (Unix)
            has_wrapper = (root / gradle_wrapper.lstrip("./")).exists()

            for filename, wrapper_cmd, fallback_cmd in _JAVA_BUILD_FILES:
                if (root / filename).exists():
                    # Gradle 系构建文件：优先用 wrapper，否则退回全局命令
                    if "gradle" in filename and not has_wrapper:
                        command = fallback_cmd
                    else:
                        command = wrapper_cmd
                    logger.info(
                        "探测到 %s，将使用构建命令: %s", filename, command
                    )
                    return command

            logger.info(
                "未在根目录发现已知 Java 构建文件（pom.xml / build.gradle），"
                "将依赖 CodeQL autobuild。"
            )
            return ""

        # 其余编译型语言（csharp / cpp 等）暂交 autobuild
        logger.info("语言 '%s' 使用 CodeQL autobuild（未配置自定义命令）。", language)
        return ""

    def detect_frameworks(self, repo_path: str) -> set[str]:
        """
        扫描构建文件，检测项目使用的表达式语言框架。

        解析 pom.xml / build.gradle / build.gradle.kts / requirements.txt 中的
        依赖声明，返回检测到的框架关键字集合。

        Args:
            repo_path: 本地仓库根目录路径。

        Returns:
            框架名称集合，例如 {"spring", "ognl", "mvel"}。
            空集合表示未检测到已知框架。
        """
        root = Path(repo_path)
        found: set[str] = set()

        # ── 关键字映射：构建文件内容关键字 → 框架标签 ────────────────
        _KEYWORD_MAP: list[tuple[str, str]] = [
            ("spring",          "spring"),
            ("springframework", "spring"),
            ("ognl",            "ognl"),
            ("mvel",            "mvel"),
            ("jinja2",          "jinja2"),
            ("mako",            "mako"),
            ("freemarker",      "freemarker"),
            ("thymeleaf",       "thymeleaf"),
            ("velocity",        "velocity"),
            ("groovy",          "groovy"),
            ("spel",            "spring"),
            ("el-api",          "el"),
        ]

        build_files = [
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "requirements.txt",
            "setup.py",
            "Pipfile",
        ]

        for fname in build_files:
            fpath = root / fname
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore").lower()
                for keyword, label in _KEYWORD_MAP:
                    if keyword in content:
                        found.add(label)
            except OSError:
                continue

        if found:
            logger.info("检测到项目使用的框架/表达式引擎: %s", ", ".join(sorted(found)))
        else:
            logger.info("未从构建文件中检测到已知框架依赖。")

        return found

    def get_repo_head_hash(self, repo_path: str) -> str:
        """
        获取本地仓库 HEAD 提交的 SHA 哈希（前 12 位）。

        用于数据库增量缓存键，相同 commit 无需重新建库。

        Args:
            repo_path: 本地仓库根目录路径。

        Returns:
            12 位 commit hash 字符串，获取失败时返回空字符串。
        """
        try:
            repo = Repo(repo_path)
            return repo.head.commit.hexsha[:12]
        except Exception as exc:  # noqa: BLE001
            logger.warning("获取 HEAD hash 失败: %s", exc)
            return ""

    def cleanup(self, repo_path: str) -> None:
        """
        删除本地克隆目录，释放磁盘空间。

        此方法应在 try...finally 块中调用，确保即使扫描失败也能清理。

        Args:
            repo_path: 要删除的本地仓库目录路径。
        """
        path = Path(repo_path)
        if path.exists():
            logger.info("正在清理临时克隆目录: %s", path)
            shutil.rmtree(path, ignore_errors=True)
            logger.info("临时目录已清理: %s", path)
        else:
            logger.debug("清理目标不存在，跳过: %s", path)
