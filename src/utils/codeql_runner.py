"""
CodeQL CLI 封装层。

所有对本地 `codeql` 可执行文件的调用均通过此模块进行，
确保超时控制、stderr 捕获与异常隔离。
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 各操作的默认超时秒数
_TIMEOUT_CREATE_DB: int = 3600  # 建库超时：大型项目（如 ByteChef）源码提取可能超过 10 分钟
_TIMEOUT_COMPILE: int = 120
_TIMEOUT_ANALYZE: int = 300


@dataclass
class RunResult:
    """封装 subprocess 调用结果，避免在调用方散落 returncode 判断。"""

    success: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


@dataclass
class CodeQLRunner:
    """
    封装对本地 CodeQL CLI 的调用。

    Attributes:
        codeql_executable: codeql 可执行文件路径，默认假设已在 PATH 中。
    """

    codeql_executable: str = "codeql"

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    def _run(
        self,
        args: list[str],
        timeout: int,
        cwd: str | None = None,
    ) -> RunResult:
        """
        执行一条 codeql 子命令，统一处理超时与异常。

        Args:
            args: 传递给 codeql 的参数列表（不含可执行文件本身）。
            timeout: 超时秒数。
            cwd: 工作目录，None 表示继承当前进程目录。

        Returns:
            RunResult 封装对象。
        """
        cmd = [self.codeql_executable, *args]
        logger.debug("执行命令: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                check=False,  # 手动检查 returncode，以便返回 stderr
            )
        except subprocess.TimeoutExpired as exc:
            msg = f"CodeQL 命令超时（{timeout}s）: {' '.join(cmd)}"
            logger.error(msg)
            return RunResult(success=False, stderr=msg, returncode=-1)
        except FileNotFoundError:
            msg = (
                f"未找到 CodeQL 可执行文件 '{self.codeql_executable}'，"
                "请确认已安装并添加到 PATH。"
            )
            logger.error(msg)
            return RunResult(success=False, stderr=msg, returncode=-1)
        except OSError as exc:
            msg = f"启动 CodeQL 进程时发生 OS 错误: {exc}"
            logger.error(msg)
            return RunResult(success=False, stderr=msg, returncode=-1)

        success = proc.returncode == 0
        if not success:
            logger.warning(
                "CodeQL 命令返回非零退出码 %d\nstderr: %s",
                proc.returncode,
                proc.stderr,
            )
        return RunResult(
            success=success,
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
        )

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def create_database(
        self,
        source_dir: str,
        db_path: str,
        language: str,
        build_command: Optional[str] = None,
        build_mode: str = "",
    ) -> bool:
        """
        调用 `codeql database create` 为指定源码目录创建 CodeQL 数据库。

        Args:
            source_dir: 目标源码根目录的绝对路径。
            db_path: 数据库输出目录路径（不应已存在）。
            language: 目标语言，如 "java"、"python" 等。
            build_command: 可选的编译命令字符串。
                - 传入非空字符串时附加 ``--command=<build_command>``，
                  适用于 Maven / Gradle 等需要显式构建的语言。
                - 传入 None 或空字符串时不附加该参数，
                  CodeQL 将使用 autobuild 机制（适用于 Python 等解释型语言）。
                - 当 build_mode 为 "none" 时此参数被忽略。
            build_mode: CodeQL 构建模式，支持 "none" / "autobuild" / ""。
                - "none"：跳过编译，直接做源码级提取（无需 JDK/Gradle/Maven）。
                  适合快速扫描大型项目或构建环境不完整时使用（CodeQL ≥2.14.6）。
                - "autobuild" 或 ""：使用 CodeQL 自动构建（默认行为）。

        Returns:
            True 表示建库成功，False 表示失败。
        """
        source_path = Path(source_dir)
        if not source_path.is_dir():
            logger.error("源码目录不存在: %s", source_dir)
            return False

        args = [
            "database",
            "create",
            db_path,
            f"--language={language}",
            f"--source-root={source_dir}",
            "--overwrite",  # 允许覆盖已有数据库，方便重跑
        ]

        if build_mode == "none":
            args.append("--build-mode=none")
            logger.info("使用 build-mode=none（源码级提取，跳过编译）。")
        elif build_command:
            args.append(f"--command={build_command}")
            logger.info("使用自定义构建命令: %s", build_command)
        else:
            logger.info("未指定构建命令，CodeQL 将使用 autobuild。")

        result = self._run(args=args, timeout=_TIMEOUT_CREATE_DB)

        if result.success:
            logger.info("CodeQL 数据库创建成功: %s", db_path)
        return result.success

    def install_query_pack(self, query_dir: str) -> bool:
        """
        调用 `codeql pack install` 解析并下载 qlpack.yml 中声明的依赖包。

        必须在 compile_query 之前调用，否则 CodeQL 无法解析标准库模块。

        Args:
            query_dir: 包含 qlpack.yml 的查询目录路径。

        Returns:
            True 表示依赖安装成功，False 表示失败。
        """
        logger.info("正在安装 CodeQL 查询包依赖: %s", query_dir)
        result = self._run(
            args=["pack", "install", query_dir],
            timeout=180,  # 首次下载可能较慢
        )
        if result.success:
            logger.info("CodeQL 包依赖安装成功: %s", query_dir)
        return result.success

    def compile_query(self, query_path: str) -> tuple[bool, str]:
        """
        调用 `codeql query compile` 对 .ql 文件进行语法编译检查。

        此方法是 Agent-Q 自修复循环的关键：通过捕获 stderr 中的报错
        信息反馈给 LLM 进行迭代修正。

        Args:
            query_path: .ql 文件的绝对路径。

        Returns:
            (success, error_message) 二元组。
            - success=True  时 error_message 为空字符串。
            - success=False 时 error_message 包含 codeql 的编译错误输出。
        """
        path = Path(query_path)
        if not path.is_file():
            msg = f".ql 文件不存在: {query_path}"
            logger.error(msg)
            return False, msg

        result = self._run(
            args=["query", "compile", query_path],
            timeout=_TIMEOUT_COMPILE,
        )

        if result.success:
            logger.info("查询编译成功: %s", query_path)
            return True, ""

        # 优先返回 stderr；若为空则降级到 stdout（部分版本行为不同）
        error_output = result.stderr.strip() or result.stdout.strip()
        logger.warning("查询编译失败:\n%s", error_output)
        return False, error_output

    def analyze(
        self,
        db_path: str,
        query_path: str,
        output_sarif: str,
    ) -> bool:
        """
        调用 `codeql database analyze` 运行查询并将结果导出为 SARIF 文件。

        Args:
            db_path: CodeQL 数据库目录路径。
            query_path: 已编译通过的 .ql 文件路径。
            output_sarif: 输出 SARIF 文件路径（含 .sarif 扩展名）。

        Returns:
            True 表示分析成功且 SARIF 文件已生成，False 表示失败。
        """
        # 确保输出目录存在
        output_path = Path(output_sarif)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        result = self._run(
            args=[
                "database",
                "analyze",
                db_path,
                query_path,
                "--format=sarif-latest",
                f"--output={output_sarif}",
                "--rerun",          # 强制重新分析，不使用缓存结果
            ],
            timeout=_TIMEOUT_ANALYZE,
        )

        if result.success and output_path.exists():
            logger.info("分析完成，SARIF 结果已写入: %s", output_sarif)
            return True

        if result.success and not output_path.exists():
            # 命令成功但没有输出文件，属于异常情况
            logger.error(
                "codeql analyze 返回成功但未生成 SARIF 文件: %s", output_sarif
            )
            return False

        return False
