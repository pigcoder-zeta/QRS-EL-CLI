"""
CodeBrowser：符号级代码导航工具（受 K-REPRO 启发）。

K-REPRO (arXiv:2602.07287) 证明 LLM Agent 使用按需代码浏览工具
（而非固定行窗口）可显著提升漏洞理解与复现成功率。

功能：
  1. 符号定义查询 — 全局搜索函数/类/变量的定义位置
  2. 符号引用查询 — 查找某个符号在项目中的所有调用点
  3. 按需代码获取 — 指定文件+行范围获取片段
  4. 数据流追踪   — 从发现点出发，沿调用链展开上下文
  5. 文件符号列表 — 列出文件内所有函数/类定义（避免读取全文）

实现策略：
  - 优先使用 tree-sitter（已安装时），精确解析 AST
  - 降级为正则扫描（零依赖回退）
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_SOURCE_EXTENSIONS: set[str] = {
    ".java", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".cs", ".cpp", ".c", ".h", ".hpp",
    ".kt", ".scala", ".rb", ".php",
}


@dataclass
class SymbolLocation:
    """符号定义/引用位置。"""
    file_path: str
    line: int
    column: int = 0
    symbol_name: str = ""
    kind: str = ""          # "function" / "class" / "method" / "variable" / "reference"
    context_line: str = ""  # 所在行的完整文本


@dataclass
class CodeSnippet:
    """代码片段。"""
    file_path: str
    start_line: int
    end_line: int
    content: str
    total_lines: int = 0


# ---------------------------------------------------------------------------
# 语言专属的符号定义正则模式
# ---------------------------------------------------------------------------

_DEFINITION_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "java": [
        (r"(?:public|private|protected|static|abstract|final|synchronized|native)?\s*(?:class|interface|enum)\s+(\w+)", "class"),
        (r"(?:public|private|protected|static|abstract|final|synchronized|native)?\s*[\w<>\[\],\s]+\s+(\w+)\s*\(", "function"),
    ],
    "python": [
        (r"^\s*class\s+(\w+)", "class"),
        (r"^\s*(?:async\s+)?def\s+(\w+)", "function"),
    ],
    "javascript": [
        (r"(?:class|function)\s+(\w+)", "class"),
        (r"(?:async\s+)?function\s+(\w+)", "function"),
        (r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(", "function"),
        (r"(\w+)\s*:\s*(?:async\s+)?function", "function"),
    ],
    "go": [
        (r"^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(", "function"),
        (r"^type\s+(\w+)\s+(?:struct|interface)", "class"),
    ],
    "csharp": [
        (r"(?:public|private|protected|internal|static|abstract|sealed)?\s*class\s+(\w+)", "class"),
        (r"(?:public|private|protected|internal|static|virtual|override|async)?\s*[\w<>\[\],\s]+\s+(\w+)\s*\(", "function"),
    ],
    "cpp": [
        (r"(?:class|struct)\s+(\w+)", "class"),
        (r"[\w:*&<>\s]+\s+(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:\{|;)", "function"),
    ],
}

_LANG_BY_EXT: dict[str, str] = {
    ".java": "java", ".py": "python", ".js": "javascript", ".ts": "javascript",
    ".jsx": "javascript", ".tsx": "javascript", ".go": "go", ".cs": "csharp",
    ".cpp": "cpp", ".c": "cpp", ".h": "cpp", ".hpp": "cpp",
}


def _detect_lang(file_path: str) -> str:
    """根据文件扩展名推测语言。"""
    ext = Path(file_path).suffix.lower()
    return _LANG_BY_EXT.get(ext, "")


# ---------------------------------------------------------------------------
# CodeBrowser 主类
# ---------------------------------------------------------------------------


class CodeBrowser:
    """
    符号级代码导航工具。

    为 Agent-R 提供主动追踪数据流的能力，替代被动的固定行窗口。

    Args:
        repo_root: 仓库根目录。
        language:  目标语言（用于选择解析规则）。
        max_depth: 数据流追踪最大深度。
    """

    def __init__(
        self,
        repo_root: str,
        language: str = "",
        max_depth: int = 3,
    ) -> None:
        self.repo_root = Path(repo_root)
        self.language = language.lower()
        self.max_depth = max_depth
        self._file_cache: dict[str, list[str]] = {}
        self._symbol_index: dict[str, list[SymbolLocation]] | None = None

    def _read_file(self, file_path: str) -> list[str]:
        """读取文件并缓存行列表。"""
        if file_path not in self._file_cache:
            fp = Path(file_path)
            if not fp.is_absolute():
                fp = self.repo_root / fp
            if not fp.exists():
                return []
            try:
                self._file_cache[file_path] = fp.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                return []
        return self._file_cache[file_path]

    def _iter_source_files(self):
        """遍历仓库中的所有源码文件。"""
        for fp in self.repo_root.rglob("*"):
            if fp.suffix.lower() in _SOURCE_EXTENSIONS and fp.is_file():
                rel = str(fp.relative_to(self.repo_root)).replace("\\", "/")
                # 排除常见无关目录
                if any(seg in rel for seg in ("node_modules/", ".git/", "vendor/", "target/", "build/", "__pycache__/")):
                    continue
                yield fp, rel

    # ------------------------------------------------------------------
    # 1. 符号定义查询
    # ------------------------------------------------------------------

    def find_definition(self, symbol_name: str) -> list[SymbolLocation]:
        """
        全局搜索符号的定义位置。

        Args:
            symbol_name: 要查找的函数/类/方法名。

        Returns:
            SymbolLocation 列表，按文件路径排序。
        """
        results: list[SymbolLocation] = []
        patterns = _DEFINITION_PATTERNS.get(self.language, [])
        if not patterns:
            for lang_patterns in _DEFINITION_PATTERNS.values():
                patterns.extend(lang_patterns)

        for fp, rel in self._iter_source_files():
            try:
                lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                for pattern, kind in patterns:
                    for m in re.finditer(pattern, line):
                        if m.group(1) == symbol_name:
                            results.append(SymbolLocation(
                                file_path=rel, line=i + 1, column=m.start(1),
                                symbol_name=symbol_name, kind=kind,
                                context_line=line.strip(),
                            ))

        logger.debug("[CodeBrowser] find_definition('%s') → %d 结果", symbol_name, len(results))
        return results

    # ------------------------------------------------------------------
    # 2. 符号引用查询
    # ------------------------------------------------------------------

    def find_references(self, symbol_name: str, max_results: int = 30) -> list[SymbolLocation]:
        """
        查找符号在项目中的所有引用点（调用点/使用点）。

        Args:
            symbol_name: 要查找的符号名。
            max_results: 最大返回数。

        Returns:
            SymbolLocation 列表。
        """
        results: list[SymbolLocation] = []
        pattern = re.compile(r'\b' + re.escape(symbol_name) + r'\b')

        for fp, rel in self._iter_source_files():
            try:
                lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if pattern.search(line):
                    results.append(SymbolLocation(
                        file_path=rel, line=i + 1,
                        symbol_name=symbol_name, kind="reference",
                        context_line=line.strip(),
                    ))
                    if len(results) >= max_results:
                        return results

        logger.debug("[CodeBrowser] find_references('%s') → %d 结果", symbol_name, len(results))
        return results

    # ------------------------------------------------------------------
    # 3. 按需代码获取
    # ------------------------------------------------------------------

    def get_snippet(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
    ) -> CodeSnippet:
        """
        获取文件指定行范围的代码片段。

        Args:
            file_path: 文件路径（相对于仓库根目录）。
            start_line: 起始行号（1-indexed，含）。
            end_line: 结束行号（1-indexed，含）。

        Returns:
            CodeSnippet 对象。
        """
        lines = self._read_file(file_path)
        if not lines:
            return CodeSnippet(file_path=file_path, start_line=start_line,
                               end_line=end_line, content="（无法读取文件）")

        lo = max(0, start_line - 1)
        hi = min(len(lines), end_line)
        numbered = [f"{lo + i + 1:4d} | {lines[lo + i]}" for i in range(hi - lo)]
        return CodeSnippet(
            file_path=file_path,
            start_line=lo + 1,
            end_line=hi,
            content="\n".join(numbered),
            total_lines=len(lines),
        )

    # ------------------------------------------------------------------
    # 4. 数据流追踪
    # ------------------------------------------------------------------

    def trace_data_flow(
        self,
        file_path: str,
        center_line: int,
        window: int = 15,
        depth: int = 2,
    ) -> str:
        """
        从发现点出发，追踪关键符号的定义与调用链，构建富上下文。

        策略：
          1. 先获取中心点 ±window 行的基础上下文
          2. 从基础上下文中提取关键方法调用
          3. 对每个关键方法，查找其定义处的代码片段
          4. 合并为完整的数据流上下文

        Args:
            file_path: 发现所在文件。
            center_line: 发现行号。
            window: 基础窗口大小。
            depth: 追踪深度（查找几层调用）。

        Returns:
            包含数据流上下文的富文本字符串。
        """
        parts: list[str] = []

        # 基础上下文
        base = self.get_snippet(file_path, center_line - window, center_line + window)
        parts.append(f"=== 漏洞位置: {file_path}:{center_line} ===\n{base.content}")

        if depth <= 0:
            return "\n\n".join(parts)

        # 从基础上下文提取可能的方法调用
        called_methods = self._extract_method_calls(base.content)
        tracked: set[str] = set()

        for method_name in called_methods[:5]:
            if method_name in tracked or len(method_name) < 3:
                continue
            tracked.add(method_name)

            defs = self.find_definition(method_name)
            if not defs:
                continue

            # 取第一个定义，获取其上下文
            d = defs[0]
            snippet = self.get_snippet(d.file_path, d.line - 3, d.line + 12)
            parts.append(
                f"=== {method_name}() 定义: {d.file_path}:{d.line} ===\n{snippet.content}"
            )

        return "\n\n".join(parts)

    def _extract_method_calls(self, code: str) -> list[str]:
        """从代码片段中提取方法调用名（去重，按出现顺序）。"""
        # 匹配 xxx.methodName( 或 methodName( 的形式
        pattern = re.compile(r'\.?(\w{3,})\s*\(')
        seen: set[str] = set()
        results: list[str] = []
        # 排除常见关键字
        skip = {"for", "if", "while", "switch", "catch", "return", "new", "throw",
                "class", "def", "func", "var", "let", "const", "import", "from",
                "try", "else", "elif", "case", "public", "private", "static",
                "void", "int", "str", "bool", "string", "println", "print", "log"}
        for m in pattern.finditer(code):
            name = m.group(1)
            if name not in seen and name.lower() not in skip:
                seen.add(name)
                results.append(name)
        return results

    # ------------------------------------------------------------------
    # 5. 文件符号列表
    # ------------------------------------------------------------------

    def list_symbols(self, file_path: str) -> list[SymbolLocation]:
        """
        列出文件内所有函数/类定义（不读取全文，只返回签名）。

        Args:
            file_path: 文件路径。

        Returns:
            SymbolLocation 列表。
        """
        lines = self._read_file(file_path)
        if not lines:
            return []

        lang = _detect_lang(file_path) or self.language
        patterns = _DEFINITION_PATTERNS.get(lang, [])
        if not patterns:
            for lp in _DEFINITION_PATTERNS.values():
                patterns.extend(lp)

        results: list[SymbolLocation] = []
        for i, line in enumerate(lines):
            for pattern, kind in patterns:
                for m in re.finditer(pattern, line):
                    results.append(SymbolLocation(
                        file_path=file_path, line=i + 1, column=m.start(1),
                        symbol_name=m.group(1), kind=kind,
                        context_line=line.strip(),
                    ))
        return results

    # ------------------------------------------------------------------
    # 6. 智能上下文构建（Agent-R 核心接口）
    # ------------------------------------------------------------------

    def build_rich_context(
        self,
        file_uri: str,
        center_line: int,
        sink_method: str = "",
        base_window: int = 15,
        max_trace_depth: int = 2,
    ) -> str:
        """
        为 Agent-R 构建富上下文：基础窗口 + 关键方法定义追踪。

        与固定 ±15 行窗口相比，此方法能：
          - 自动追踪 Sink 方法的定义源码
          - 追踪中间调用链的关键节点
          - 在不超出 token 预算的前提下提供最大信息量

        Args:
            file_uri: SARIF 中的文件 URI。
            center_line: 发现行号。
            sink_method: Agent-R 识别的 Sink 方法名（优先追踪）。
            base_window: 基础窗口大小。
            max_trace_depth: 追踪深度。

        Returns:
            富上下文字符串（带行号前缀）。
        """
        clean_uri = file_uri.removeprefix("file://").lstrip("/")
        parts: list[str] = []

        # 1. 基础上下文（与旧版兼容的固定窗口）
        base = self.get_snippet(clean_uri, center_line - base_window, center_line + base_window)
        parts.append(base.content)

        # 2. 优先追踪 Sink 方法定义
        if sink_method:
            method_name = sink_method.split("(")[0].split(".")[-1]
            if method_name and len(method_name) >= 3:
                defs = self.find_definition(method_name)
                for d in defs[:2]:
                    if d.file_path != clean_uri or abs(d.line - center_line) > base_window:
                        snippet = self.get_snippet(d.file_path, d.line - 3, d.line + 15)
                        parts.append(
                            f"\n--- Sink 方法 {method_name}() 定义: {d.file_path}:{d.line} ---\n"
                            f"{snippet.content}"
                        )

        # 3. 追踪基础上下文中的关键调用
        if max_trace_depth > 0:
            called = self._extract_method_calls(base.content)
            tracked: set[str] = {sink_method.split("(")[0].split(".")[-1]} if sink_method else set()

            for method_name in called[:4]:
                if method_name in tracked or len(method_name) < 3:
                    continue
                tracked.add(method_name)

                defs = self.find_definition(method_name)
                for d in defs[:1]:
                    if d.file_path != clean_uri or abs(d.line - center_line) > base_window:
                        snippet = self.get_snippet(d.file_path, d.line - 2, d.line + 10)
                        parts.append(
                            f"\n--- 调用链: {method_name}() @ {d.file_path}:{d.line} ---\n"
                            f"{snippet.content}"
                        )

        result = "\n".join(parts)
        # 限制总长度（避免超出 LLM 上下文窗口）
        if len(result) > 8000:
            result = result[:8000] + "\n... (上下文已截断)"

        return result
