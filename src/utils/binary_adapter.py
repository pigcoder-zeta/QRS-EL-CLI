"""
二进制/固件安全：外部工具集成适配器。

支持将 Ghidra / Binwalk / Radare2 / Cppcheck 等工具的输出
转换为 SARIF 格式，对接 Argus 的 --external-sarif 流水线。

工作流程：
1. firmware_extract()  — 调用 Binwalk 解包固件，提取文件系统
2. ghidra_analyze()    — 调用 Ghidra headless 模式进行反编译分析
3. normalize_to_sarif() — 将各种工具输出统一转换为 SARIF
"""

from __future__ import annotations

import json
import logging
import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class BinaryFinding:
    """二进制分析发现。"""
    tool: str
    rule_id: str
    severity: str       # error / warning / note
    message: str
    file_path: str
    line_number: int = 0
    function_name: str = ""
    address: str = ""   # 二进制地址（如 0x08001234）


# ---------------------------------------------------------------------------
# Binwalk 固件提取
# ---------------------------------------------------------------------------

def firmware_extract(
    firmware_path: str,
    output_dir: str,
    binwalk_cmd: str = "binwalk",
) -> Optional[str]:
    """
    使用 Binwalk 解包固件镜像。

    Returns:
        解包后的根目录路径，失败返回 None。
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [binwalk_cmd, "-e", "-C", str(out), str(firmware_path)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            logger.warning("Binwalk 解包失败: %s", result.stderr[:500])
            return None

        extracted = list(out.rglob("*squashfs*")) or list(out.rglob("*filesystem*"))
        if extracted:
            logger.info("Binwalk 解包成功: %s", extracted[0])
            return str(extracted[0])

        subdirs = [d for d in out.iterdir() if d.is_dir()]
        if subdirs:
            return str(subdirs[0])

        logger.warning("Binwalk 解包后未找到文件系统")
        return str(out)

    except FileNotFoundError:
        logger.error("未找到 Binwalk，请安装: pip install binwalk")
        return None
    except subprocess.TimeoutExpired:
        logger.error("Binwalk 解包超时（>300s）")
        return None


# ---------------------------------------------------------------------------
# Ghidra headless 分析
# ---------------------------------------------------------------------------

def ghidra_analyze(
    binary_path: str,
    ghidra_home: str,
    project_dir: str = "/tmp/ghidra_project",
    script: str = "FindVulnerabilities.java",
    output_file: str = "/tmp/ghidra_results.json",
) -> list[BinaryFinding]:
    """
    调用 Ghidra headless 模式分析二进制文件。

    Args:
        binary_path: 待分析的二进制文件路径。
        ghidra_home: Ghidra 安装目录（如 /opt/ghidra）。
        project_dir: Ghidra 临时项目目录。
        script: Ghidra 分析脚本名称。
        output_file: 结果输出文件路径。

    Returns:
        BinaryFinding 列表。
    """
    headless = Path(ghidra_home) / "support" / "analyzeHeadless"
    if not headless.exists():
        headless = Path(ghidra_home) / "support" / "analyzeHeadless.bat"

    if not headless.exists():
        logger.error("未找到 Ghidra analyzeHeadless: %s", headless)
        return []

    Path(project_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        str(headless),
        project_dir, "qrse_analysis",
        "-import", binary_path,
        "-postScript", script, output_file,
        "-deleteProject",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            logger.warning("Ghidra 分析失败: %s", result.stderr[:500])
            return []

        return _parse_ghidra_output(output_file, binary_path)

    except FileNotFoundError:
        logger.error("Ghidra headless 执行失败")
        return []
    except subprocess.TimeoutExpired:
        logger.error("Ghidra 分析超时（>600s）")
        return []


def _parse_ghidra_output(output_file: str, binary_path: str) -> list[BinaryFinding]:
    """解析 Ghidra 脚本输出的 JSON 格式结果。"""
    findings = []
    try:
        data = json.loads(Path(output_file).read_text(encoding="utf-8"))
        for item in data if isinstance(data, list) else data.get("findings", []):
            findings.append(BinaryFinding(
                tool="ghidra",
                rule_id=item.get("type", "unknown"),
                severity=item.get("severity", "warning"),
                message=item.get("description", ""),
                file_path=binary_path,
                function_name=item.get("function", ""),
                address=item.get("address", ""),
            ))
    except Exception as exc:
        logger.debug("解析 Ghidra 输出失败: %s", exc)
    return findings


# ---------------------------------------------------------------------------
# 通用工具输出解析
# ---------------------------------------------------------------------------

def parse_cppcheck_output(xml_path: str) -> list[BinaryFinding]:
    """解析 Cppcheck XML 输出。"""
    import xml.etree.ElementTree as ET

    findings = []
    try:
        tree = ET.parse(xml_path)
        for error in tree.findall(".//error"):
            severity_map = {"error": "error", "warning": "warning", "style": "note"}
            loc = error.find("location")
            findings.append(BinaryFinding(
                tool="cppcheck",
                rule_id=error.get("id", "unknown"),
                severity=severity_map.get(error.get("severity", ""), "warning"),
                message=error.get("msg", ""),
                file_path=loc.get("file", "") if loc is not None else "",
                line_number=int(loc.get("line", "0")) if loc is not None else 0,
            ))
    except Exception as exc:
        logger.debug("解析 Cppcheck 输出失败: %s", exc)
    return findings


def parse_radare2_output(json_path: str) -> list[BinaryFinding]:
    """解析 Radare2 JSON 输出（r2 -qc 'aaa;aflj' binary > output.json）。"""
    findings = []
    try:
        data = json.loads(Path(json_path).read_text(encoding="utf-8"))
        dangerous_functions = {
            "sym.imp.strcpy", "sym.imp.strcat", "sym.imp.sprintf",
            "sym.imp.gets", "sym.imp.scanf", "sym.imp.system",
            "sym.imp.exec", "sym.imp.popen",
        }
        for func in data if isinstance(data, list) else []:
            name = func.get("name", "")
            if name in dangerous_functions:
                findings.append(BinaryFinding(
                    tool="radare2",
                    rule_id="dangerous-function-import",
                    severity="warning",
                    message=f"二进制文件导入了危险函数 {name}，可能存在缓冲区溢出或命令注入风险",
                    file_path=json_path,
                    address=hex(func.get("offset", 0)),
                    function_name=name,
                ))
    except Exception as exc:
        logger.debug("解析 Radare2 输出失败: %s", exc)
    return findings


# ---------------------------------------------------------------------------
# 统一 SARIF 转换
# ---------------------------------------------------------------------------

def normalize_to_sarif(
    findings: list[BinaryFinding],
    tool_name: str = "Argus Binary Analyzer",
) -> dict[str, Any]:
    """将二进制分析结果统一转换为 SARIF 格式。"""
    results = []
    for f in findings:
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file_path},
                "region": {"startLine": max(f.line_number, 1)},
            }
        }
        if f.function_name:
            loc["logicalLocations"] = [{"name": f.function_name, "kind": "function"}]

        result: dict[str, Any] = {
            "ruleId": f"binary/{f.tool}/{f.rule_id}",
            "level": f.severity,
            "message": {"text": f.message},
            "locations": [loc],
        }
        if f.address:
            result["properties"] = {"binaryAddress": f.address}

        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "2.3",
                }
            },
            "results": results,
        }],
    }


def save_sarif(sarif: dict[str, Any], output_path: str) -> None:
    """将 SARIF 字典写入文件。"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("二进制分析 SARIF 已写入: %s", output_path)
