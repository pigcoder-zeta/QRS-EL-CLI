"""
供应链安全：依赖分析模块。

功能：
1. 自动检测项目使用的包管理器（Maven/npm/pip/Go Modules）
2. 解析依赖清单，提取包名 + 版本
3. 通过 OSV.dev API 查询已知漏洞（CVE）
4. 包名 typosquatting 检测（与热门包名的编辑距离对比）
5. 输出 SARIF 格式结果，可对接 Agent-R 审查
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """单个依赖描述。"""
    name: str
    version: str
    ecosystem: str          # maven / npm / pypi / go
    source_file: str        # 来源文件（pom.xml / package.json / requirements.txt / go.mod）
    line_number: int = 0


@dataclass
class VulnMatch:
    """已知漏洞匹配结果。"""
    dep: Dependency
    cve_id: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW
    summary: str
    fixed_version: str = ""


@dataclass
class TyposquatAlert:
    """Typosquatting 警报。"""
    dep: Dependency
    similar_to: str         # 疑似仿冒的正规包名
    distance: int           # 编辑距离


# ---------------------------------------------------------------------------
# 依赖解析器
# ---------------------------------------------------------------------------

def parse_dependencies(repo_root: str) -> list[Dependency]:
    """自动检测并解析仓库中的所有依赖声明。"""
    root = Path(repo_root)
    deps: list[Dependency] = []

    # Maven pom.xml
    for pom in root.rglob("pom.xml"):
        deps.extend(_parse_pom(pom))

    # npm package.json
    for pkg in root.rglob("package.json"):
        if "node_modules" in str(pkg):
            continue
        deps.extend(_parse_package_json(pkg))

    # pip requirements.txt
    for req in root.rglob("requirements*.txt"):
        deps.extend(_parse_requirements_txt(req))

    # Go go.mod
    for gomod in root.rglob("go.mod"):
        deps.extend(_parse_go_mod(gomod))

    # Gradle build.gradle
    for gradle in root.rglob("build.gradle"):
        deps.extend(_parse_gradle(gradle))

    logger.info("依赖分析: 共解析 %d 个依赖", len(deps))
    return deps


def _parse_pom(pom_path: Path) -> list[Dependency]:
    """解析 Maven pom.xml。"""
    deps = []
    try:
        tree = ET.parse(str(pom_path))
        root = tree.getroot()
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}

        for dep in root.findall(".//m:dependency", ns):
            gid = dep.findtext("m:groupId", "", ns)
            aid = dep.findtext("m:artifactId", "", ns)
            ver = dep.findtext("m:version", "", ns)
            if aid and ver and not ver.startswith("${"):
                deps.append(Dependency(
                    name=f"{gid}:{aid}" if gid else aid,
                    version=ver,
                    ecosystem="maven",
                    source_file=str(pom_path),
                ))
    except Exception as exc:
        logger.debug("解析 pom.xml 失败: %s: %s", pom_path, exc)
    return deps


def _parse_package_json(pkg_path: Path) -> list[Dependency]:
    """解析 npm package.json。"""
    deps = []
    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies"):
            for name, ver in data.get(section, {}).items():
                clean_ver = re.sub(r"[^0-9.]", "", ver)
                deps.append(Dependency(
                    name=name,
                    version=clean_ver or ver,
                    ecosystem="npm",
                    source_file=str(pkg_path),
                ))
    except Exception as exc:
        logger.debug("解析 package.json 失败: %s: %s", pkg_path, exc)
    return deps


def _parse_requirements_txt(req_path: Path) -> list[Dependency]:
    """解析 pip requirements.txt。"""
    deps = []
    try:
        for i, line in enumerate(req_path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([a-zA-Z0-9_.-]+)\s*[=<>!~]+\s*([0-9][0-9a-zA-Z.*]*)", line)
            if m:
                deps.append(Dependency(
                    name=m.group(1),
                    version=m.group(2),
                    ecosystem="pypi",
                    source_file=str(req_path),
                    line_number=i,
                ))
    except Exception as exc:
        logger.debug("解析 requirements.txt 失败: %s: %s", req_path, exc)
    return deps


def _parse_go_mod(gomod_path: Path) -> list[Dependency]:
    """解析 Go go.mod。"""
    deps = []
    try:
        in_require = False
        for i, line in enumerate(gomod_path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")":
                in_require = False
                continue
            if in_require or stripped.startswith("require "):
                m = re.match(r"^\s*([^\s]+)\s+(v[^\s]+)", stripped.replace("require ", ""))
                if m:
                    deps.append(Dependency(
                        name=m.group(1),
                        version=m.group(2),
                        ecosystem="go",
                        source_file=str(gomod_path),
                        line_number=i,
                    ))
    except Exception as exc:
        logger.debug("解析 go.mod 失败: %s: %s", gomod_path, exc)
    return deps


def _parse_gradle(gradle_path: Path) -> list[Dependency]:
    """解析 Gradle build.gradle（基础正则，覆盖常见格式）。"""
    deps = []
    try:
        content = gradle_path.read_text(encoding="utf-8")
        # implementation 'group:artifact:version'
        for m in re.finditer(
            r"""(?:implementation|compile|api|testImplementation)\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]""",
            content,
        ):
            deps.append(Dependency(
                name=f"{m.group(1)}:{m.group(2)}",
                version=m.group(3),
                ecosystem="maven",
                source_file=str(gradle_path),
            ))
    except Exception as exc:
        logger.debug("解析 build.gradle 失败: %s: %s", gradle_path, exc)
    return deps


# ---------------------------------------------------------------------------
# OSV.dev 漏洞查询
# ---------------------------------------------------------------------------

def query_osv(deps: list[Dependency], timeout: int = 10) -> list[VulnMatch]:
    """通过 OSV.dev 批量查询已知漏洞。"""
    import httpx

    _ecosystem_map = {
        "maven": "Maven",
        "npm": "npm",
        "pypi": "PyPI",
        "go": "Go",
    }

    results: list[VulnMatch] = []

    # OSV 批量查询 API
    queries = []
    for dep in deps:
        eco = _ecosystem_map.get(dep.ecosystem)
        if eco and dep.version:
            queries.append({
                "package": {"name": dep.name, "ecosystem": eco},
                "version": dep.version,
            })

    if not queries:
        return results

    # 分批查询（OSV 限制 1000/次）
    batch_size = 500
    for i in range(0, len(queries), batch_size):
        batch = queries[i:i + batch_size]
        try:
            resp = httpx.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": batch},
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning("OSV API 返回 %d", resp.status_code)
                continue

            data = resp.json()
            for j, result in enumerate(data.get("results", [])):
                vulns = result.get("vulns", [])
                if vulns and (i + j) < len(deps):
                    dep = deps[i + j]
                    for v in vulns[:3]:
                        cve = ""
                        for alias in v.get("aliases", []):
                            if alias.startswith("CVE-"):
                                cve = alias
                                break
                        sev = "MEDIUM"
                        for s in v.get("severity", []):
                            if s.get("type") == "CVSS_V3":
                                score = float(s.get("score", "0").split("/")[0] if "/" in s.get("score", "") else "0")
                                if score >= 9.0:
                                    sev = "CRITICAL"
                                elif score >= 7.0:
                                    sev = "HIGH"
                                elif score >= 4.0:
                                    sev = "MEDIUM"
                                else:
                                    sev = "LOW"

                        results.append(VulnMatch(
                            dep=dep,
                            cve_id=cve or v.get("id", "N/A"),
                            severity=sev,
                            summary=v.get("summary", "")[:200],
                        ))

        except Exception as exc:
            logger.warning("OSV API 查询失败: %s", exc)

    logger.info("OSV 漏洞查询: %d 个依赖中发现 %d 个已知漏洞", len(deps), len(results))
    return results


# ---------------------------------------------------------------------------
# Typosquatting 检测
# ---------------------------------------------------------------------------

_POPULAR_PACKAGES: dict[str, list[str]] = {
    "npm": [
        "express", "react", "lodash", "axios", "moment", "webpack", "babel",
        "eslint", "prettier", "typescript", "vue", "angular", "jquery",
        "chalk", "commander", "debug", "dotenv", "uuid", "cors",
    ],
    "pypi": [
        "requests", "flask", "django", "numpy", "pandas", "scipy", "boto3",
        "pillow", "sqlalchemy", "celery", "pytest", "pyyaml", "cryptography",
        "jinja2", "beautifulsoup4", "scrapy", "fastapi", "pydantic",
    ],
    "maven": [
        "spring-boot", "spring-core", "spring-web", "log4j", "slf4j",
        "jackson", "guava", "commons-io", "commons-lang3", "hibernate",
        "mybatis", "fastjson", "gson", "netty", "junit",
    ],
}


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein 编辑距离。"""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (0 if ca == cb else 1),
            ))
        prev = curr
    return prev[len(b)]


def check_typosquatting(deps: list[Dependency]) -> list[TyposquatAlert]:
    """检测疑似 typosquatting 的依赖。"""
    alerts: list[TyposquatAlert] = []
    for dep in deps:
        popular = _POPULAR_PACKAGES.get(dep.ecosystem, [])
        pkg_name = dep.name.split(":")[-1].lower()
        for pop in popular:
            if pkg_name == pop:
                break
            dist = _edit_distance(pkg_name, pop)
            if 0 < dist <= 2 and len(pkg_name) > 3:
                alerts.append(TyposquatAlert(dep=dep, similar_to=pop, distance=dist))
                break

    if alerts:
        logger.warning("Typosquatting 警报: %d 个疑似仿冒包", len(alerts))
    return alerts


# ---------------------------------------------------------------------------
# SARIF 输出
# ---------------------------------------------------------------------------

def to_sarif(
    vuln_matches: list[VulnMatch],
    typo_alerts: list[TyposquatAlert],
) -> dict[str, Any]:
    """将供应链分析结果转换为 SARIF 格式。"""
    results = []

    for vm in vuln_matches:
        results.append({
            "ruleId": f"supply-chain/known-vuln/{vm.cve_id}",
            "level": "error" if vm.severity in ("CRITICAL", "HIGH") else "warning",
            "message": {
                "text": f"依赖 {vm.dep.name}@{vm.dep.version} 包含已知漏洞 {vm.cve_id}: {vm.summary}",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": vm.dep.source_file},
                    "region": {"startLine": max(vm.dep.line_number, 1)},
                }
            }],
        })

    for ta in typo_alerts:
        results.append({
            "ruleId": "supply-chain/typosquatting",
            "level": "warning",
            "message": {
                "text": f"依赖 '{ta.dep.name}' 与知名包 '{ta.similar_to}' 仅差 {ta.distance} 个字符，疑似 typosquatting",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": ta.dep.source_file},
                    "region": {"startLine": max(ta.dep.line_number, 1)},
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Argus Supply Chain Analyzer",
                    "version": "2.3",
                }
            },
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------
# 公开接口
# ---------------------------------------------------------------------------

def analyze_supply_chain(
    repo_root: str,
    output_sarif: Optional[str] = None,
    skip_osv: bool = False,
) -> dict[str, Any]:
    """
    完整供应链分析流水线。

    Args:
        repo_root: 仓库根目录。
        output_sarif: 可选的 SARIF 输出路径。
        skip_osv: 是否跳过 OSV 漏洞查询（离线模式）。

    Returns:
        SARIF 格式结果字典。
    """
    deps = parse_dependencies(repo_root)
    if not deps:
        logger.info("未检测到任何依赖声明文件")
        return to_sarif([], [])

    vulns = query_osv(deps) if not skip_osv else []
    typos = check_typosquatting(deps)
    sarif = to_sarif(vulns, typos)

    if output_sarif:
        Path(output_sarif).parent.mkdir(parents=True, exist_ok=True)
        Path(output_sarif).write_text(
            json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        logger.info("供应链分析 SARIF 已写入: %s", output_sarif)

    return sarif
