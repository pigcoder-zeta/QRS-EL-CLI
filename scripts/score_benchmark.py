"""
QRSE-X 通用 Benchmark 评分工具

支持多种测试集:
  - OWASP Benchmark v1.2  (benchmark_type="owasp")
  - Juliet Test Suite      (benchmark_type="juliet")
  - CVE-Bench              (benchmark_type="cvebench")
  - 自定义                  (benchmark_type="custom")

将 QRSE-X 输出的 SARIF 文件与标准答案对比，计算：
  - TP / FP / TN / FN
  - 精确率 (Precision) / 召回率 (Recall) / F1
  - Youden Index（TPR - FPR）

使用方法：
  python scripts/score_benchmark.py \\
      --sarif data/results/benchmark/results_xxx.sarif \\
      --expected data/benchmark/BenchmarkJava/expectedresults-1.2.csv \\
      --benchmark-type owasp
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# OWASP Benchmark 漏洞类型 → QRSE-X vuln_type 映射
# ---------------------------------------------------------------------------

# Benchmark category 字段 → 对应的 CWE 与关键词
_CATEGORY_META: dict[str, dict] = {
    "sqli":         {"cwe": 89,  "label": "SQL Injection"},
    "cmdi":         {"cwe": 78,  "label": "Command Injection"},
    "pathtraver":   {"cwe": 22,  "label": "Path Traversal"},
    "xss":          {"cwe": 79,  "label": "XSS"},
    "xxe":          {"cwe": 611, "label": "XXE"},
    "deserial":     {"cwe": 502, "label": "Insecure Deserialization"},
    "ssrf":         {"cwe": 918, "label": "SSRF"},
    "trustbound":   {"cwe": 501, "label": "Trust Boundary Violation"},
    "weakrand":     {"cwe": 330, "label": "Weak Randomness"},
    "crypto":       {"cwe": 327, "label": "Weak Cryptography"},
    "ldapi":        {"cwe": 90,  "label": "LDAP Injection"},
    "xpathi":       {"cwe": 643, "label": "XPath Injection"},
    "headerinjection": {"cwe": 113, "label": "Header Injection"},
}

# QRSE-X 输出的 rule_id / message 关键词 → Benchmark category
_QRSE_TO_CATEGORY: list[tuple[str, str]] = [
    (r"sql.inject",        "sqli"),
    (r"command.inject",    "cmdi"),
    (r"path.travers",      "pathtraver"),
    (r"directory.travers", "pathtraver"),
    (r"\bxss\b",           "xss"),
    (r"cross.site",        "xss"),
    (r"\bxxe\b",           "xxe"),
    (r"xml.external",      "xxe"),
    (r"deserializ",        "deserial"),
    (r"\bssrf\b",          "ssrf"),
    (r"server.side.request", "ssrf"),
    (r"weak.rand",         "weakrand"),
    (r"weak.crypto",       "crypto"),
    (r"ldap.inject",       "ldapi"),
    (r"xpath.inject",      "xpathi"),
    (r"header.inject",     "headerinjection"),
    (r"trust.bound",       "trustbound"),
]


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class ExpectedResult:
    """Benchmark 标准答案中的一条记录。"""
    test_name: str       # e.g. "BenchmarkTest00001"
    category:  str       # e.g. "sqli"
    is_real:   bool      # True = 真漏洞 (TP candidate)
    cwe:       int


@dataclass
class FindingRecord:
    """QRSE-X SARIF 中的一条发现。"""
    test_name: str       # 从文件路径提取 BenchmarkTestXXXXX
    category:  str       # 推断的 Benchmark category
    rule_id:   str
    file_uri:  str
    line:      int
    message:   str


@dataclass
class CategoryScore:
    """单个漏洞类别的评分结果。"""
    category:   str
    label:      str
    cwe:        int
    total:      int   = 0   # 该类别 Benchmark 总用例数
    real:       int   = 0   # 真实漏洞数（expected=true）
    detected:   int   = 0   # QRSE-X 报告的总发现数
    tp:         int   = 0
    fp:         int   = 0
    tn:         int   = 0
    fn:         int   = 0
    precision:  float = 0.0
    recall:     float = 0.0
    f1:         float = 0.0
    tpr:        float = 0.0   # True Positive Rate = Recall
    fpr:        float = 0.0   # False Positive Rate = FP / (FP + TN)
    youden:     float = 0.0   # TPR - FPR

    def compute(self) -> None:
        total_pos = self.tp + self.fn
        total_neg = self.fp + self.tn
        self.tpr = self.tp / total_pos if total_pos > 0 else 0.0
        self.fpr = self.fp / total_neg if total_neg > 0 else 0.0
        self.youden = self.tpr - self.fpr
        self.recall = self.tpr
        if self.tp + self.fp > 0:
            self.precision = self.tp / (self.tp + self.fp)
        if self.precision + self.recall > 0:
            self.f1 = 2 * self.precision * self.recall / (self.precision + self.recall)


@dataclass
class BenchmarkScore:
    """完整评分结果。"""
    tool_name:       str = "QRSE-X"
    sarif_files:     int = 0
    total_findings:  int = 0
    categories:      list[CategoryScore] = field(default_factory=list)
    overall_tp:      int   = 0
    overall_fp:      int   = 0
    overall_tn:      int   = 0
    overall_fn:      int   = 0
    overall_precision: float = 0.0
    overall_recall:    float = 0.0
    overall_f1:        float = 0.0
    overall_youden:    float = 0.0
    overall_tpr:       float = 0.0
    overall_fpr:       float = 0.0
    notes:           list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 解析函数
# ---------------------------------------------------------------------------

def parse_expected_csv(
    csv_path: str,
    benchmark_type: str = "owasp",
) -> dict[str, ExpectedResult]:
    """
    解析标准答案文件（根据 benchmark_type 切换解析策略）。

    通用格式 (OWASP / custom):
      # test name, category, real vulnerability, CWE
      BenchmarkTest00001,pathtraver,false,22

    Juliet 格式:
      文件名本身含 good/bad 标记，或使用通用格式的 manifest.csv
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"标准答案文件不存在: {csv_path}")

    if benchmark_type == "juliet":
        return _parse_expected_juliet(path)

    results: dict[str, ExpectedResult] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                if len(parts) >= 3:
                    test_name = parts[0].strip()
                    is_real = parts[-1].strip().lower() in ("true", "1", "yes", "bad")
                    results[test_name] = ExpectedResult(
                        test_name=test_name, category="unknown",
                        is_real=is_real, cwe=0,
                    )
                continue
            test_name = parts[0].strip()
            category  = parts[1].strip().lower()
            is_real   = parts[2].strip().lower() in ("true", "1", "yes", "bad")
            try:
                cwe = int(parts[3].strip())
            except ValueError:
                cwe = 0
            results[test_name] = ExpectedResult(
                test_name=test_name, category=category,
                is_real=is_real, cwe=cwe,
            )

    print(f"[解析] 标准答案 ({benchmark_type}): {len(results)} 条用例")
    return results


def _parse_expected_juliet(path: Path) -> dict[str, ExpectedResult]:
    """解析 Juliet manifest（支持通用 CSV 格式或按行文件名推断）。"""
    results: dict[str, ExpectedResult] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 4:
                test_name = parts[0].strip()
                category  = parts[1].strip().lower()
                is_real   = parts[2].strip().lower() in ("true", "1", "yes", "bad")
                try:
                    cwe = int(parts[3].strip())
                except ValueError:
                    cwe = 0
                results[test_name] = ExpectedResult(
                    test_name=test_name, category=category,
                    is_real=is_real, cwe=cwe,
                )
            elif len(parts) >= 1:
                fname = parts[0].strip()
                is_bad = "__bad" in fname.lower() or "_bad" in fname.lower()
                is_good = "__good" in fname.lower() or "_good" in fname.lower()
                is_real = is_bad and not is_good
                cwe_m = re.search(r"CWE(\d+)", fname, re.IGNORECASE)
                cwe = int(cwe_m.group(1)) if cwe_m else 0
                cat = f"cwe{cwe}" if cwe else "unknown"
                results[fname] = ExpectedResult(
                    test_name=fname, category=cat,
                    is_real=is_real, cwe=cwe,
                )

    print(f"[解析] 标准答案 (juliet): {len(results)} 条用例")
    return results


def _extract_test_name(file_uri: str, benchmark_type: str = "owasp") -> Optional[str]:
    """从文件路径提取测试用例名（根据 benchmark_type 切换策略）。"""
    if benchmark_type == "juliet":
        return _extract_test_name_juliet(file_uri)
    if benchmark_type == "cvebench":
        return _extract_test_name_cvebench(file_uri)
    if benchmark_type == "custom":
        return _extract_test_name_generic(file_uri)
    m = re.search(r"(BenchmarkTest\d+)", file_uri, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_test_name_juliet(file_uri: str) -> Optional[str]:
    """Juliet: CWE<id>_<VulnType>__<variant>"""
    m = re.search(r"(CWE\d+_[A-Za-z0-9_]+?)\.(?:java|c|cpp)$", file_uri, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"(CWE\d+[^\\/]+)", file_uri, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_test_name_cvebench(file_uri: str) -> Optional[str]:
    """CVE-Bench: CVE-YYYY-NNNNN"""
    m = re.search(r"(CVE-\d{4}-\d+)", file_uri, re.IGNORECASE)
    return m.group(1) if m else _extract_test_name_generic(file_uri)


def _extract_test_name_generic(file_uri: str) -> Optional[str]:
    """通用：用文件名（不含后缀）作为 test_name。"""
    uri = file_uri.replace("\\", "/")
    name = uri.rsplit("/", 1)[-1] if "/" in uri else uri
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return stem if stem else None


def _infer_category(rule_id: str, message: str) -> Optional[str]:
    """从 QRSE-X 的 rule_id 和 message 推断 Benchmark category。"""
    text = f"{rule_id} {message}".lower()
    for pattern, cat in _QRSE_TO_CATEGORY:
        if re.search(pattern, text, re.IGNORECASE):
            return cat
    return None


def parse_sarif_findings(
    sarif_path: str,
    benchmark_type: str = "owasp",
) -> list[FindingRecord]:
    """解析单个 SARIF 文件，提取测试用例的发现。"""
    path = Path(sarif_path)
    if not path.exists():
        return []

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    findings: list[FindingRecord] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            locs = result.get("locations", [])
            if not locs:
                continue
            pl = locs[0].get("physicalLocation", {})
            uri  = pl.get("artifactLocation", {}).get("uri", "")
            line = pl.get("region", {}).get("startLine", 0)

            test_name = _extract_test_name(uri, benchmark_type=benchmark_type)
            if not test_name:
                continue

            category = _infer_category(rule_id, message)
            if not category:
                category = "unknown"

            findings.append(FindingRecord(
                test_name=test_name,
                category=category,
                rule_id=rule_id,
                file_uri=uri,
                line=line,
                message=message,
            ))

    return findings


def load_all_sarif(
    sarif_dir: Optional[str],
    sarif_file: Optional[str],
    benchmark_type: str = "owasp",
) -> tuple[list[FindingRecord], int]:
    """加载所有 SARIF 文件，返回发现列表和文件数。"""
    all_findings: list[FindingRecord] = []
    file_count = 0

    if sarif_file:
        findings = parse_sarif_findings(sarif_file, benchmark_type=benchmark_type)
        all_findings.extend(findings)
        file_count += 1
        print(f"[解析] {sarif_file}: {len(findings)} 条发现")

    if sarif_dir:
        for fp in Path(sarif_dir).glob("*.sarif"):
            findings = parse_sarif_findings(str(fp), benchmark_type=benchmark_type)
            all_findings.extend(findings)
            file_count += 1
            print(f"[解析] {fp.name}: {len(findings)} 条发现")

    seen: set[tuple[str, str]] = set()
    deduped: list[FindingRecord] = []
    for f in all_findings:
        key = (f.test_name, f.category)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    print(f"[解析] SARIF 共 {file_count} 个文件，去重后 {len(deduped)} 条发现")
    return deduped, file_count


# ---------------------------------------------------------------------------
# 评分逻辑
# ---------------------------------------------------------------------------

def compute_score(
    expected: dict[str, ExpectedResult],
    findings: list[FindingRecord],
) -> BenchmarkScore:
    """
    按 OWASP Benchmark 标准计算 TP/FP/TN/FN 及各项指标。

    判定规则：
      对每个 (test_name, category) 组合：
        - QRSE-X 报告了该 test_name 的该类别发现 AND expected.is_real=True  → TP
        - QRSE-X 报告了该 test_name 的该类别发现 AND expected.is_real=False → FP
        - QRSE-X 未报告 AND expected.is_real=True                            → FN
        - QRSE-X 未报告 AND expected.is_real=False                           → TN
    """
    score = BenchmarkScore(sarif_files=0, total_findings=len(findings))

    # 构建 QRSE-X 发现集合：{test_name → set of categories}
    detected: dict[str, set[str]] = {}
    for f in findings:
        detected.setdefault(f.test_name, set()).add(f.category)

    # 按 Benchmark category 分组所有期望记录
    cat_groups: dict[str, list[ExpectedResult]] = {}
    for er in expected.values():
        cat_groups.setdefault(er.category, []).append(er)

    # 对每个类别计算指标
    for cat, ers in sorted(cat_groups.items()):
        meta  = _CATEGORY_META.get(cat, {"cwe": 0, "label": cat})
        cs    = CategoryScore(category=cat, label=meta["label"], cwe=meta["cwe"])
        cs.total = len(ers)
        cs.real  = sum(1 for er in ers if er.is_real)

        for er in ers:
            # QRSE-X 是否报告了这个 test_name 在该类别或任意类别的漏洞
            test_detected_cats = detected.get(er.test_name, set())
            # 允许 category 匹配（精确）或 unknown（工具未能分类）
            was_detected = cat in test_detected_cats or "unknown" in test_detected_cats

            if was_detected and er.is_real:
                cs.tp += 1
            elif was_detected and not er.is_real:
                cs.fp += 1
            elif not was_detected and er.is_real:
                cs.fn += 1
            else:
                cs.tn += 1

        cs.detected = cs.tp + cs.fp
        cs.compute()
        score.categories.append(cs)

        score.overall_tp += cs.tp
        score.overall_fp += cs.fp
        score.overall_tn += cs.tn
        score.overall_fn += cs.fn

    # 总体指标
    total_pos = score.overall_tp + score.overall_fn
    total_neg = score.overall_fp + score.overall_tn
    score.overall_tpr = score.overall_tp / total_pos if total_pos > 0 else 0.0
    score.overall_fpr = score.overall_fp / total_neg if total_neg > 0 else 0.0
    score.overall_youden  = score.overall_tpr - score.overall_fpr
    score.overall_recall  = score.overall_tpr
    if score.overall_tp + score.overall_fp > 0:
        score.overall_precision = score.overall_tp / (score.overall_tp + score.overall_fp)
    if score.overall_precision + score.overall_recall > 0:
        score.overall_f1 = (2 * score.overall_precision * score.overall_recall
                            / (score.overall_precision + score.overall_recall))

    return score


# ---------------------------------------------------------------------------
# 输出格式化
# ---------------------------------------------------------------------------

def print_score_table(score: BenchmarkScore) -> None:
    """打印评分结果表格（纯 ASCII，无颜色依赖）。"""
    sep = "+" + "-" * 18 + "+" + "-" * 7 + "+" + "-" * 6 + "+" + "-" * 6 + \
          "+" + "-" * 6 + "+" + "-" * 6 + "+" + "-" * 8 + "+" + "-" * 8 + \
          "+" + "-" * 8 + "+" + "-" * 9 + "+"
    header = (
        f"| {'Category':<16} | {'Total':>5} | {'TP':>4} | {'FP':>4} |"
        f" {'FN':>4} | {'TN':>4} | {'Prec':>6} | {'Recall':>6} |"
        f" {'F1':>6} | {'Youden':>7} |"
    )

    print("\n" + "=" * 100)
    print(f"  QRSE-X x OWASP Benchmark 评分报告")
    print(f"  SARIF 文件: {score.sarif_files}  |  总发现: {score.total_findings}")
    print("=" * 100)
    print(sep)
    print(header)
    print(sep)

    for cs in score.categories:
        youden_str = f"{cs.youden:+.3f}"
        flag = " [+]" if cs.youden > 0.5 else (" [~]" if cs.youden > 0 else " [-]")
        print(
            f"| {cs.label:<16} | {cs.total:>5} | {cs.tp:>4} | {cs.fp:>4} |"
            f" {cs.fn:>4} | {cs.tn:>4} | {cs.precision:>6.1%} | {cs.recall:>6.1%} |"
            f" {cs.f1:>6.3f} | {youden_str:>7} |{flag}"
        )

    print(sep)
    # 总行
    y = score.overall_youden
    youden_str = f"{y:+.3f}"
    print(
        f"| {'OVERALL':<16} | {sum(c.total for c in score.categories):>5}"
        f" | {score.overall_tp:>4} | {score.overall_fp:>4} |"
        f" {score.overall_fn:>4} | {score.overall_tn:>4} |"
        f" {score.overall_precision:>6.1%} | {score.overall_recall:>6.1%} |"
        f" {score.overall_f1:>6.3f} | {youden_str:>7} |"
    )
    print(sep)
    print(f"\n  Youden Index 说明: > 0 优于随机猜测 | > 0.5 良好 | = 1.0 完美")
    print(f"  TPR (召回率): {score.overall_tpr:.1%}  |  FPR: {score.overall_fpr:.1%}")
    print()


def save_json(
    score: BenchmarkScore,
    output_path: str,
    benchmark_type: str = "owasp",
) -> None:
    """将评分结果保存为 JSON。"""
    data = {
        "tool": score.tool_name,
        "benchmark_type": benchmark_type,
        "sarif_files": score.sarif_files,
        "total_findings": score.total_findings,
        "overall": {
            "tp": score.overall_tp, "fp": score.overall_fp,
            "tn": score.overall_tn, "fn": score.overall_fn,
            "precision": round(score.overall_precision, 4),
            "recall":    round(score.overall_recall, 4),
            "f1":        round(score.overall_f1, 4),
            "tpr":       round(score.overall_tpr, 4),
            "fpr":       round(score.overall_fpr, 4),
            "youden":    round(score.overall_youden, 4),
        },
        "categories": [
            {
                "category":  cs.category,
                "label":     cs.label,
                "cwe":       cs.cwe,
                "total":     cs.total,
                "real":      cs.real,
                "detected":  cs.detected,
                "tp": cs.tp, "fp": cs.fp, "tn": cs.tn, "fn": cs.fn,
                "precision": round(cs.precision, 4),
                "recall":    round(cs.recall, 4),
                "f1":        round(cs.f1, 4),
                "tpr":       round(cs.tpr, 4),
                "fpr":       round(cs.fpr, 4),
                "youden":    round(cs.youden, 4),
            }
            for cs in score.categories
        ],
        "notes": score.notes,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[保存] 评分结果 → {output_path}")


# ---------------------------------------------------------------------------
# 预期结果生成（干运行模式）
# ---------------------------------------------------------------------------

def dry_run_summary(expected: dict[str, ExpectedResult]) -> None:
    """打印 Benchmark 标准答案的统计摘要（不依赖 SARIF）。"""
    cats: dict[str, dict] = {}
    for er in expected.values():
        meta = _CATEGORY_META.get(er.category, {"label": er.category, "cwe": 0})
        c = cats.setdefault(er.category, {"label": meta["label"], "total": 0, "real": 0})
        c["total"] += 1
        if er.is_real:
            c["real"] += 1

    print("\n=== OWASP Benchmark 标准答案摘要 ===")
    print(f"{'类别':<22} {'总用例':>8} {'真漏洞':>8} {'伪漏洞':>8} {'真漏洞率':>10}")
    print("-" * 62)
    total = real = 0
    for cat, d in sorted(cats.items()):
        false_cnt = d["total"] - d["real"]
        rate = d["real"] / d["total"] if d["total"] > 0 else 0
        print(f"{d['label']:<22} {d['total']:>8} {d['real']:>8} {false_cnt:>8} {rate:>10.1%}")
        total += d["total"]
        real  += d["real"]
    print("-" * 62)
    print(f"{'合计':<22} {total:>8} {real:>8} {total-real:>8} {real/total:>10.1%}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="QRSE-X 通用 Benchmark 评分工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  # OWASP Benchmark
  python scripts/score_benchmark.py \\
      --sarif data/results/benchmark/results_sqli.sarif \\
      --expected data/benchmark/BenchmarkJava/expectedresults-1.2.csv \\
      --benchmark-type owasp

  # Juliet Test Suite
  python scripts/score_benchmark.py \\
      --sarif-dir data/results/juliet \\
      --expected data/benchmark/Juliet/manifest.csv \\
      --benchmark-type juliet
        """,
    )
    parser.add_argument("--sarif", default=None, metavar="FILE",
                        help="单个 SARIF 文件路径")
    parser.add_argument("--sarif-dir", default=None, metavar="DIR",
                        help="包含多个 .sarif 文件的目录")
    parser.add_argument("--expected", required=True, metavar="CSV",
                        help="标准答案文件路径")
    parser.add_argument("--output", default=None, metavar="JSON",
                        help="评分结果 JSON 输出路径（可选）")
    parser.add_argument("--benchmark-type", default="owasp",
                        choices=["owasp", "juliet", "cvebench", "custom"],
                        help="测试集类型 (默认: owasp)")
    parser.add_argument("--dry-run", action="store_true",
                        help="仅显示标准答案统计，不解析 SARIF")
    args = parser.parse_args()

    btype = args.benchmark_type

    expected = parse_expected_csv(args.expected, benchmark_type=btype)

    if args.dry_run:
        dry_run_summary(expected)
        return

    if not args.sarif and not args.sarif_dir:
        parser.error("必须提供 --sarif 或 --sarif-dir")

    findings, file_count = load_all_sarif(args.sarif_dir, args.sarif, benchmark_type=btype)

    score = compute_score(expected, findings)
    score.sarif_files = file_count

    print_score_table(score)

    if args.output:
        save_json(score, args.output)
    else:
        prefix = {"owasp": "benchmark", "juliet": "juliet",
                  "cvebench": "cvebench", "custom": "custom"}.get(btype, "benchmark")
        default_out = f"data/results/{prefix}_score.json"
        save_json(score, default_out)


if __name__ == "__main__":
    main()
