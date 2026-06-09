"""
从大型 SARIF 文件中抽取小样本，同时保留已知的 TP 和 FP，用于快速验证 Agent-R 过滤能力。
"""
import json
import csv
import argparse
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sarif", required=True)
    p.add_argument("--expected", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--n-tp", type=int, default=10, help="抽取 TP 数量")
    p.add_argument("--n-fp", type=int, default=10, help="抽取 FP 数量")
    args = p.parse_args()

    # 读取 expected results（BenchmarkTest编号 -> real_vulnerability bool）
    expected = {}
    with open(args.expected, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 列名有前导空格，strip 后再取值
            row_clean = {k.strip(): v.strip() if v else "" for k, v in row.items() if k}
            test_name = row_clean.get("# test name", "").strip()
            is_vuln = row_clean.get("real vulnerability", "false").lower() == "true"
            cat = row_clean.get("category", "").strip()
            expected[test_name] = (is_vuln, cat)

    sarif = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
    
    tp_results = []
    fp_results = []
    
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            locs = result.get("locations", [])
            if not locs:
                continue
            uri = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            # 提取测试用例编号：BenchmarkTest00006
            import re
            m = re.search(r"(BenchmarkTest\d+)", uri)
            if not m:
                continue
            test_name = m.group(1)
            if test_name not in expected:
                continue
            is_vuln, cat = expected[test_name]
            if cat.lower() in ("cmdi", "command-injection", "commandinjection"):
                if is_vuln:
                    tp_results.append(result)
                else:
                    fp_results.append(result)

    print(f"找到 TP: {len(tp_results)}, FP: {len(fp_results)}")
    
    sampled_tp = tp_results[:args.n_tp]
    sampled_fp = fp_results[:args.n_fp]
    sampled = sampled_tp + sampled_fp
    
    print(f"抽样: {len(sampled_tp)} TP + {len(sampled_fp)} FP = {len(sampled)} findings")
    
    out_sarif = json.loads(json.dumps(sarif))
    for run in out_sarif.get("runs", []):
        run["results"] = sampled
        break
    
    Path(args.output).write_text(json.dumps(out_sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"已写入: {args.output}")


if __name__ == "__main__":
    main()
