"""评估 checkpoint 中已完成的审查结果 vs OWASP ground truth。"""
import csv, json, re, sys
from pathlib import Path

cp_path = sys.argv[1] if len(sys.argv) > 1 else "data/results/benchmark/sarif_agent_r_allcwe.checkpoint.json"
gt_path = "data/benchmark/BenchmarkJava/expectedresults-1.2.csv"

cp = json.loads(Path(cp_path).read_text(encoding="utf-8"))
done = cp["done"]

gt = {}
with open(gt_path, encoding="utf-8") as f:
    for row in csv.reader(f):
        if row[0].startswith("#") or not row[0].startswith("Benchmark"):
            continue
        name = row[0].strip()
        is_real = row[2].strip().lower() == "true"
        gt[name] = is_real

tp = fp = fn_killed = tn_correct = uncertain_tp = uncertain_fp = 0
misclassified = []

for key, verdict in done.items():
    m = re.search(r"(BenchmarkTest\d+)", key)
    if not m:
        continue
    test_name = m.group(1)
    if test_name not in gt:
        continue

    is_real = gt[test_name]
    status = verdict["status"]

    if status == "vulnerable":
        if is_real:
            tp += 1
        else:
            fp += 1
    elif status == "safe":
        if is_real:
            fn_killed += 1
            misclassified.append(f"  FN (killed TP): {test_name} - {verdict['reasoning'][:80]}")
        else:
            tn_correct += 1
    elif status == "uncertain":
        if is_real:
            uncertain_tp += 1
        else:
            uncertain_fp += 1

total = tp + fp + fn_killed + tn_correct + uncertain_tp + uncertain_fp
print(f"=== Agent-R Checkpoint Accuracy ({total} findings matched to ground truth) ===")
print(f"  TP (correctly kept):       {tp}")
print(f"  FP (should have filtered): {fp}")
print(f"  TN (correctly filtered):   {tn_correct}")
print(f"  FN (wrongly killed TP):    {fn_killed}")
print(f"  UNCERTAIN (real vuln):     {uncertain_tp}")
print(f"  UNCERTAIN (false pos):     {uncertain_fp}")
print()

kept = tp + fp + uncertain_tp + uncertain_fp
precision = tp / kept * 100 if kept else 0
recall = tp / (tp + fn_killed + uncertain_tp) * 100 if (tp + fn_killed) else 0
filter_accuracy = tn_correct / (tn_correct + fp) * 100 if (tn_correct + fp) else 0
print(f"  Precision (kept):  {precision:.1f}%  (TP/{kept} kept)")
print(f"  Recall:            {recall:.1f}%  (TP/{tp+fn_killed} real vulns)")
print(f"  FP filter rate:    {tn_correct}/{tn_correct+fp} = {filter_accuracy:.1f}% of FPs correctly removed")
print(f"  TP kill rate:      {fn_killed}/{tp+fn_killed} = {fn_killed/(tp+fn_killed)*100:.1f}% of TPs wrongly removed" if (tp+fn_killed) else "")
print()

if misclassified:
    print("=== Wrongly killed TPs (FN) ===")
    for m in misclassified:
        print(m)
