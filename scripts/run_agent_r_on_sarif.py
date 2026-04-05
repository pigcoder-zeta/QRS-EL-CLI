"""
独立脚本：对指定 SARIF 文件运行 Agent-R 语义过滤，输出过滤后的 SARIF。

用途：把官方 CodeQL 查询（高召回）的输出送入 Agent-R（高精确），
      预期最终达到高召回 + 高精确的联合效果。

用法：
    python scripts/run_agent_r_on_sarif.py \
        --sarif data/results/benchmark/sarif_official_cmdinj.sarif \
        --repo  data/benchmark/BenchmarkJava \
        --language java \
        --workers 4 \
        --output data/results/benchmark/sarif_filtered_cmdinj.sarif
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# 强制 stdout/stderr 无缓冲，防止 PowerShell 2>&1 重定向导致输出"假死"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(line_buffering=True)
os.environ.setdefault("PYTHONUNBUFFERED", "1")

# 把项目根目录加入 sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# StreamHandler 使用 UTF-8 stdout，write_through=True 禁止内部缓冲
import io
_utf8_stdout = io.TextIOWrapper(
    sys.stdout.buffer, encoding="utf-8", errors="replace",
    line_buffering=True, write_through=True,
)
_handler = logging.StreamHandler(_utf8_stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Agent-R SARIF 语义过滤器")
    p.add_argument("--sarif", required=True, help="输入 SARIF 文件路径")
    p.add_argument("--repo", required=True, help="源码仓库根目录")
    p.add_argument("--language", default="java", help="编程语言（默认 java）")
    p.add_argument("--workers", type=int, default=1, help="并发线程数（默认 1）")
    p.add_argument("--batch", type=int, default=1, help="每次 LLM 调用包含的 finding 数（默认 1，建议 5~10）")
    p.add_argument("--output", required=True, help="输出 SARIF 文件路径")
    p.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="保留 finding 的最低置信度（默认 0.5）",
    )
    p.add_argument(
        "--no-code-browser",
        action="store_true",
        help="禁用 CodeBrowser 智能上下文（大仓库建议开启此选项以避免卡顿）",
    )
    return p


def _checkpoint_path(output: str) -> Path:
    return Path(output).with_suffix(".checkpoint.json")


def _load_checkpoint(output: str) -> dict:
    cp = _checkpoint_path(output)
    if cp.exists():
        try:
            return json.loads(cp.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_checkpoint(output: str, data: dict) -> None:
    cp = _checkpoint_path(output)
    cp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def main() -> None:
    args = _build_parser().parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("[ERROR] 未设置 OPENAI_API_KEY 环境变量")

    from src.agents.agent_r import AgentR, VulnStatus, _parse_sarif, _load_code_context

    agent_r = AgentR(enable_code_browser=not args.no_code_browser)

    logger.info(">> 开始 Agent-R 语义审查")
    logger.info("  输入 SARIF : %s", args.sarif)
    logger.info("  仓库根目录 : %s", args.repo)
    logger.info("  并发 workers: %d, batch: %d", args.workers, args.batch)

    # --- 断点续跑：加载已审查的结果 ---
    checkpoint = _load_checkpoint(args.output)
    done_keys: dict[str, dict] = checkpoint.get("done", {})
    if done_keys:
        logger.info(">> 从断点恢复: 已完成 %d 条", len(done_keys))

    results = agent_r.review(
        sarif_path=args.sarif,
        repo_root=args.repo,
        language=args.language,
        parallel_workers=args.workers,
        batch_size=args.batch,
        checkpoint_done=done_keys,
        checkpoint_callback=lambda batch_results: _on_batch_done(
            args.output, done_keys, batch_results
        ),
    )

    confirmed = [r for r in results if r.status == VulnStatus.VULNERABLE and r.confidence >= args.min_confidence]
    uncertain = [r for r in results if r.status == VulnStatus.UNCERTAIN]
    fp = [r for r in results if r.status == VulnStatus.SAFE]

    logger.info(
        ">> 审查完成: 总计=%d  确认=%d  不确定=%d  误报=%d",
        len(results), len(confirmed), len(uncertain), len(fp),
    )

    # ---------- 构造过滤后的 SARIF ----------
    raw_sarif = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
    orig_results = []
    for run in raw_sarif.get("runs", []):
        orig_results.extend(run.get("results", []))

    def _loc(res: dict) -> tuple[str, int]:
        locs = res.get("locations", [])
        if not locs:
            return ("", 0)
        pl = locs[0].get("physicalLocation", {})
        uri = pl.get("artifactLocation", {}).get("uri", "")
        line = pl.get("region", {}).get("startLine", 0)
        return (uri, line)

    keep_locs: set[tuple[str, int]] = set()
    for r in results:
        if r.status != VulnStatus.SAFE:
            keep_locs.add((r.finding.file_uri, r.finding.start_line))

    out_sarif = json.loads(json.dumps(raw_sarif))
    for run in out_sarif.get("runs", []):
        run["results"] = [
            res for res in run.get("results", [])
            if _loc(res) in keep_locs
        ]

    kept_count = sum(len(run.get("results", [])) for run in out_sarif.get("runs", []))
    logger.info(">> 过滤后保留 %d 条 findings (原 %d 条)", kept_count, len(orig_results))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("[OK] 已写入: %s", out_path)

    # 清理 checkpoint
    cp = _checkpoint_path(args.output)
    if cp.exists():
        cp.unlink()
        logger.info("[OK] 断点文件已清理")

    print("\n" + "=" * 60)
    print(f"  Agent-R 过滤摘要")
    print("=" * 60)
    print(f"  输入 findings : {len(orig_results)}")
    print(f"  确认漏洞(VULNERABLE): {len(confirmed)}")
    print(f"  不确定(UNCERTAIN)  : {len(uncertain)}")
    print(f"  判定安全(SAFE)     : {len(fp)}")
    print(f"  输出 findings : {kept_count}")
    print("=" * 60)


def _on_batch_done(output: str, done_keys: dict, batch_results: list) -> None:
    """每个 batch 完成后保存断点。"""
    for r in batch_results:
        key = f"{r.finding.file_uri}:{r.finding.start_line}"
        done_keys[key] = {
            "status": r.status.value,
            "confidence": r.confidence,
            "engine_detected": r.engine_detected,
            "reasoning": r.reasoning[:200],
            "sink_method": r.sink_method,
        }
    _save_checkpoint(output, {"done": done_keys})
    logger.info("[Checkpoint] 已保存进度: %d 条已完成", len(done_keys))


if __name__ == "__main__":
    main()
