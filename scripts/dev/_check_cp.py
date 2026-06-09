import json
cp = json.load(open("data/results/benchmark/sarif_agent_r_allcwe.checkpoint.json", "r", encoding="utf-8"))
print(f"Checkpoint: {len(cp['done'])} done")
