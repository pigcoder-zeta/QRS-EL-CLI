import httpx, os, json

resp = httpx.get(
    "https://new.lemonapi.site/v1/models",
    headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
    timeout=15
)
data = resp.json()
models = sorted([m["id"] for m in data.get("data", [])])

print("=== 所有可用模型 ===")
for m in models:
    print(" ", m)

print("\n=== 推荐快速模型 ===")
fast_kw = ["flash", "mini", "turbo", "fast", "haiku", "3.5", "4o-mini", "2.0"]
for m in models:
    if any(k in m.lower() for k in fast_kw):
        print(" ", m)
