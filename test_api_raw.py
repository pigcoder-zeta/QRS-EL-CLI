import os, httpx, json, sys

# 强制 utf-8 输出
sys.stdout.reconfigure(encoding="utf-8")

env = {}
try:
    for line in open(".env", encoding="utf-8").readlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
except Exception as e:
    print("读取 .env 失败:", e)

api_key = env.get("OPENAI_API_KEY", "")
base_url = env.get("OPENAI_BASE_URL", "https://api.openai.com/v1")

test_prompt = 'Reply with ONLY this JSON, no other text: {"status": "safe", "confidence": 0.9, "engine_detected": "Test", "reasoning": "test", "sink_method": "none"}'

candidates = ["gpt-5-nano", "gpt-5.1", "gpt-5.2", "gpt-5", "gpt-4o", "gpt-4o-mini"]

for test_model in candidates:
    payload = {
        "model": test_model,
        "messages": [{"role": "user", "content": test_prompt}],
        "max_tokens": 150,
        "temperature": 0,
    }
    try:
        r = httpx.post(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        if r.status_code != 200:
            print(f"[{test_model}] HTTP {r.status_code} - 不可用")
            continue
        data = r.json()
        choices = data.get("choices", [])
        if not choices:
            print(f"[{test_model}] 无 choices")
            continue
        content = choices[0].get("message", {}).get("content") or ""
        usage = data.get("usage", {})
        if content.strip():
            print(f"[{test_model}] OK - content={repr(content[:80])} tokens={usage}")
        else:
            print(f"[{test_model}] content=null/空 tokens={usage}")
    except Exception as e:
        print(f"[{test_model}] 异常: {e}")
