"""测试不同模型响应速度"""
import os, time
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

models_to_test = [
    "[L]gemini-2.5-flash",
    "[L]gemini-3-flash-preview",
]

base_url = os.environ.get("OPENAI_BASE_URL")
api_key = os.environ.get("OPENAI_API_KEY")

for model in models_to_test:
    print(f"\n测试模型: {model}")
    try:
        llm = ChatOpenAI(model=model, temperature=0.1, base_url=base_url, timeout=60)
        t0 = time.time()
        resp = llm.invoke([HumanMessage(content="Reply with exactly one word: Hello")])
        elapsed = time.time() - t0
        print(f"  响应: {resp.content!r}")
        print(f"  耗时: {elapsed:.1f}s")
    except Exception as e:
        print(f"  错误: {e}")
