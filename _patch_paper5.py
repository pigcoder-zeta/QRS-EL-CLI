import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

with open(r'c:\Users\23504\Desktop\reV\paper2.md', 'rb') as f:
    raw = f.read()
text = raw.decode('utf-8')
changes = 0

# ---- E: Agent-E - the text has no explicit "Agent-E" before the Dockerfile line
# Replace from the Dockerfile line
old_E = (
    "`Dockerfile` / `docker-compose.yml`\uff0c\u52a8\u6001\u6784\u5efa\u955c\u50cf"
    "\u5e76\u62c9\u8d77\u9694\u79bb\u6c99\u7b71\u3002\u9a8c\u8bc1\u5224\u5b9a\u91c7\u7528"
    "**\u53cc\u5c42\u5206\u6790\u673a\u5236**\uff1a"
)
new_E = (
    "`Dockerfile` / `docker-compose.yml`\uff0c\u52a8\u6001\u6784\u5efa\u955c\u50cf"
    "\u5e76\u62c9\u8d77\u9694\u79bb\u6c99\u7b71\u3002"
    "\u65b0\u589e Docker \u955c\u50cf\u590d\u7528\u7f13\u5b58\uff08`_image_cache`\uff09"
    "\u2014\u2014\u76f8\u540c\u4ed3\u5e93\u8def\u5f84\u7684\u540e\u7eed\u9a8c\u8bc1"
    "\u76f4\u63a5\u590d\u7528\u5df2\u6784\u5efa\u955c\u50cf\uff0c\u907f\u514d\u91cd\u590d"
    " `docker build` \u5f00\u9500\uff0c\u5728 PoC \u8fed\u4ee3\u573a\u666f\u4e0b\u6548\u679c"
    "\u663e\u8457\u3002HTTP \u8bf7\u6c42\u6784\u9020\u80fd\u529b\u5df2\u5168\u9762\u6269\u5c55"
    "\uff1a\u652f\u6301 JSON Body\uff08`application/json`\uff09\u3001\u81ea\u5b9a\u4e49"
    " Header \u4e0e Cookie \u7684\u5b8c\u6574\u6784\u9020\uff0c\u8986\u76d6\u73b0\u4ee3"
    " API \u7684\u771f\u5b9e\u8c03\u7528\u573a\u666f\u3002"
    "\u9a8c\u8bc1\u5224\u5b9a\u91c7\u7528**\u53cc\u5c42\u5206\u6790\u673a\u5236**\uff1a"
)
if old_E in text:
    text = text.replace(old_E, new_E, 1)
    print("OK E: Agent-E Docker cache + full HTTP")
    changes += 1
else:
    print("MISS E, searching...")
    idx = text.find('docker-compose')
    print(repr(text[idx-5:idx+120]))

print(f"\nTotal: {changes} changes")
with open(r'c:\Users\23504\Desktop\reV\paper2.md', 'wb') as f:
    f.write(text.encode('utf-8'))
print("File saved.")
