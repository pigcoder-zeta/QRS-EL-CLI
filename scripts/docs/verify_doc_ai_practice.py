from pathlib import Path

from docx import Document

ROOT = Path(__file__).resolve().parents[2]
p = ROOT / "赵泽达_设计与开发文档 (1).docx"
d = Document(p)

keys = [
    "作品在人工智能实践赛视角下的价值与待验证问题",
    "（一）创新性边界：技术整合能力突出，但原创突破仍需进一步厘清",
    "（二）神经符号融合深度：当前更接近“LLM 增强型 SAST”",
    "（三）技术实现透明度与鲁棒性：关键环节需补充可复核细节",
    "实用性与推广可行性评估",
    "面向人工智能实践赛决赛的改进重点",
]

for k in keys:
    ok = any((para.text or "").strip() == k for para in d.paragraphs)
    print(("FOUND" if ok else "MISS"), k)
