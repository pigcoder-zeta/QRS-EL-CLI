"""
规则记忆库：将编译成功的 .ql 文件持久化，并支持语义检索。

工作流：
1. 每次 Agent-Q 成功生成并编译通过一条规则后，调用 `save()` 写入索引。
2. 下次生成相似漏洞类型时，调用 `search()` 检索最近邻规则作为 Few-Shot 示例。
3. 索引文件为纯 JSON（rule_memory_index.json），无需外部向量数据库。
4. 相似度算法：TF-IDF + 余弦相似度（依赖 scikit-learn，轻量可选）。
   若 scikit-learn 不可用，降级为词袋 Jaccard 相似度。
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import numpy as np

logger = logging.getLogger(__name__)

_INDEX_FILENAME = "rule_memory_index.json"
_EMBEDDING_FILENAME = "embeddings.npz"   # numpy 压缩格式存储向量
_EMBED_MODEL = "all-MiniLM-L6-v2"       # sentence-transformers 轻量模型（80MB）

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class RuleRecord:
    """
    单条成功规则的元数据记录。

    Attributes:
        rule_id: 唯一 ID（时间戳 + 随机后缀）。
        language: 目标语言（java / python / ...）。
        vuln_type: 漏洞类型描述（如 Spring EL Injection）。
        query_path: .ql 文件路径（已持久化到 memory_dir/rules/ 下）。
        created_at: 创建时间 ISO 字符串。
        tags: 额外标签（框架名、引擎名等）。
    """

    rule_id: str
    language: str
    vuln_type: str
    query_path: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 相似度计算
# ---------------------------------------------------------------------------


def _jaccard_similarity(a: str, b: str) -> float:
    """词袋 Jaccard 相似度（不依赖任何第三方库）。"""
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if not tokens_a and not tokens_b:
        return 1.0
    inter = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return inter / union if union else 0.0


def _tfidf_similarity(query_text: str, corpus: list[str]) -> list[float]:
    """
    TF-IDF + 余弦相似度（需要 scikit-learn）。
    失败时自动降级为 Jaccard。
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity

        texts = [query_text] + corpus
        vec = TfidfVectorizer(analyzer="word", token_pattern=r"[a-zA-Z0-9_]+")
        tfidf = vec.fit_transform(texts)
        sims = cosine_similarity(tfidf[0:1], tfidf[1:]).flatten()
        return sims.tolist()
    except ImportError:
        logger.debug("scikit-learn 未安装，降级为 Jaccard 相似度。")
        return [_jaccard_similarity(query_text, doc) for doc in corpus]


def _neural_similarity(
    query_text: str,
    corpus: list[str],
    cached_embeddings: Optional["np.ndarray"],
) -> tuple[list[float], Optional["np.ndarray"]]:
    """
    sentence-transformers 神经嵌入 + 余弦相似度。

    Args:
        query_text: 查询文本。
        corpus: 候选文档列表。
        cached_embeddings: 已缓存的候选向量矩阵（shape: [N, dim]），为 None 时重新编码。

    Returns:
        (scores, corpus_embeddings) — 相似度列表 + 最新候选矩阵（供外部缓存）。
    """
    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer  # type: ignore
        from sklearn.metrics.pairwise import cosine_similarity

        model = SentenceTransformer(_EMBED_MODEL)
        q_vec = model.encode([query_text], normalize_embeddings=True)

        if cached_embeddings is not None and cached_embeddings.shape[0] == len(corpus):
            c_vecs = cached_embeddings
        else:
            c_vecs = model.encode(corpus, normalize_embeddings=True)

        sims = cosine_similarity(q_vec, c_vecs).flatten()
        return sims.tolist(), c_vecs

    except ImportError:
        logger.debug("sentence-transformers 未安装，降级为 TF-IDF 相似度。")
        return _tfidf_similarity(query_text, corpus), None


# ---------------------------------------------------------------------------
# RuleMemory 主类
# ---------------------------------------------------------------------------


class RuleMemory:
    """
    规则记忆库。

    Args:
        memory_dir: 存储根目录，内含 rule_memory_index.json 与 rules/ 子目录。
    """

    def __init__(
        self,
        memory_dir: str = "data/rule_memory",
        use_neural: bool = True,
    ) -> None:
        self.memory_dir = Path(memory_dir)
        self.rules_dir = self.memory_dir / "rules"
        self.index_path = self.memory_dir / _INDEX_FILENAME
        self.embed_path = self.memory_dir / _EMBEDDING_FILENAME
        self.use_neural = use_neural
        self._records: list[RuleRecord] = []
        self._corpus_embeddings: Optional["np.ndarray"] = None
        self._load_index()
        self._load_embeddings()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------

    def _load_index(self) -> None:
        """从磁盘加载索引。"""
        if not self.index_path.exists():
            return
        try:
            with open(self.index_path, encoding="utf-8") as fh:
                raw = json.load(fh)
            self._records = [RuleRecord(**item) for item in raw.get("records", [])]
            logger.debug("规则记忆库加载完成：%d 条规则。", len(self._records))
        except Exception as exc:  # noqa: BLE001
            logger.warning("规则记忆库索引损坏，重置为空: %s", exc)
            self._records = []

    def _load_embeddings(self) -> None:
        """从磁盘加载缓存的神经嵌入矩阵。"""
        if not self.use_neural or not self.embed_path.exists():
            return
        try:
            import numpy as np
            data = np.load(str(self.embed_path))
            self._corpus_embeddings = data["embeddings"]
            logger.debug("嵌入矩阵加载完成: shape=%s", self._corpus_embeddings.shape)
        except Exception as exc:  # noqa: BLE001
            logger.debug("嵌入矩阵加载失败，将重新编码: %s", exc)
            self._corpus_embeddings = None

    def _save_embeddings(self, embeddings: "np.ndarray") -> None:
        """将神经嵌入矩阵持久化到磁盘。"""
        try:
            import numpy as np
            np.savez_compressed(str(self.embed_path), embeddings=embeddings)
            self._corpus_embeddings = embeddings
        except Exception as exc:  # noqa: BLE001
            logger.debug("嵌入矩阵保存失败: %s", exc)

    def _save_index(self) -> None:
        """将内存索引写回磁盘。"""
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        payload = {"records": [asdict(r) for r in self._records]}
        with open(self.index_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    def save(
        self,
        language: str,
        vuln_type: str,
        query_path: str,
        tags: Optional[list[str]] = None,
    ) -> RuleRecord:
        """
        将一条编译成功的规则写入记忆库。

        Args:
            language: 目标语言。
            vuln_type: 漏洞类型描述。
            query_path: 原始 .ql 文件路径。
            tags: 额外标签列表。

        Returns:
            写入的 RuleRecord。
        """
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        src = Path(query_path)
        if not src.exists():
            raise FileNotFoundError(f"规则文件不存在: {query_path}")

        # 将 .ql 文件复制到 rules/ 归档目录
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        lang_safe = language.lower()
        archived_name = f"{lang_safe}_{ts}_{src.stem}.ql"
        dest = self.rules_dir / archived_name
        shutil.copy2(src, dest)

        record = RuleRecord(
            rule_id=f"{lang_safe}_{ts}",
            language=language.lower(),
            vuln_type=vuln_type,
            query_path=str(dest),
            tags=tags or [],
        )
        self._records.append(record)
        self._save_index()
        # 新增规则后使嵌入缓存失效，下次搜索时重新编码
        self._corpus_embeddings = None
        if self.embed_path.exists():
            self.embed_path.unlink(missing_ok=True)

        logger.info(
            "[RuleMemory] 规则已归档 | 语言: %s | 类型: %s | 路径: %s",
            language, vuln_type, dest,
        )
        return record

    # ------------------------------------------------------------------
    # 检索
    # ------------------------------------------------------------------

    def search(
        self,
        language: str,
        vuln_type: str,
        top_k: int = 3,
    ) -> list[tuple[RuleRecord, float]]:
        """
        检索与目标漏洞类型最相似的历史规则。

        Args:
            language: 过滤语言（空字符串表示不过滤）。
            vuln_type: 漏洞类型查询词。
            top_k: 返回最多 k 条结果。

        Returns:
            (RuleRecord, similarity_score) 元组列表，按相似度降序排列。
        """
        candidates = [
            r for r in self._records
            if not language or r.language == language.lower()
        ]
        if not candidates:
            return []

        corpus = [f"{r.language} {r.vuln_type} {' '.join(r.tags)}" for r in candidates]
        query_text = f"{language} {vuln_type}"

        if self.use_neural:
            scores, new_embeddings = _neural_similarity(
                query_text, corpus, self._corpus_embeddings
            )
            if new_embeddings is not None and self._corpus_embeddings is None:
                self._save_embeddings(new_embeddings)
        else:
            scores = _tfidf_similarity(query_text, corpus)

        ranked = sorted(
            zip(candidates, scores),
            key=lambda x: x[1],
            reverse=True,
        )
        return ranked[:top_k]

    def load_query_code(self, record: RuleRecord) -> str:
        """读取记录对应的 .ql 源代码。"""
        path = Path(record.query_path)
        if not path.exists():
            raise FileNotFoundError(f"规则文件已被删除: {path}")
        return path.read_text(encoding="utf-8")

    def count(self) -> int:
        """返回库中规则总数。"""
        return len(self._records)

    def __repr__(self) -> str:
        return f"<RuleMemory records={len(self._records)} dir={self.memory_dir}>"
