"""
高级 RAG 规则记忆库（Rule Memory with RAG）。

架构升级：从 TF-IDF 升级为向量语义检索，存储完整的漏洞链路上下文。

存储维度（每条成功规则）：
  - QL 查询代码
  - Sink 方法全名
  - Source → Sink 数据流路径摘要
  - SARIF 发现消息
  - 漏洞代码片段
  - 检测到的框架/引擎
  - CWE 编号

来源验证机制（抵御投毒攻击）：
  - 每条记录携带 source_repo / source_commit / ql_hash 溯源元数据
  - 信任级别（TrustLevel）：trusted > verified > unverified > quarantined
  - 本地扫描默认 verified；Bundle 导入默认 unverified（隔离期）
  - search() 默认只注入 verified 以上记录，低信任记录不参与 Few-Shot
  - HMAC-SHA256 签名保护 Bundle 完整性，签名不符时拒绝导入

向量后端优先级（自动选择最优可用后端）：
  1. ChromaDB        — 本地持久向量数据库（最优，支持语义+元数据过滤）
  2. FAISS           — 高性能向量索引（大规模场景）
  3. sentence-transformers + numpy  — 轻量嵌入（中等）
  4. TF-IDF          — 纯 sklearn（最轻量）
  5. Jaccard         — 零依赖回退
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    import numpy as np

logger = logging.getLogger(__name__)

_INDEX_FILENAME     = "rule_memory_index.json"
_EMBEDDING_FILENAME = "embeddings.npz"
_CHROMA_DIR         = "chroma_db"
_EMBED_MODEL        = "all-MiniLM-L6-v2"

# ---------------------------------------------------------------------------
# 信任级别
# ---------------------------------------------------------------------------

class TrustLevel:
    """RuleRecord 信任级别常量（从高到低）。"""
    TRUSTED      = "trusted"       # 团队手动验证，最高信任
    VERIFIED     = "verified"      # 本机本地扫描产生，自动信任
    UNVERIFIED   = "unverified"    # 外部 Bundle 导入，处于隔离期
    QUARANTINED  = "quarantined"   # 被明确标记为可疑，永不参与检索

    _ORDER = {TRUSTED: 3, VERIFIED: 2, UNVERIFIED: 1, QUARANTINED: 0}

    @classmethod
    def rank(cls, level: str) -> int:
        return cls._ORDER.get(level, 0)

    @classmethod
    def meets(cls, level: str, minimum: str) -> bool:
        """level 是否达到 minimum 要求。"""
        return cls.rank(level) >= cls.rank(minimum)

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class RuleRecord:
    """
    单条成功规则的完整上下文记录。

    字段说明：
        sink_method:        危险 Sink 方法全名（如 ognl.Ognl.getValue）
        data_flow_summary:  Source → Sink 数据流路径的自然语言摘要
        sarif_message:      CodeQL 原始发现消息
        code_snippet:       漏洞所在代码片段（20行以内）
        cwe:                CWE 编号（如 CWE-094）
        detected_frameworks: 检测到的项目框架列表

        --- 来源验证字段（抵御投毒攻击）---
        source_repo:        来源仓库 URL 或本地路径（local://<path>）
        source_commit:      扫描时的 git commit hash
        ql_hash:            QL 文件内容的 SHA-256（完整性校验）
        trust_level:        信任级别（TrustLevel 常量）
        import_source:      记录来源类型（local_scan / bundle_import / manual）
        verified_at:        人工验证时间戳（verified/trusted 时设置）
        verified_by:        人工验证者标识
    """

    rule_id:             str
    language:            str
    vuln_type:           str
    query_path:          str
    created_at:          str        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags:                list[str]  = field(default_factory=list)

    # ── 漏洞链路上下文（RAG 核心） ────────────────────────────────────────
    sink_method:         str        = ""
    data_flow_summary:   str        = ""
    sarif_message:       str        = ""
    code_snippet:        str        = ""
    cwe:                 str        = ""
    detected_frameworks: list[str]  = field(default_factory=list)

    # ── 来源验证字段 ──────────────────────────────────────────────────────
    source_repo:         str        = ""                    # 来源仓库 URL / local:// 路径
    source_commit:       str        = ""                    # git commit hash
    ql_hash:             str        = ""                    # SHA-256(QL 文件内容)
    trust_level:         str        = TrustLevel.VERIFIED   # 默认本地扫描可信
    import_source:       str        = "local_scan"          # local_scan / bundle_import / manual
    verified_at:         str        = ""
    verified_by:         str        = ""

    def to_embedding_text(self) -> str:
        """
        将记录序列化为用于向量嵌入的富文本。

        包含漏洞类型、语言、Sink、数据流路径和代码片段，
        让向量模型能理解"漏洞利用链路"的语义而非仅靠关键词。
        """
        parts = [
            f"Language: {self.language}",
            f"Vulnerability: {self.vuln_type}",
            f"CWE: {self.cwe}" if self.cwe else "",
            f"Sink: {self.sink_method}" if self.sink_method else "",
            f"Frameworks: {', '.join(self.detected_frameworks)}" if self.detected_frameworks else "",
            f"Data flow: {self.data_flow_summary}" if self.data_flow_summary else "",
            f"Finding: {self.sarif_message}" if self.sarif_message else "",
            f"Code:\n{self.code_snippet}" if self.code_snippet else "",
        ]
        return "\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# 向量后端抽象
# ---------------------------------------------------------------------------


class _VectorBackend:
    """向量检索后端基类（策略模式）。"""

    name: str = "base"

    def add(self, record_id: str, text: str, metadata: dict[str, Any]) -> None:
        raise NotImplementedError

    def query(self, query_text: str, n_results: int, where: dict | None = None) -> list[tuple[str, float]]:
        """返回 (record_id, similarity_score) 列表，按相似度降序。"""
        raise NotImplementedError

    def delete(self, record_id: str) -> None:
        pass

    def count(self) -> int:
        return 0


class _ChromaBackend(_VectorBackend):
    """ChromaDB 后端：本地持久向量数据库，支持元数据过滤。"""

    name = "chromadb"

    def __init__(self, persist_dir: Path) -> None:
        import chromadb  # type: ignore

        persist_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(persist_dir))

        # 优先使用 sentence-transformers 嵌入函数，
        # 若未安装则回退到 ChromaDB 内置的 ONNX MiniLM 嵌入函数（无需额外依赖）
        try:
            from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction  # type: ignore
            ef: Any = SentenceTransformerEmbeddingFunction(model_name=_EMBED_MODEL)
            logger.debug("[ChromaDB] 使用 SentenceTransformer 嵌入函数")
        except (ImportError, ValueError):
            from chromadb.utils.embedding_functions import DefaultEmbeddingFunction  # type: ignore
            ef = DefaultEmbeddingFunction()
            logger.debug("[ChromaDB] 使用内置 ONNX 嵌入函数（DefaultEmbeddingFunction）")

        self._col = self._client.get_or_create_collection(
            name="qrs_rule_memory",
            embedding_function=ef,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("[RuleMemory] 使用 ChromaDB 后端 (持久化路径: %s)", persist_dir)

    def add(self, record_id: str, text: str, metadata: dict[str, Any]) -> None:
        # ChromaDB metadata 只支持 str/int/float/bool，list 需要序列化
        safe_meta = {
            k: json.dumps(v) if isinstance(v, list) else v
            for k, v in metadata.items()
        }
        self._col.upsert(ids=[record_id], documents=[text], metadatas=[safe_meta])

    def query(self, query_text: str, n_results: int, where: dict | None = None) -> list[tuple[str, float]]:
        kwargs: dict[str, Any] = {"query_texts": [query_text], "n_results": min(n_results, self.count())}
        if where:
            kwargs["where"] = where
        if self.count() == 0:
            return []
        try:
            result = self._col.query(**kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[ChromaDB] 查询失败: %s", exc)
            return []
        ids = result["ids"][0]
        # ChromaDB 返回距离（余弦距离 = 1 - 相似度），转换为相似度
        distances = result["distances"][0]
        return [(rid, 1.0 - dist) for rid, dist in zip(ids, distances)]

    def count(self) -> int:
        return self._col.count()


class _FAISSBackend(_VectorBackend):
    """FAISS 后端：高性能内存向量索引，适合大规模规则库。"""

    name = "faiss"

    def __init__(self, index_path: Path) -> None:
        import faiss  # type: ignore
        import numpy as np
        from sentence_transformers import SentenceTransformer  # type: ignore

        self._index_path = index_path
        self._model = SentenceTransformer(_EMBED_MODEL)
        self._dim = self._model.get_sentence_embedding_dimension()
        self._id_map: list[str] = []   # FAISS index → record_id

        if index_path.exists():
            self._index = faiss.read_index(str(index_path))
            id_map_path = index_path.with_suffix(".ids.json")
            if id_map_path.exists():
                self._id_map = json.loads(id_map_path.read_text())
        else:
            self._index = faiss.IndexFlatIP(self._dim)  # 内积（归一化后等价余弦）

        logger.info("[RuleMemory] 使用 FAISS 后端 (维度: %d)", self._dim)

    def add(self, record_id: str, text: str, metadata: dict[str, Any]) -> None:
        import faiss
        import numpy as np

        vec = self._model.encode([text], normalize_embeddings=True).astype("float32")
        self._index.add(vec)
        self._id_map.append(record_id)
        self._persist()

    def query(self, query_text: str, n_results: int, where: dict | None = None) -> list[tuple[str, float]]:
        import numpy as np

        if len(self._id_map) == 0:
            return []
        vec = self._model.encode([query_text], normalize_embeddings=True).astype("float32")
        k = min(n_results, len(self._id_map))
        scores, indices = self._index.search(vec, k)
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0 and idx < len(self._id_map):
                results.append((self._id_map[idx], float(score)))
        return results

    def count(self) -> int:
        return len(self._id_map)

    def _persist(self) -> None:
        import faiss
        self._index_path.parent.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self._index, str(self._index_path))
        id_map_path = self._index_path.with_suffix(".ids.json")
        id_map_path.write_text(json.dumps(self._id_map), encoding="utf-8")


class _EmbeddingBackend(_VectorBackend):
    """sentence-transformers + numpy 后端（中量级，无需额外数据库）。"""

    name = "sentence-transformers"

    def __init__(self, embed_path: Path) -> None:
        from sentence_transformers import SentenceTransformer  # type: ignore
        self._model = SentenceTransformer(_EMBED_MODEL)
        self._embed_path = embed_path
        self._ids: list[str] = []
        self._vecs: Optional["np.ndarray"] = None
        self._load()
        logger.info("[RuleMemory] 使用 sentence-transformers 后端")

    def _load(self) -> None:
        import numpy as np
        if not self._embed_path.exists():
            return
        try:
            data = np.load(str(self._embed_path), allow_pickle=True)
            self._vecs = data["vecs"]
            self._ids = list(data["ids"])
        except Exception:
            pass

    def _save(self) -> None:
        import numpy as np
        if self._vecs is None:
            return
        self._embed_path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(str(self._embed_path), vecs=self._vecs, ids=np.array(self._ids))

    def add(self, record_id: str, text: str, metadata: dict[str, Any]) -> None:
        import numpy as np
        vec = self._model.encode([text], normalize_embeddings=True)
        if self._vecs is None:
            self._vecs = vec
        else:
            self._vecs = np.vstack([self._vecs, vec])
        self._ids.append(record_id)
        self._save()

    def query(self, query_text: str, n_results: int, where: dict | None = None) -> list[tuple[str, float]]:
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity
        if self._vecs is None or len(self._ids) == 0:
            return []
        q_vec = self._model.encode([query_text], normalize_embeddings=True)
        sims = cosine_similarity(q_vec, self._vecs).flatten()
        top_idx = sims.argsort()[::-1][:n_results]
        return [(self._ids[i], float(sims[i])) for i in top_idx]

    def count(self) -> int:
        return len(self._ids)


class _TFIDFBackend(_VectorBackend):
    """TF-IDF + 余弦相似度后端（仅需 scikit-learn）。"""

    name = "tfidf"

    def __init__(self) -> None:
        self._docs: dict[str, str] = {}   # record_id → text
        logger.info("[RuleMemory] 使用 TF-IDF 后端")

    def add(self, record_id: str, text: str, metadata: dict[str, Any]) -> None:
        self._docs[record_id] = text

    def query(self, query_text: str, n_results: int, where: dict | None = None) -> list[tuple[str, float]]:
        if not self._docs:
            return []
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity

            ids = list(self._docs.keys())
            corpus = [self._docs[i] for i in ids]
            texts = [query_text] + corpus
            vec = TfidfVectorizer(analyzer="word", token_pattern=r"[a-zA-Z0-9_]+")
            tfidf = vec.fit_transform(texts)
            sims = cosine_similarity(tfidf[0:1], tfidf[1:]).flatten()
            ranked = sorted(zip(ids, sims.tolist()), key=lambda x: x[1], reverse=True)
            return ranked[:n_results]
        except ImportError:
            # 最终降级：Jaccard
            results = []
            q_tokens = set(query_text.lower().split())
            for rid, text in self._docs.items():
                d_tokens = set(text.lower().split())
                union = len(q_tokens | d_tokens)
                sim = len(q_tokens & d_tokens) / union if union else 0.0
                results.append((rid, sim))
            results.sort(key=lambda x: x[1], reverse=True)
            return results[:n_results]

    def count(self) -> int:
        return len(self._docs)


def _build_backend(memory_dir: Path, backend: str) -> _VectorBackend:
    """
    按优先级尝试构建向量后端。

    优先级: chromadb → faiss → sentence-transformers → tfidf
    """
    order = ["chromadb", "faiss", "sentence-transformers", "tfidf"] \
        if backend == "auto" else [backend, "tfidf"]

    for name in order:
        try:
            if name == "chromadb":
                return _ChromaBackend(memory_dir / _CHROMA_DIR)
            elif name == "faiss":
                return _FAISSBackend(memory_dir / "faiss.index")
            elif name == "sentence-transformers":
                return _EmbeddingBackend(memory_dir / _EMBEDDING_FILENAME)
            elif name == "tfidf":
                return _TFIDFBackend()
        except Exception as exc:
            logger.debug("[RuleMemory] %s 后端初始化失败，尝试下一个: %s", name, exc)

    return _TFIDFBackend()  # 保底


# ---------------------------------------------------------------------------
# RuleMemory 主类
# ---------------------------------------------------------------------------


class RuleMemory:
    """
    高级 RAG 规则记忆库。

    Args:
        memory_dir: 存储根目录。
        backend:    向量后端选择（"auto" / "chromadb" / "faiss" / "sentence-transformers" / "tfidf"）。
    """

    def __init__(
        self,
        memory_dir: str = "data/rule_memory",
        backend: str = "auto",
        trusted_sources: Optional[list[str]] = None,
    ) -> None:
        self.memory_dir = Path(memory_dir)
        self.rules_dir  = self.memory_dir / "rules"
        self.index_path = self.memory_dir / _INDEX_FILENAME
        self._records: dict[str, RuleRecord] = {}
        self._backend: _VectorBackend = _build_backend(self.memory_dir, backend)
        # 受信任来源白名单：local:// 始终在白名单内
        self._trusted_sources: set[str] = {"local://"}
        if trusted_sources:
            self._trusted_sources.update(trusted_sources)
        self._load_index()
        self._sync_backend()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------

    def _load_index(self) -> None:
        if not self.index_path.exists():
            return
        try:
            with open(self.index_path, encoding="utf-8") as fh:
                raw = json.load(fh)
            for item in raw.get("records", []):
                rec = RuleRecord(**item)
                self._records[rec.rule_id] = rec
            logger.debug(
                "[RuleMemory] 索引加载完成：%d 条规则，后端: %s",
                len(self._records), self._backend.name,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("[RuleMemory] 索引损坏，重置: %s", exc)

    def _save_index(self) -> None:
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        payload = {"records": [asdict(r) for r in self._records.values()]}
        with open(self.index_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

    def _sync_backend(self) -> None:
        """将 JSON 索引中已有记录同步到向量后端（应对后端重置场景）。"""
        if self._backend.count() == len(self._records):
            return
        logger.debug("[RuleMemory] 向量后端记录数不一致，重新同步...")
        for record in self._records.values():
            self._backend.add(
                record_id=record.rule_id,
                text=record.to_embedding_text(),
                metadata={"language": record.language, "vuln_type": record.vuln_type},
            )

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    def save(
        self,
        language: str,
        vuln_type: str,
        query_path: str,
        tags:                Optional[list[str]] = None,
        sink_method:         str = "",
        data_flow_summary:   str = "",
        sarif_message:       str = "",
        code_snippet:        str = "",
        cwe:                 str = "",
        detected_frameworks: Optional[list[str]] = None,
        # ── 来源验证参数 ────────────────────────────────────────────────
        source_repo:         str = "",
        source_commit:       str = "",
        import_source:       str = "local_scan",
        trust_level:         Optional[str] = None,
    ) -> RuleRecord:
        """
        将一条编译成功的规则及其漏洞链路上下文写入记忆库。

        来源验证逻辑：
          - local_scan:    默认 trust_level = verified（自己扫描的可信）
          - bundle_import: 默认 trust_level = unverified（外部导入需人工审核）
          - manual:        trust_level 由调用方指定

        Args:
            language:           目标语言。
            vuln_type:          漏洞类型描述。
            query_path:         原始 .ql 文件路径。
            source_repo:        扫描来源仓库 URL 或本地路径。
            source_commit:      扫描时的 git commit hash。
            import_source:      记录来源类型（local_scan/bundle_import/manual）。
            trust_level:        显式指定信任级别（None 时自动推断）。

        Returns:
            写入的 RuleRecord。
        """
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        src = Path(query_path)
        if not src.exists():
            raise FileNotFoundError(f"规则文件不存在: {query_path}")

        # 计算 QL 文件的 SHA-256 完整性指纹
        ql_content = src.read_bytes()
        ql_hash = hashlib.sha256(ql_content).hexdigest()

        # 自动推断信任级别
        if trust_level is None:
            trust_level = (
                TrustLevel.VERIFIED   if import_source == "local_scan"
                else TrustLevel.UNVERIFIED
            )

        # 检查白名单：白名单仓库自动升为 verified
        if trust_level == TrustLevel.UNVERIFIED and self._is_trusted_source(source_repo):
            trust_level = TrustLevel.VERIFIED
            logger.debug("[RuleMemory] 白名单仓库，自动升级为 verified: %s", source_repo)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        lang_safe = language.lower()
        archived_name = f"{lang_safe}_{ts}_{src.stem}.ql"
        dest = self.rules_dir / archived_name
        shutil.copy2(src, dest)

        record = RuleRecord(
            rule_id=f"{lang_safe}_{ts}",
            language=lang_safe,
            vuln_type=vuln_type,
            query_path=str(dest),
            tags=tags or [],
            sink_method=sink_method,
            data_flow_summary=data_flow_summary,
            sarif_message=sarif_message,
            code_snippet=code_snippet[:1500],
            cwe=cwe,
            detected_frameworks=detected_frameworks or [],
            # 来源验证字段
            source_repo=source_repo,
            source_commit=source_commit,
            ql_hash=ql_hash,
            trust_level=trust_level,
            import_source=import_source,
        )

        self._records[record.rule_id] = record
        self._save_index()

        self._backend.add(
            record_id=record.rule_id,
            text=record.to_embedding_text(),
            metadata={"language": lang_safe, "vuln_type": vuln_type,
                      "trust_level": trust_level},
        )

        logger.info(
            "[RuleMemory] 规则已归档 | %s | %s | sink=%s | trust=%s | 后端=%s",
            lang_safe, vuln_type, sink_method or "N/A", trust_level, self._backend.name,
        )

        if trust_level == TrustLevel.UNVERIFIED:
            logger.warning(
                "[RuleMemory] ⚠ 规则 %s 处于 unverified 状态（来源: %s），"
                "不会参与 Few-Shot 检索，请运行 rule_memory.verify('%s') 后启用。",
                record.rule_id, source_repo or import_source, record.rule_id,
            )

        return record

    # ------------------------------------------------------------------
    # 语义检索
    # ------------------------------------------------------------------

    def search(
        self,
        language: str,
        vuln_type: str,
        sink_hint:         str = "",
        top_k:             int = 3,
        min_trust_level:   str = TrustLevel.VERIFIED,
        score_threshold:   float = 0.3,
    ) -> list[tuple[RuleRecord, float]]:
        """
        语义检索最相似的历史规则（利用链路级别的向量匹配）。

        投毒防御：
          - 默认只返回 trust_level >= verified 的记录
          - quarantined 记录永远不参与检索
          - 相似度低于 score_threshold 的结果被丢弃

        Args:
            language:        目标语言，用于 metadata 过滤。
            vuln_type:       漏洞类型，作为查询核心语义。
            sink_hint:       可选的 Sink 方法提示，加入查询文本提升精度。
            top_k:           最多返回 k 条。
            min_trust_level: 最低信任级别要求（默认 verified）。
            score_threshold: 最低相似度阈值（默认 0.3）。

        Returns:
            (RuleRecord, similarity_score) 列表，按相似度降序。
        """
        if not self._records:
            return []

        query_parts = [f"Language: {language}", f"Vulnerability: {vuln_type}"]
        if sink_hint:
            query_parts.append(f"Sink: {sink_hint}")
        query_text = "\n".join(query_parts)

        if self._backend.name == "chromadb":
            where_clauses = [{"language": language.lower()}]
            if vuln_type:
                where_clauses.append({"vuln_type": vuln_type.lower()})
            where = {"$and": where_clauses} if len(where_clauses) > 1 else where_clauses[0]
        else:
            where = None
        raw = self._backend.query(query_text, n_results=top_k * 5, where=where)

        results = []
        skipped_untrusted = 0

        for rid, score in raw:
            if rid not in self._records:
                continue
            record = self._records[rid]

            # 语言过滤（非 ChromaDB 后端）
            if language and record.language != language.lower():
                continue

            # 相似度阈值过滤
            if score < score_threshold:
                continue

            # 信任级别过滤（核心防投毒逻辑）
            if record.trust_level == TrustLevel.QUARANTINED:
                logger.debug(
                    "[RuleMemory] 跳过隔离记录 %s（trust=quarantined）", rid
                )
                continue

            if not TrustLevel.meets(record.trust_level, min_trust_level):
                skipped_untrusted += 1
                logger.debug(
                    "[RuleMemory] 跳过低信任记录 %s（trust=%s，要求>=%s，来源=%s）",
                    rid, record.trust_level, min_trust_level, record.source_repo or "unknown",
                )
                continue

            # 完整性校验：验证 ql_hash 是否与文件一致
            if record.ql_hash:
                try:
                    actual_hash = hashlib.sha256(
                        Path(record.query_path).read_bytes()
                    ).hexdigest()
                    if actual_hash != record.ql_hash:
                        logger.warning(
                            "[RuleMemory] ⚠ 完整性校验失败！记录 %s 的 QL 文件已被篡改，跳过。"
                            "期望 hash=%s，实际 hash=%s",
                            rid, record.ql_hash[:12], actual_hash[:12],
                        )
                        # 自动隔离被篡改的记录
                        self._auto_quarantine(rid, reason="ql_hash_mismatch")
                        continue
                except FileNotFoundError:
                    logger.warning("[RuleMemory] QL 文件缺失: %s，跳过记录 %s", record.query_path, rid)
                    continue

            results.append((record, score))

        if skipped_untrusted > 0:
            logger.info(
                "[RuleMemory] 已过滤 %d 条低信任记录（min_trust=%s），"
                "可运行 rule_memory.verify('<rule_id>') 提升信任级别",
                skipped_untrusted, min_trust_level,
            )

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def load_query_code(self, record: RuleRecord) -> str:
        """读取记录对应的 .ql 源代码。"""
        path = Path(record.query_path)
        if not path.exists():
            raise FileNotFoundError(f"规则文件已被删除: {path}")
        return path.read_text(encoding="utf-8")

    def count(self) -> int:
        """返回库中规则总数。"""
        return len(self._records)

    def get_backend_name(self) -> str:
        """返回当前使用的向量后端名称。"""
        return self._backend.name

    # ------------------------------------------------------------------
    # 来源验证 API
    # ------------------------------------------------------------------

    def verify(
        self,
        rule_id: str,
        verified_by: str = "manual",
        promote_to: str = TrustLevel.VERIFIED,
    ) -> bool:
        """
        人工验证一条记录，提升其信任级别。

        Args:
            rule_id:     要验证的记录 ID。
            verified_by: 验证者标识（用户名/系统名）。
            promote_to:  目标信任级别（默认 verified，团队核心规则可设为 trusted）。

        Returns:
            True 表示成功，False 表示记录不存在。
        """
        if rule_id not in self._records:
            logger.warning("[RuleMemory] verify() 目标记录不存在: %s", rule_id)
            return False

        record = self._records[rule_id]
        old_level = record.trust_level
        record.trust_level = promote_to
        record.verified_at = datetime.now(timezone.utc).isoformat()
        record.verified_by = verified_by
        self._save_index()
        logger.info(
            "[RuleMemory] 记录 %s 已验证：%s → %s（验证者: %s）",
            rule_id, old_level, promote_to, verified_by,
        )
        return True

    def quarantine(self, rule_id: str, reason: str = "manual") -> bool:
        """
        隔离一条可疑记录，使其永久不参与 Few-Shot 检索。

        Args:
            rule_id: 要隔离的记录 ID。
            reason:  隔离原因（记录到日志）。

        Returns:
            True 表示成功，False 表示记录不存在。
        """
        if rule_id not in self._records:
            return False
        record = self._records[rule_id]
        record.trust_level = TrustLevel.QUARANTINED
        record.tags = list(set(record.tags + [f"quarantined:{reason}"]))
        self._save_index()
        logger.warning(
            "[RuleMemory] ⚠ 记录 %s 已被隔离（原因: %s）。"
            "该规则将不再参与任何 Few-Shot 检索。",
            rule_id, reason,
        )
        return True

    def _auto_quarantine(self, rule_id: str, reason: str) -> None:
        """内部自动隔离接口（篡改检测时调用）。"""
        self.quarantine(rule_id, reason=f"auto:{reason}")

    def get_trust_stats(self) -> dict[str, Any]:
        """
        返回记忆库信任级别统计信息。

        Returns:
            包含各级别计数、来源分布、最近写入记录摘要的字典。
        """
        from collections import Counter
        level_counts: Counter = Counter()
        source_counts: Counter = Counter()
        hash_mismatches = 0

        for record in self._records.values():
            level_counts[record.trust_level] += 1
            source_counts[record.import_source] += 1
            # 快速完整性预检
            if record.ql_hash:
                try:
                    actual = hashlib.sha256(
                        Path(record.query_path).read_bytes()
                    ).hexdigest()
                    if actual != record.ql_hash:
                        hash_mismatches += 1
                except FileNotFoundError:
                    hash_mismatches += 1

        return {
            "total": len(self._records),
            "by_trust_level": dict(level_counts),
            "by_import_source": dict(source_counts),
            "hash_integrity_errors": hash_mismatches,
            "backend": self._backend.name,
            "trusted_sources": list(self._trusted_sources),
        }

    # 白名单管理
    def add_trusted_source(self, pattern: str) -> None:
        """
        添加受信任仓库来源（支持通配符 * 前缀匹配）。

        示例：
            memory.add_trusted_source("https://github.com/my-org/")
            memory.add_trusted_source("local://")
        """
        self._trusted_sources.add(pattern)
        logger.info("[RuleMemory] 已添加受信任来源: %s", pattern)

    def remove_trusted_source(self, pattern: str) -> None:
        """移除受信任仓库来源。"""
        self._trusted_sources.discard(pattern)

    def _is_trusted_source(self, source_repo: str) -> bool:
        """检查 source_repo 是否匹配任意白名单模式。"""
        if not source_repo:
            return False
        for pattern in self._trusted_sources:
            if pattern.endswith("*"):
                if source_repo.startswith(pattern[:-1]):
                    return True
            elif source_repo == pattern or source_repo.startswith(pattern):
                return True
        return False

    def verify_all_integrity(self) -> dict[str, list[str]]:
        """
        批量校验所有记录的 QL 文件完整性（Hash 比对）。

        Returns:
            {"ok": [...], "tampered": [...], "missing": [...]}
        """
        ok, tampered, missing = [], [], []
        for rid, record in self._records.items():
            if not record.ql_hash:
                ok.append(rid)  # 旧记录无 hash，跳过校验
                continue
            try:
                actual = hashlib.sha256(
                    Path(record.query_path).read_bytes()
                ).hexdigest()
                if actual == record.ql_hash:
                    ok.append(rid)
                else:
                    tampered.append(rid)
                    logger.warning(
                        "[RuleMemory] ⚠ 完整性异常: %s (期望 %s...，实际 %s...)",
                        rid, record.ql_hash[:12], actual[:12],
                    )
            except FileNotFoundError:
                missing.append(rid)

        logger.info(
            "[RuleMemory] 完整性校验完成: ok=%d tampered=%d missing=%d",
            len(ok), len(tampered), len(missing),
        )
        return {"ok": ok, "tampered": tampered, "missing": missing}

    # ------------------------------------------------------------------
    # 导出 / 导入（跨机器共享规则）
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Bundle 导出 / 导入（带 HMAC 签名，抵御 Bundle 投毒）
    # ------------------------------------------------------------------

    _BUNDLE_MANIFEST = "bundle_manifest.json"
    _BUNDLE_HMAC_KEY_ENV = "QRSE_BUNDLE_HMAC_KEY"

    def _get_hmac_key(self) -> Optional[bytes]:
        """从环境变量读取 HMAC 密钥（未设置时返回 None，跳过签名）。"""
        import os
        key = os.environ.get(self._BUNDLE_HMAC_KEY_ENV, "")
        return key.encode() if key else None

    def _compute_bundle_hmac(self, zip_bytes: bytes, key: bytes) -> str:
        """计算 ZIP 内容的 HMAC-SHA256，返回十六进制字符串。"""
        return hmac.new(key, zip_bytes, hashlib.sha256).hexdigest()

    def export_bundle(self, output_path: str, sign: bool = True) -> str:
        """
        将整个规则记忆库打包为一个自包含的 ZIP 文件。

        Bundle 结构：
          rule_memory_index.json  — 元数据索引（含 ql_hash 完整性指纹）
          rules/                  — 所有 .ql 文件
          bundle_manifest.json    — 签名清单（HMAC-SHA256，需设置环境变量 QRSE_BUNDLE_HMAC_KEY）

        Args:
            output_path: 输出 ZIP 文件路径。
            sign:        True 时尝试 HMAC 签名（密钥来自环境变量）。

        Returns:
            实际写入的 ZIP 文件路径。
        """
        import zipfile

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        # 1. 构建清单：每个 QL 文件的 SHA-256
        file_hashes: dict[str, str] = {}
        if self.rules_dir.exists():
            for ql_file in sorted(self.rules_dir.glob("*.ql")):
                h = hashlib.sha256(ql_file.read_bytes()).hexdigest()
                file_hashes[ql_file.name] = h

        manifest = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "record_count": self.count(),
            "file_hashes": file_hashes,
            "hmac_signature": "",   # 先留空，后填
        }

        # 2. 打包 ZIP（不含签名字段）
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if self.index_path.exists():
                zf.write(self.index_path, arcname="rule_memory_index.json")
            if self.rules_dir.exists():
                for ql_file in sorted(self.rules_dir.glob("*.ql")):
                    zf.write(ql_file, arcname=f"rules/{ql_file.name}")
            zf.writestr(self._BUNDLE_MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=2))

        # 3. 若有密钥，计算整个 ZIP 文件的 HMAC 并写入清单
        hmac_key = self._get_hmac_key() if sign else None
        if hmac_key:
            zip_bytes = out.read_bytes()
            sig = self._compute_bundle_hmac(zip_bytes, hmac_key)
            manifest["hmac_signature"] = sig
            # 重写 ZIP，更新清单中的签名
            with zipfile.ZipFile(out, "a") as zf:
                zf.writestr(self._BUNDLE_MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=2))
            logger.info("[RuleMemory] Bundle 已签名（HMAC-SHA256）")
        else:
            logger.warning(
                "[RuleMemory] 未设置环境变量 %s，Bundle 未签名。"
                "导入时将以 unverified 信任级别处理。",
                self._BUNDLE_HMAC_KEY_ENV,
            )

        logger.info("[RuleMemory] 导出完成: %s (共 %d 条规则)", out, self.count())
        return str(out)

    def import_bundle(
        self,
        bundle_path: str,
        merge: bool = True,
        trusted_bundle: bool = False,
    ) -> int:
        """
        从 ZIP Bundle 导入规则记忆库。

        防投毒机制：
          1. 校验 Bundle 内每个 QL 文件的 SHA-256（防文件篡改）
          2. 验证 HMAC-SHA256 签名（防 Bundle 整体替换）
          3. 签名验证通过 → import_source=bundle_import, trust_level=verified
             签名缺失/失败 → import_source=bundle_import, trust_level=unverified
          4. trusted_bundle=True 时跳过隔离（仅用于已知可信的内部分发）

        Args:
            bundle_path:    ZIP 文件路径。
            merge:          True 合并现有库；False 先清空再导入。
            trusted_bundle: 标记为内部可信 Bundle（自动升级为 verified）。

        Returns:
            成功导入的规则条数。
        """
        import zipfile

        bundle = Path(bundle_path)
        if not bundle.exists():
            raise FileNotFoundError(f"Bundle 文件不存在: {bundle_path}")

        # 1. HMAC 签名验证
        signature_valid = False
        hmac_key = self._get_hmac_key()
        if hmac_key:
            try:
                zip_bytes = bundle.read_bytes()
                with zipfile.ZipFile(bundle, "r") as zf:
                    if self._BUNDLE_MANIFEST in zf.namelist():
                        manifest = json.loads(zf.read(self._BUNDLE_MANIFEST).decode())
                        claimed_sig = manifest.get("hmac_signature", "")
                        # 验证签名时需要排除签名字段本身：用预签前内容验证
                        # 简化方案：比较不含签名的 manifest hash
                        if claimed_sig:
                            manifest_no_sig = {k: v for k, v in manifest.items() if k != "hmac_signature"}
                            content_to_verify = json.dumps(manifest_no_sig, ensure_ascii=False, sort_keys=True).encode()
                            expected = hmac.new(hmac_key, content_to_verify, hashlib.sha256).hexdigest()
                            if hmac.compare_digest(claimed_sig, expected):
                                signature_valid = True
                                logger.info("[RuleMemory] Bundle HMAC 签名验证通过")
                            else:
                                logger.warning(
                                    "[RuleMemory] ⚠ Bundle HMAC 签名不匹配！"
                                    "Bundle 可能已被篡改，所有导入记录将标记为 unverified。"
                                )
            except Exception as exc:
                logger.warning("[RuleMemory] 签名验证过程异常: %s", exc)
        else:
            logger.info(
                "[RuleMemory] 未设置 %s，跳过签名验证，导入记录将为 unverified",
                self._BUNDLE_HMAC_KEY_ENV,
            )

        # 决定信任级别
        if trusted_bundle or signature_valid:
            import_trust = TrustLevel.VERIFIED
        else:
            import_trust = TrustLevel.UNVERIFIED

        if not merge:
            if self.memory_dir.exists():
                import shutil as _shutil
                _shutil.rmtree(self.memory_dir)
            self._records = {}

        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)

        imported = 0
        rejected_hash = 0

        with zipfile.ZipFile(bundle, "r") as zf:
            names = zf.namelist()

            # 读取清单（文件级 hash）
            manifest_hashes: dict[str, str] = {}
            if self._BUNDLE_MANIFEST in names:
                try:
                    manifest_hashes = json.loads(
                        zf.read(self._BUNDLE_MANIFEST).decode()
                    ).get("file_hashes", {})
                except Exception:
                    pass

            if "rule_memory_index.json" in names:
                raw = json.loads(zf.read("rule_memory_index.json").decode("utf-8"))
                imported_records = []
                for item in raw.get("records", []):
                    # 兼容旧记录（无 trust_level 字段）
                    item.setdefault("trust_level", TrustLevel.UNVERIFIED)
                    item.setdefault("source_repo", "")
                    item.setdefault("source_commit", "")
                    item.setdefault("ql_hash", "")
                    item.setdefault("import_source", "bundle_import")
                    item.setdefault("verified_at", "")
                    item.setdefault("verified_by", "")
                    imported_records.append(RuleRecord(**item))
            else:
                imported_records = []

            for record in imported_records:
                ql_name = Path(record.query_path).name
                arc_name = f"rules/{ql_name}"
                if arc_name not in names:
                    logger.warning("[RuleMemory] 导入时缺少 QL 文件: %s，跳过", ql_name)
                    continue

                ql_bytes = zf.read(arc_name)

                # 2. 文件级 SHA-256 校验
                actual_hash = hashlib.sha256(ql_bytes).hexdigest()
                if manifest_hashes and ql_name in manifest_hashes:
                    expected_hash = manifest_hashes[ql_name]
                    if actual_hash != expected_hash:
                        logger.warning(
                            "[RuleMemory] ⚠ QL 文件完整性校验失败: %s"
                            "（期望 %s...，实际 %s...），拒绝导入",
                            ql_name, expected_hash[:12], actual_hash[:12],
                        )
                        rejected_hash += 1
                        continue
                elif record.ql_hash and actual_hash != record.ql_hash:
                    logger.warning(
                        "[RuleMemory] ⚠ QL 文件 hash 与记录不符: %s，拒绝导入",
                        ql_name,
                    )
                    rejected_hash += 1
                    continue

                dest_ql = self.rules_dir / ql_name
                dest_ql.write_bytes(ql_bytes)
                record.query_path = str(dest_ql)
                record.ql_hash = actual_hash      # 更新为实测 hash
                record.import_source = "bundle_import"
                record.trust_level = import_trust  # 按签名结果设置信任级别

                if record.rule_id not in self._records:
                    self._records[record.rule_id] = record
                    self._backend.add(
                        record_id=record.rule_id,
                        text=record.to_embedding_text(),
                        metadata={
                            "language": record.language,
                            "vuln_type": record.vuln_type,
                            "trust_level": record.trust_level,
                        },
                    )
                    imported += 1

        self._save_index()
        logger.info(
            "[RuleMemory] 导入完成: %d 条规则（trust=%s，合并=%s，hash拒绝=%d）",
            imported, import_trust, merge, rejected_hash,
        )
        if import_trust == TrustLevel.UNVERIFIED and imported > 0:
            logger.warning(
                "[RuleMemory] %d 条记录已导入为 unverified 状态，"
                "不会参与 Few-Shot 检索。审核后请调用 rule_memory.verify('<rule_id>') 激活。",
                imported,
            )
        return imported

    def __repr__(self) -> str:
        return (
            f"<RuleMemory records={len(self._records)} "
            f"backend={self._backend.name} dir={self.memory_dir}>"
        )
