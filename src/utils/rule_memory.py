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

向量后端优先级（自动选择最优可用后端）：
  1. ChromaDB        — 本地持久向量数据库（最优，支持语义+元数据过滤）
  2. FAISS           — 高性能向量索引（大规模场景）
  3. sentence-transformers + numpy  — 轻量嵌入（中等）
  4. TF-IDF          — 纯 sklearn（最轻量）
  5. Jaccard         — 零依赖回退
"""

from __future__ import annotations

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

_INDEX_FILENAME    = "rule_memory_index.json"
_EMBEDDING_FILENAME = "embeddings.npz"
_CHROMA_DIR        = "chroma_db"
_EMBED_MODEL       = "all-MiniLM-L6-v2"

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class RuleRecord:
    """
    单条成功规则的完整上下文记录。

    新增字段（漏洞链路上下文，用于语义 RAG 检索）：
        sink_method:        危险 Sink 方法全名（如 ognl.Ognl.getValue）
        data_flow_summary:  Source → Sink 数据流路径的自然语言摘要
        sarif_message:      CodeQL 原始发现消息
        code_snippet:       漏洞所在代码片段（20行以内）
        cwe:                CWE 编号（如 CWE-094）
        detected_frameworks: 检测到的项目框架列表
    """

    rule_id:             str
    language:            str
    vuln_type:           str
    query_path:          str
    created_at:          str        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags:                list[str]  = field(default_factory=list)

    # ── 漏洞链路上下文（RAG 核心） ────────────────────────────────────────
    sink_method:         str        = ""
    data_flow_summary:   str        = ""   # "HTTP param 'filter' → Ognl.getValue() at APIKafka.java:53"
    sarif_message:       str        = ""
    code_snippet:        str        = ""   # 漏洞代码片段（最多 20 行）
    cwe:                 str        = ""
    detected_frameworks: list[str]  = field(default_factory=list)

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
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction  # type: ignore

        persist_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(persist_dir))
        ef = SentenceTransformerEmbeddingFunction(model_name=_EMBED_MODEL)
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
    ) -> None:
        self.memory_dir = Path(memory_dir)
        self.rules_dir  = self.memory_dir / "rules"
        self.index_path = self.memory_dir / _INDEX_FILENAME
        self._records: dict[str, RuleRecord] = {}   # rule_id → record
        self._backend: _VectorBackend = _build_backend(self.memory_dir, backend)
        self._load_index()
        # 将已有记录重新加载到后端（保持后端与索引同步）
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
    ) -> RuleRecord:
        """
        将一条编译成功的规则及其漏洞链路上下文写入记忆库。

        Args:
            language:           目标语言。
            vuln_type:          漏洞类型描述。
            query_path:         原始 .ql 文件路径。
            tags:               额外标签列表。
            sink_method:        触发漏洞的 Sink 方法（用于语义检索）。
            data_flow_summary:  Source→Sink 数据流路径摘要（自然语言）。
            sarif_message:      CodeQL 发现消息。
            code_snippet:       漏洞代码片段（≤20行）。
            cwe:                CWE 编号。
            detected_frameworks: 项目使用的框架列表。

        Returns:
            写入的 RuleRecord。
        """
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        src = Path(query_path)
        if not src.exists():
            raise FileNotFoundError(f"规则文件不存在: {query_path}")

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
            code_snippet=code_snippet[:1500],   # 最多 1500 字符
            cwe=cwe,
            detected_frameworks=detected_frameworks or [],
        )

        self._records[record.rule_id] = record
        self._save_index()

        # 将富文本嵌入向量后端
        self._backend.add(
            record_id=record.rule_id,
            text=record.to_embedding_text(),
            metadata={"language": lang_safe, "vuln_type": vuln_type},
        )

        logger.info(
            "[RuleMemory] 规则已归档 | %s | %s | sink=%s | 后端=%s",
            lang_safe, vuln_type, sink_method or "N/A", self._backend.name,
        )
        return record

    # ------------------------------------------------------------------
    # 语义检索
    # ------------------------------------------------------------------

    def search(
        self,
        language: str,
        vuln_type: str,
        sink_hint:    str = "",
        top_k:        int = 3,
    ) -> list[tuple[RuleRecord, float]]:
        """
        语义检索最相似的历史规则（利用链路级别的向量匹配）。

        Args:
            language:  目标语言，用于 metadata 过滤。
            vuln_type: 漏洞类型，作为查询核心语义。
            sink_hint: 可选的 Sink 方法提示，加入查询文本提升精度。
            top_k:     最多返回 k 条。

        Returns:
            (RuleRecord, similarity_score) 列表，按相似度降序。
        """
        if not self._records:
            return []

        # 构造查询文本（包含语言、漏洞类型、Sink 提示）
        query_parts = [f"Language: {language}", f"Vulnerability: {vuln_type}"]
        if sink_hint:
            query_parts.append(f"Sink: {sink_hint}")
        query_text = "\n".join(query_parts)

        # ChromaDB 支持 where 过滤，其他后端在结果层面过滤语言
        where = {"language": language.lower()} if self._backend.name == "chromadb" else None
        raw = self._backend.query(query_text, n_results=top_k * 3, where=where)

        results = []
        for rid, score in raw:
            if rid not in self._records:
                continue
            record = self._records[rid]
            # 非 ChromaDB 后端在此过滤语言
            if language and record.language != language.lower():
                continue
            results.append((record, score))

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
    # 导出 / 导入（跨机器共享规则）
    # ------------------------------------------------------------------

    def export_bundle(self, output_path: str) -> str:
        """
        将整个规则记忆库打包为一个自包含的 ZIP 文件。

        Bundle 结构：
          rule_memory_index.json  — 元数据索引
          rules/                  — 所有 .ql 文件

        Args:
            output_path: 输出 ZIP 文件路径（如 "data/memory_bundle.zip"）。

        Returns:
            实际写入的 ZIP 文件路径。
        """
        import zipfile

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if self.index_path.exists():
                zf.write(self.index_path, arcname="rule_memory_index.json")

            if self.rules_dir.exists():
                for ql_file in self.rules_dir.glob("*.ql"):
                    zf.write(ql_file, arcname=f"rules/{ql_file.name}")

        logger.info(
            "[RuleMemory] 导出完成: %s (共 %d 条规则)",
            out, self.count(),
        )
        return str(out)

    def import_bundle(self, bundle_path: str, merge: bool = True) -> int:
        """
        从 ZIP Bundle 导入规则记忆库。

        Args:
            bundle_path: ZIP 文件路径（由 export_bundle 生成）。
            merge:       True 表示合并到现有库；False 表示先清空再导入。

        Returns:
            成功导入的规则条数。
        """
        import zipfile

        bundle = Path(bundle_path)
        if not bundle.exists():
            raise FileNotFoundError(f"Bundle 文件不存在: {bundle_path}")

        if not merge:
            # 清空现有库
            if self.memory_dir.exists():
                import shutil as _shutil
                _shutil.rmtree(self.memory_dir)
            self._records = {}

        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)

        imported = 0
        with zipfile.ZipFile(bundle, "r") as zf:
            names = zf.namelist()

            # 读取导入的索引
            if "rule_memory_index.json" in names:
                raw = json.loads(zf.read("rule_memory_index.json").decode("utf-8"))
                imported_records = [RuleRecord(**item) for item in raw.get("records", [])]
            else:
                imported_records = []

            for record in imported_records:
                ql_name = Path(record.query_path).name
                arc_name = f"rules/{ql_name}"
                if arc_name not in names:
                    logger.warning("[RuleMemory] 导入时缺少 QL 文件: %s，跳过", ql_name)
                    continue

                dest_ql = self.rules_dir / ql_name
                dest_ql.write_bytes(zf.read(arc_name))

                # 更新记录中的路径为本地绝对路径
                record.query_path = str(dest_ql)

                if record.rule_id not in self._records:
                    self._records[record.rule_id] = record
                    self._backend.add(
                        record_id=record.rule_id,
                        text=record.to_embedding_text(),
                        metadata={"language": record.language, "vuln_type": record.vuln_type},
                    )
                    imported += 1

        self._save_index()
        logger.info("[RuleMemory] 导入完成: %d 条规则（合并模式=%s）", imported, merge)
        return imported

    def __repr__(self) -> str:
        return (
            f"<RuleMemory records={len(self._records)} "
            f"backend={self._backend.name} dir={self.memory_dir}>"
        )
