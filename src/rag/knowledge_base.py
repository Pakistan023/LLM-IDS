"""
Lightweight RAG (Retrieval-Augmented Generation) knowledge base.

Rather than requiring an external vector database, this uses TF-IDF +
cosine similarity over a small corpus of markdown threat-intel documents
(src/rag/threat_docs/*.md). This keeps the bonus "RAG-based threat
knowledge base" feature dependency-free and fully offline-capable, while
still giving the LLM analyzer grounded, retrieved context instead of
relying purely on its own training knowledge.

Swap `TfidfVectorizer` for a real embedding model + vector DB (e.g.
sentence-transformers + Chroma/FAISS) for production use — the interface
(`retrieve(query, top_k)`) stays the same.
"""

import glob
import os
from dataclasses import dataclass
from typing import List

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from src.utils.config_loader import load_config
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class RetrievedDoc:
    source: str
    content: str
    score: float


class ThreatKnowledgeBase:
    def __init__(self, knowledge_dir: str = None):
        cfg = load_config()
        self.knowledge_dir = knowledge_dir or cfg["_abs"](cfg["rag"]["knowledge_dir"])
        self.top_k_default = cfg["rag"]["top_k"]

        self.doc_paths: List[str] = sorted(glob.glob(os.path.join(self.knowledge_dir, "*.md")))
        self.docs: List[str] = []
        for path in self.doc_paths:
            with open(path, "r") as f:
                self.docs.append(f.read())

        if not self.docs:
            log.warning(f"No threat-intel docs found in {self.knowledge_dir}")
            self.vectorizer = None
            self.doc_matrix = None
        else:
            self.vectorizer = TfidfVectorizer(stop_words="english")
            self.doc_matrix = self.vectorizer.fit_transform(self.docs)
            log.info(f"RAG knowledge base loaded: {len(self.docs)} documents from {self.knowledge_dir}")

    def retrieve(self, query: str, top_k: int = None) -> List[RetrievedDoc]:
        if not self.docs or self.vectorizer is None:
            return []
        top_k = top_k or self.top_k_default

        query_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(query_vec, self.doc_matrix).flatten()
        ranked_idx = sims.argsort()[::-1][:top_k]

        results = []
        for idx in ranked_idx:
            if sims[idx] <= 0:
                continue
            results.append(RetrievedDoc(
                source=os.path.basename(self.doc_paths[idx]),
                content=self.docs[idx],
                score=float(sims[idx]),
            ))
        return results

    def build_context_block(self, query: str, top_k: int = None) -> str:
        """Formats retrieved docs into a context block ready to inject into an LLM prompt."""
        results = self.retrieve(query, top_k)
        if not results:
            return "No matching threat-intel documents were retrieved."
        blocks = [f"[Source: {r.source} | relevance={r.score:.2f}]\n{r.content}" for r in results]
        return "\n\n---\n\n".join(blocks)
