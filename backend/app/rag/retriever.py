"""
RAG Retriever Module v3.2 - Gracefully Degraded Vector Search
"""

import os
import pickle
import time
import logging
from typing import List, Dict, Any

log = logging.getLogger(__name__)

# Optional RAG imports (faiss, sentence_transformers)
_HAS_FAISS = False
_HAS_ST = False

try:
    import faiss
    import numpy as np
    _HAS_FAISS = True
except ImportError:
    log.info("[RAG Retriever Note] faiss library not installed. Vector search disabled.")

try:
    from sentence_transformers import SentenceTransformer
    _HAS_ST = True
except ImportError:
    log.info("[RAG Retriever Note] sentence_transformers library not installed. Vector search disabled.")

STORE_PATH = os.path.join(os.path.dirname(__file__), "vector_store")
_model = None
_index = None
_chunks = None

JUNK_FILES = [".github", "contributing", "changelog", "issue_template", "pull_request", "conventions", "license.md", "readme.md", "xamarin", "mach-o", "wasm-", "universal-binaries", "pre-training", "android", "nfc", "hce"]


def get_retriever():
    global _model, _index, _chunks
    if not _HAS_FAISS or not _HAS_ST:
        return None, None, None

    if _model is None:
        try:
            start = time.time()
            faiss_file = os.path.join(STORE_PATH, "hacktricks.faiss")
            chunks_file = os.path.join(STORE_PATH, "chunks.pkl")

            if not os.path.exists(faiss_file) or not os.path.exists(chunks_file):
                log.info("[RAG Retriever Note] Vector index files not found. Vector search disabled.")
                return None, None, None

            log.info("[RAG] Loading FAISS index...")
            _model = SentenceTransformer("all-MiniLM-L6-v2")
            _index = faiss.read_index(faiss_file)
            with open(chunks_file, "rb") as f:
                _chunks = pickle.load(f)
            log.info(f"[RAG] Loaded {len(_chunks)} chunks in {time.time()-start:.1f}s")
        except Exception as e:
            log.warning(f"[RAG Load Exception]: {e}")
            _model, _index, _chunks = None, None, None

    return _model, _index, _chunks


def search(query: str, k: int = 5) -> List[Dict[str, Any]]:
    """
    Safely searches vector store. Returns empty list if faiss/index is unavailable.
    Never raises exceptions.
    """
    if not query or not query.strip():
        return []

    model, index, chunks = get_retriever()
    if model is None or index is None or not chunks:
        return []

    try:
        q_lower = query.lower()
        q_emb = model.encode([query])
        D, I = index.search(np.array(q_emb).astype("float32"), min(30, len(chunks)))

        scored = []
        for dist, idx in zip(D[0], I[0]):
            if not (0 <= idx < len(chunks)):
                continue
            chunk = chunks[idx]
            text_low = chunk.get("text", "").lower()
            source_low = chunk.get("source", "").lower()

            if any(j in source_low for j in JUNK_FILES):
                continue
            if "subdomain" in source_low and "mitm" in q_lower:
                continue
            if "malware" in source_low and "mitm" in q_lower:
                continue

            score = float(dist)
            if any(term in text_low for term in ["mitm", "phish", "aitm", "evilginx", "spoof"]):
                score -= 0.15  # Boost security relevant chunks

            scored.append((score, chunk))

        scored.sort(key=lambda x: x[0])
        return [c for _, c in scored[:k]]
    except Exception as e:
        log.warning(f"[RAG Search Error]: {e}")
        return []
