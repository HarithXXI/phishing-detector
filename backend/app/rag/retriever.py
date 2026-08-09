import faiss, pickle, os, time
import numpy as np
from sentence_transformers import SentenceTransformer

STORE_PATH = "app/rag/vector_store"
_model = None
_index = None
_chunks = None

PHISHING_KEYWORDS = ["phish", "mitm", "aitm", "evilginx", "d3fend", "phishing", "spoof", "session", "cookie", "ssl", "tls", "https", "dns", "interception"]

JUNK_FILES = [".github", "contributing", "changelog", "issue_template", "pull_request", "conventions", "license.md", "readme.md", "xamarin", "mach-o", "wasm-", "universal-binaries", "pre-training", "android", "nfc", "hce"]

def get_retriever():
    global _model, _index, _chunks
    if _model is None:
        start = time.time()
        print("[RAG] Loading FAISS index...")
        _model = SentenceTransformer("all-MiniLM-L6-v2")
        _index = faiss.read_index(f"{STORE_PATH}/hacktricks.faiss")
        with open(f"{STORE_PATH}/chunks.pkl", "rb") as f:
            _chunks = pickle.load(f)
        print(f"[RAG] Loaded {len(_chunks)} chunks in {time.time()-start:.1f}s")
    return _model, _index, _chunks

def search(query, k=5):
    model, index, chunks = get_retriever()
    q_lower = query.lower()
    
    q_emb = model.encode([query])
    D, I = index.search(np.array(q_emb).astype('float32'), 30)  # get 30 then filter
    
    scored = []
    for dist, idx in zip(D[0], I[0]):
        if not (0 <= idx < len(chunks)):
            continue
        chunk = chunks[idx]
        text_low = chunk["text"].lower()
        source_low = chunk["source"].lower()
        
        # Hard filter junk
        if any(j in source_low for j in JUNK_FILES):
            continue
        if "subdomain" in source_low and "mitm" in q_lower: 
            continue
        if "malware" in source_low and "mitm" in q_lower:
            continue
        
        # For MITM/phishing queries, require some relevance
        if any(k in q_lower for k in ["mitm", "phish", "aitm"]):
            # Must contain at least one relevant keyword or be from relevant folder
            is_relevant = (
                any(kw in text_low for kw in PHISHING_KEYWORDS) or
                "phishing" in source_low or
                "spoofing" in source_low or
                "mitm" in source_low or
                "d3fend" in source_low or
                chunk.get("repo") == "d3fend"
            )
            if not is_relevant:
                continue

        score = float(dist)
        
        # Boosts for MITM
        if "mitm" in q_lower:
            if "man-in-the-middle" in text_low or "man in the middle" in text_low: score -= 0.5
            if "mitm" in text_low: score -= 0.4
            if "interception" in text_low: score -= 0.2
            if "phishing" in source_low: score -= 0.2
        
        if "phishing" in text_low: score -= 0.15
        if "aitm" in q_lower and "aitm" in text_low: score -= 0.4
        if "d3fend" in q_lower and chunk.get("repo") == "d3fend": score -= 0.3

        scored.append((score, chunk))

    scored.sort(key=lambda x: x[0])
    results = [c for _, c in scored[:k]]
    
    print(f"[RAG] query='{query}' -> {[r['source'].split('/')[-1] for r in results]}")
    
    return results
