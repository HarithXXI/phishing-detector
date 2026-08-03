"""
RAG Ingestion Pipeline
Embeds markdown files from HackTricks, OWASP CheatSheets, and MITRE D3FEND into FAISS.
Caps HackTricks at 3000 most-informative chunks for practical CPU ingestion time (~3-5 min).
"""

import pickle
import random
from pathlib import Path
import numpy as np

# pyrefly: ignore [missing-import]
import faiss
# pyrefly: ignore [missing-import]
from sentence_transformers import SentenceTransformer
# pyrefly: ignore [missing-import]
from langchain_text_splitters import RecursiveCharacterTextSplitter

# Path configuration
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
RAG_DIR = Path(__file__).resolve().parent
VECTOR_STORE_DIR = RAG_DIR / "vector_store"
INDEX_PATH = VECTOR_STORE_DIR / "hacktricks.faiss"
CHUNKS_PATH = VECTOR_STORE_DIR / "chunks.pkl"

# Repos config: (rel_path, max_chunks or None for all)
REPOS = [
    ("data/hacktricks",   3000),   # Cap to 3000 best chunks
    ("data/cheatsheets",  None),   # Keep all
    ("data/d3fend",       None),   # Keep all
]
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"


def should_skip(rel_path: str) -> bool:
    """Return True for meta/boilerplate files that pollute RAG results."""
    low = rel_path.lower()
    # Skip anything inside .github (issue templates, workflows, etc.)
    if ".github" in low:
        return True
    # Skip contribution / changelog / conduct meta files
    if "contributing" in low or "changelog" in low:
        return True
    if "code_of_conduct" in low or "issue_template" in low:
        return True
    if "pull_request_template" in low:
        return True
    # Skip SUMMARY.md (GitBook nav file)
    if "summary.md" in low:
        return True
    # Skip root-level README.md (depth <= 2 parts after repo root)
    # e.g. data/hacktricks/README.md  -> parts count = 3  -> skip
    # but  data/hacktricks/network/README.md -> parts = 4 -> keep
    if low.endswith("readme.md") and rel_path.count("/") <= 2:
        return True
    return False

random.seed(42)


def run_ingestion():
    print("[*] Starting RAG ingestion pipeline...")
    VECTOR_STORE_DIR.mkdir(parents=True, exist_ok=True)

    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    chunks_data = []

    for repo_rel, max_chunks in REPOS:
        repo_path = BACKEND_DIR / repo_rel
        if not repo_path.exists():
            print(f"[!] Repo directory not found: {repo_path}")
            continue

        repo_name = Path(repo_rel).name
        repo_type = "offensive" if "hacktricks" in repo_name else "defensive"
        md_files = list(repo_path.glob("**/*.md"))
        print(f"[*] Scanning {repo_name} ({len(md_files)} .md files)...")

        repo_chunks = []
        for filepath in md_files:
            try:
                rel_path = filepath.relative_to(BACKEND_DIR).as_posix()

                # Skip boilerplate / meta files
                if should_skip(rel_path):
                    continue

                text = filepath.read_text(encoding="utf-8", errors="ignore").strip()

                if len(text) < 300:
                    continue

                split_chunks = splitter.split_text(text)
                for chunk_text in split_chunks:
                    repo_chunks.append({
                        "text": chunk_text,
                        "source": rel_path,
                        "repo": repo_name,
                        "type": repo_type,
                    })
            except Exception:
                continue

        # Cap if needed
        if max_chunks and len(repo_chunks) > max_chunks:
            # Sort by text length descending (longer = more content-rich) then cap
            repo_chunks.sort(key=lambda c: len(c["text"]), reverse=True)
            repo_chunks = repo_chunks[:max_chunks]
            print(f"[*] Capped {repo_name} to {max_chunks} most content-rich chunks")
        else:
            print(f"[*] Using all {len(repo_chunks)} chunks from {repo_name}")

        chunks_data.extend(repo_chunks)

    total_chunks = len(chunks_data)
    print(f"[*] Total chunks to embed: {total_chunks}")

    if total_chunks == 0:
        print("[!] No chunks generated. Aborting.")
        return

    # Compute Embeddings
    print(f"[*] Loading model {EMBEDDING_MODEL_NAME}...")
    model = SentenceTransformer(EMBEDDING_MODEL_NAME)

    texts = [c["text"] for c in chunks_data]
    print(f"[*] Encoding {total_chunks} chunks (batch_size=32, ~3-5 min on CPU)...")
    embeddings = model.encode(
        texts,
        batch_size=32,
        show_progress_bar=True,
        normalize_embeddings=True
    )
    embeddings = np.array(embeddings, dtype=np.float32)

    dimension = embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)
    index.add(embeddings)

    # Save FAISS index and chunks.pkl
    faiss.write_index(index, str(INDEX_PATH))
    with open(CHUNKS_PATH, "wb") as f:
        pickle.dump(chunks_data, f)

    print(f"[OK] RAG Ingestion Complete!")
    print(f"[OK] FAISS Index: {INDEX_PATH}")
    print(f"[OK] Chunks PKL:  {CHUNKS_PATH}")
    print(f"[OK] Total indexed: {total_chunks} chunks")


if __name__ == "__main__":
    run_ingestion()
