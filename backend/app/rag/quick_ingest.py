"""
Quick Initial RAG Ingestion
Indexes core HackTricks & OWASP CheatSheetSeries markdown files into vector_store/hacktricks.faiss.
"""

import pickle
from pathlib import Path
import numpy as np

# pyrefly: ignore [missing-import]
import faiss
# pyrefly: ignore [missing-import]
from sentence_transformers import SentenceTransformer
# pyrefly: ignore [missing-import]
from langchain_text_splitters import RecursiveCharacterTextSplitter

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
HACKTRICKS_DIR = DATA_DIR / "hacktricks"
CHEATSHEETS_DIR = DATA_DIR / "cheatsheets"
D3FEND_DIR = DATA_DIR / "d3fend"
RAG_DIR = Path(__file__).resolve().parent
VECTOR_STORE_DIR = RAG_DIR / "vector_store"
INDEX_PATH = VECTOR_STORE_DIR / "hacktricks.faiss"
CHUNKS_PATH = VECTOR_STORE_DIR / "chunks.pkl"


def run_quick_ingest():
    if not DATA_DIR.exists():
        print(f"[!] {DATA_DIR} does not exist.")
        return

    VECTOR_STORE_DIR.mkdir(parents=True, exist_ok=True)
    all_mds = list(DATA_DIR.glob("**/*.md"))

    print(f"[*] Found total {len(all_mds)} markdown files across HackTricks, OWASP, & MITRE D3FEND repositories.")

    # Sample top 250 files for fast initialization
    sample_mds = all_mds[:250]
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)

    documents = []
    for filepath in sample_mds:
        try:
            rel_path = filepath.relative_to(DATA_DIR).as_posix()
            text = filepath.read_text(encoding="utf-8", errors="ignore").strip()
            if not text or len(text) < 30:
                continue

            chunks = splitter.split_text(text)
            for i, chunk in enumerate(chunks):
                documents.append({
                    "id": f"{rel_path}#{i}",
                    "text": chunk,
                    "source": rel_path,
                    "title": filepath.name,
                })
        except Exception:
            continue

    print(f"[*] Quick Ingest: Generated {len(documents)} text chunks.")
    if not documents:
        return

    model = SentenceTransformer("all-MiniLM-L6-v2")
    texts = [doc["text"] for doc in documents]
    embeddings = model.encode(texts, batch_size=64, show_progress_bar=False, normalize_embeddings=True)
    embeddings = np.array(embeddings, dtype=np.float32)

    dimension = embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)
    index.add(embeddings)

    faiss.write_index(index, str(INDEX_PATH))
    with open(CHUNKS_PATH, "wb") as f:
        pickle.dump(documents, f)

    print(f"[OK] Quick Ingest Complete! {len(documents)} chunks indexed in {INDEX_PATH}")


if __name__ == "__main__":
    run_quick_ingest()
