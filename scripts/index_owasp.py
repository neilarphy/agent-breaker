"""Initialize ChromaDB with OWASP LLM Top 10 knowledge base."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import chromadb
from chromadb.utils import embedding_functions


DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "owasp", "llm_top10.json")
CHROMA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "chroma")
COLLECTION_NAME = "owasp_llm_top10"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


def chunk_entry(entry: dict) -> list[dict]:
    chunks = []

    main_text = (
        f"{entry['id']}: {entry['name']}\n"
        f"Category: {entry['category']}\n"
        f"Severity: {entry['severity']}\n\n"
        f"{entry['description']}\n\n"
        f"Vulnerable patterns: {', '.join(entry['vulnerable_patterns'])}"
    )
    chunks.append({
        "id": f"{entry['id']}_main",
        "text": main_text,
        "metadata": {
            "owasp_id": entry["id"],
            "name": entry["name"],
            "category": entry["category"],
            "severity": entry["severity"],
            "chunk_type": "description",
        },
    })

    examples_text = (
        f"{entry['id']}: {entry['name']} — Attack Examples\n\n"
        + "\n".join(f"- {ex}" for ex in entry["attack_examples"])
    )
    chunks.append({
        "id": f"{entry['id']}_examples",
        "text": examples_text,
        "metadata": {
            "owasp_id": entry["id"],
            "name": entry["name"],
            "category": entry["category"],
            "severity": entry["severity"],
            "chunk_type": "examples",
        },
    })

    mitigations_text = (
        f"{entry['id']}: {entry['name']} — Mitigations\n\n"
        + "\n".join(f"- {m}" for m in entry["mitigations"])
    )
    chunks.append({
        "id": f"{entry['id']}_mitigations",
        "text": mitigations_text,
        "metadata": {
            "owasp_id": entry["id"],
            "name": entry["name"],
            "category": entry["category"],
            "severity": entry["severity"],
            "chunk_type": "mitigations",
        },
    })

    return chunks


def main():
    print(f"Loading OWASP data from {DATA_PATH}")
    with open(DATA_PATH, "r") as f:
        entries = json.load(f)

    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )

    client = chromadb.PersistentClient(path=CHROMA_PATH)

    try:
        client.delete_collection(COLLECTION_NAME)
        print(f"Deleted existing collection '{COLLECTION_NAME}'")
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    all_chunks = []
    for entry in entries:
        all_chunks.extend(chunk_entry(entry))

    collection.add(
        ids=[c["id"] for c in all_chunks],
        documents=[c["text"] for c in all_chunks],
        metadatas=[c["metadata"] for c in all_chunks],
    )

    print(f"Indexed {len(all_chunks)} chunks from {len(entries)} OWASP entries")
    print(f"ChromaDB stored at: {os.path.abspath(CHROMA_PATH)}")


if __name__ == "__main__":
    main()
