"""
Auto-Seed Script for ChromaDB Vector Store
==========================================
Populates persistent ChromaDB with HackTricks cheat sheets.
"""
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def seed_knowledge_base():
    try:
        from knowledge.ingestion import RAGIngestion
        from knowledge.security_docs import SECURITY_KNOWLEDGE_DOCS

        print("[*] Initializing RAG Ingestion Engine...")
        ingestor = RAGIngestion()

        for doc in SECURITY_KNOWLEDGE_DOCS:
            print(f"[*] Ingesting doc: {doc['id']} ({doc['title']})...")
            ingestor.ingest_text(
                text=f"{doc['title']}\n\n{doc['content']}",
                doc_id=doc['id'],
                metadata={"category": doc["category"], "source": "hacktricks"}
            )

        print("✅ HackTricks Knowledge Base successfully seeded into ChromaDB!")
        return True
    except Exception as e:
        print(f"[-] Knowledge Base Seeding Error: {e}")
        return False

if __name__ == "__main__":
    seed_knowledge_base()
