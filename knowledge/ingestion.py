import os
import pypdf
import json
from config.settings import settings

class RAGIngestion:
    def __init__(self):
        self.chroma_client = None
        self.collection = None
        self.model = None

        try:
            import chromadb
            from sentence_transformers import SentenceTransformer
            self.chroma_client = chromadb.PersistentClient(path=os.path.join(settings.BASE_DIR, "memory", "chroma_db"))
            self.collection = self.chroma_client.get_or_create_collection(name="knowledge_base")
            self.model = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception as e:
            print(f"[*] RAG Vector Store fallback mode (sentence-transformers/chroma optional): {e}")

    def ingest_text(self, text: str, doc_id: str, metadata: dict = None):
        if not metadata:
            metadata = {}

        chunks = [text[i:i+500] for i in range(0, len(text), 500)]

        if self.collection and self.model:
            for idx, chunk in enumerate(chunks):
                chunk_id = f"{doc_id}_chunk_{idx}"
                embedding = self.model.encode(chunk).tolist()
                self.collection.add(
                    embeddings=[embedding],
                    documents=[chunk],
                    metadatas=[metadata],
                    ids=[chunk_id]
                )
            print(f"[*] Ingested document {doc_id} into Chroma vector DB ({len(chunks)} chunks).")
        else:
            # Fallback file-based knowledge storage
            fallback_dir = os.path.join(settings.BASE_DIR, "memory", "knowledge_fallback")
            os.makedirs(fallback_dir, exist_ok=True)
            with open(os.path.join(fallback_dir, f"{doc_id}.txt"), "w") as f:
                f.write(text)
            print(f"[*] Saved document {doc_id} into fallback knowledge store.")

    def ingest_pdf(self, file_path: str):
        try:
            reader = pypdf.PdfReader(file_path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
            self.ingest_text(text, os.path.basename(file_path), {"type": "pdf"})
        except Exception as e:
            print(f"[-] Failed to parse PDF: {e}")
