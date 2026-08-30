import os
import chromadb
from sentence_transformers import SentenceTransformer
import pypdf
from config.settings import settings

class RAGIngestion:
    def __init__(self):
        self.chroma_client = chromadb.PersistentClient(path=os.path.join(settings.BASE_DIR, "memory", "chroma_db"))
        self.collection = self.chroma_client.get_or_create_collection(name="knowledge_base")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')

    def ingest_text(self, text: str, doc_id: str, metadata: dict = None):
        if not metadata:
            metadata = {}
        
        # Simple chunking logic
        chunks = [text[i:i+500] for i in range(0, len(text), 500)]
        
        for idx, chunk in enumerate(chunks):
            chunk_id = f"{doc_id}_chunk_{idx}"
            embedding = self.model.encode(chunk).tolist()
            self.collection.add(
                embeddings=[embedding],
                documents=[chunk],
                metadatas=[metadata],
                ids=[chunk_id]
            )
        print(f"[*] Ingested document {doc_id} into vector DB.")

    def ingest_pdf(self, file_path: str):
        try:
            reader = pypdf.PdfReader(file_path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
            self.ingest_text(text, os.path.basename(file_path), {"type": "pdf"})
        except Exception as e:
            print(f"[-] Failed to parse PDF: {e}")
