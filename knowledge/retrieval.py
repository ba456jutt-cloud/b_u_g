import os
import chromadb
from sentence_transformers import SentenceTransformer
from config.settings import settings
from tools.base import Tool

class RAGSearchTool(Tool):
    name = "rag_search"
    description = "Searches the local knowledge base for relevant context."

    def __init__(self):
        self.chroma_client = chromadb.PersistentClient(path=os.path.join(settings.BASE_DIR, "memory", "chroma_db"))
        self.collection = self.chroma_client.get_or_create_collection(name="knowledge_base")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')

    def execute(self, query: str, **kwargs) -> str:
        try:
            embedding = self.model.encode(query).tolist()
            results = self.collection.query(
                query_embeddings=[embedding],
                n_results=3
            )
            
            documents = results.get("documents", [[]])[0]
            if not documents:
                return "No relevant context found in knowledge base."
                
            return "Retrieved Context:\n" + "\n---\n".join(documents)
        except Exception as e:
            return f"Error querying vector DB: {str(e)}"
