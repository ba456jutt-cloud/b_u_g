"""
Security RAG Knowledge Tool
===========================
Queries ChromaDB vector store seeded with HackTricks, PayloadsAllTheThings,
and CTF security cheatsheets.
"""
import os
from tools.base import Tool

class SecurityRAGTool(Tool):
    name = "security_rag"
    description = (
        "Queries the HackTricks & Security Knowledge Base vector database for WAF bypasses, "
        "SQLi/XSS/SSRF/JWT payloads, CTF trick sheets, and exploitation methodology."
    )
    parameters = {
        "query": "The vulnerability or technique to search (e.g. 'SQLi WAF bypass', 'SSRF AWS metadata', 'JWT none alg', 'CTF xor decode')"
    }

    def __init__(self):
        self._retrieval_tool = None

    def _get_tool(self):
        if self._retrieval_tool is None:
            try:
                from knowledge.retrieval import RAGSearchTool
                self._retrieval_tool = RAGSearchTool()
            except Exception as e:
                self._retrieval_tool = None
        return self._retrieval_tool

    def execute(self, query: str = "", **kwargs) -> str:
        query = str(query).strip()
        if not query:
            return "Error: No search query provided."

        tool = self._get_tool()
        if tool:
            res = tool.execute(query=query)
            if "Retrieved Context:" in res or len(res) > 50:
                return res

        # Fallback to local security cheat sheet search if ChromaDB is not initialized
        from knowledge.security_docs import SECURITY_KNOWLEDGE_DOCS
        matched = []
        for doc in SECURITY_KNOWLEDGE_DOCS:
            if any(q.lower() in doc["content"].lower() or q.lower() in doc["title"].lower() for q in query.split()):
                matched.append(f"=== {doc['title']} ===\n{doc['content']}")

        if matched:
            return "Retrieved Knowledge Base Context:\n" + "\n\n".join(matched[:2])

        return f"No specific security cheat sheet found for query: '{query}'."
