"use client";
import React, { useEffect, useState } from 'react';

type SearchResult = { source: string; content: string; score?: number };

export default function KnowledgePage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [searchDone, setSearchDone] = useState(false);
  const [memoryStats, setMemoryStats] = useState<any>(null);
  const [recentTopics, setRecentTopics] = useState<string[]>([]);

  useEffect(() => {
    // Load memory stats and recent research topics from real API
    fetch('/api/backend?path=memory')
      .then(r => r.json())
      .then(data => setMemoryStats(data.record_counts))
      .catch(() => {});

    // Use knowledge endpoint
    fetch('/api/backend?path=knowledge')
      .then(r => r.json())
      .catch(() => {});
  }, []);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!query.trim()) return;

    setIsSearching(true);
    setSearchDone(false);
    setResults([]);

    try {
      // Ask SecurityKnowledgeAgent via chat API
      const res = await fetch('/api/backend?path=agents/SecurityKnowledgeAgent/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: `Search knowledge base and explain: ${query}` })
      });
      const data = await res.json();
      if (data.response) {
        setResults([{ source: 'SecurityKnowledgeAgent', content: data.response }]);
      }
    } catch (err) {
      setResults([{ source: 'Error', content: 'Failed to reach backend. Is the server running?' }]);
    } finally {
      setIsSearching(false);
      setSearchDone(true);
    }
  };

  const QUICK_TOPICS = [
    'OWASP Top 10', 'SQL Injection', 'XSS Prevention', 'IDOR vulnerability',
    'SSRF exploitation', 'JWT security', 'CSRF bypass', 'Path traversal',
    'Subdomain takeover', 'Open redirect'
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center border-b border-gray-800 pb-4">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">📚 Knowledge Base</h2>
          <p className="text-gray-400 text-sm mt-1">Powered by SecurityKnowledgeAgent — OWASP, CVE research, secure coding</p>
        </div>
      </div>

      {/* Memory Stats */}
      {memoryStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Research Memory', value: memoryStats.research_memory || 0 },
            { label: 'Key Findings', value: memoryStats.key_findings || 0 },
            { label: 'Session Logs', value: memoryStats.session_logs || 0 },
            { label: 'User Notes', value: memoryStats.user_notes || 0 },
          ].map(({ label, value }) => (
            <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-gray-400 text-xs">{label}</div>
              <div className="text-2xl font-bold text-white mt-1">{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Search */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4 text-white">🔍 Ask the Knowledge Agent</h3>
        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="e.g. How to exploit IDOR? What is SSRF? OWASP Top 10 explained..."
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 placeholder-gray-500"
          />
          <button
            type="submit"
            disabled={isSearching || !query.trim()}
            className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 text-white rounded-lg font-medium transition-colors"
          >
            {isSearching ? '⟳ Searching...' : 'Search'}
          </button>
        </form>

        {/* Quick Topics */}
        <div className="mt-4">
          <p className="text-xs text-gray-500 mb-2">Quick topics:</p>
          <div className="flex flex-wrap gap-2">
            {QUICK_TOPICS.map(topic => (
              <button
                key={topic}
                onClick={() => { setQuery(topic); }}
                className="px-3 py-1 text-xs bg-gray-800 hover:bg-indigo-600/20 border border-gray-700 hover:border-indigo-500 text-gray-400 hover:text-indigo-300 rounded-full transition-colors"
              >
                {topic}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Results */}
      {isSearching && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
          <div className="text-gray-400 animate-pulse">SecurityKnowledgeAgent is researching... this may take 15-30 seconds</div>
        </div>
      )}

      {searchDone && results.map((r, i) => (
        <div key={i} className="bg-gray-900 border border-indigo-500/30 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4 pb-3 border-b border-gray-800">
            <span className="text-xs px-2 py-0.5 bg-indigo-500/10 text-indigo-400 rounded-full border border-indigo-500/30">
              {r.source}
            </span>
            <span className="text-xs text-gray-500">Response for: "{query}"</span>
          </div>
          <pre className="whitespace-pre-wrap text-gray-200 text-sm leading-relaxed font-sans">{r.content}</pre>
        </div>
      ))}

      {searchDone && results.length === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center text-gray-500">
          No results found. Try a different query.
        </div>
      )}

      {/* Info Box */}
      <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-5">
        <h4 className="text-blue-300 font-semibold mb-2">💡 PKCERT Bug Bounty Guidance</h4>
        <p className="text-gray-400 text-sm leading-relaxed">
          This knowledge base is powered by SecurityKnowledgeAgent trained on OWASP, NIST, and CVE data.
          Ask about vulnerability types, exploitation techniques, CVSS scoring, or mitigation strategies
          before reporting to PKCERT. Always follow responsible disclosure guidelines.
        </p>
      </div>
    </div>
  );
}
