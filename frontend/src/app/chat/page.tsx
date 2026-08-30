"use client";
import React, { useEffect, useRef, useState } from 'react';

type Message = { role: 'user' | 'agent'; content: string; agent?: string; time: string };

const AGENT_OPTIONS = [
  { value: 'MasterAgent',               label: '🧠 Master Orchestrator',       desc: 'Full pipeline: Recon → CVE → Chain → Report' },
  { value: 'ReconAnalysisAgent',        label: '🔍 Recon Agent',                desc: 'Adaptive: Nmap, web audit, OSINT, fuzzing' },
  { value: 'AttackChainAgent',          label: '⛓️ Attack Chain Analyst',       desc: 'Chain low vulns → critical impact + PoC' },
  { value: 'CVEResearchAgent',          label: '🐛 CVE Research Agent',         desc: 'NIST NVD lookup, CVSS scores' },
  { value: 'VulnerabilityAnalysisAgent',label: '⚠️ Vulnerability Analyst',     desc: 'CVSS scoring, attack vector analysis' },
  { value: 'ReportAgent',               label: '📄 Report Generator',           desc: 'Professional security reports' },
  { value: 'CodeReviewAgent',           label: '💻 Code Review Agent',          desc: 'SAST, injection flaws, logic bugs' },
  { value: 'SecurityKnowledgeAgent',    label: '📚 Security Knowledge',         desc: 'OWASP, mitigations, best practices' },
  { value: 'GeneralToolBuilderAgent',   label: '🛠️ Tool Builder',              desc: 'Build custom exploit PoCs & tools' },
];

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'agent',
      agent: 'System',
      content: '🛡️ **PKCERT Bug Bounty Copilot** ready.\n\nSelect an agent below and start chatting. You can ask agents to:\n• Scan a target: `Scan https://gov.pk for vulnerabilities`\n• Find CVEs: `Find CVEs for Apache 2.4.7`\n• Build tools: `Write a Python PoC for SSRF`\n• Get guidance: `How to test for SQL injection?`',
      time: new Date().toLocaleTimeString(),
    }
  ]);
  const [input, setInput] = useState('');
  const [selectedAgent, setSelectedAgent] = useState('MasterAgent');
  const [isLoading, setIsLoading] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMsg: Message = { role: 'user', content: input, time: new Date().toLocaleTimeString() };
    setMessages(prev => [...prev, userMsg]);
    const currentInput = input;
    setInput('');
    setIsLoading(true);

    try {
      const res = await fetch(`/api/backend?path=agents/${selectedAgent}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: currentInput })
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || `HTTP ${res.status}`);
      }

      const agentMsg: Message = {
        role: 'agent',
        agent: selectedAgent,
        content: data.response || 'No response from agent.',
        time: new Date().toLocaleTimeString(),
      };
      if (data.chat_id) setTaskId(data.chat_id);
      setMessages(prev => [...prev, agentMsg]);
    } catch (err: any) {
      setMessages(prev => [...prev, {
        role: 'agent',
        agent: 'System',
        content: `⚠️ Error: ${err.message}. Make sure the backend server is running.`,
        time: new Date().toLocaleTimeString(),
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([{
      role: 'agent', agent: 'System',
      content: 'Chat cleared. Ready for new session.',
      time: new Date().toLocaleTimeString(),
    }]);
    setTaskId(null);
  };

  return (
    <div className="h-full flex flex-col animate-in fade-in duration-500" style={{ maxHeight: 'calc(100vh - 4rem)' }}>
      {/* Header */}
      <div className="border-b border-gray-800 pb-4 mb-4 flex justify-between items-start shrink-0">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">💬 Agent Chat</h2>
          <p className="text-sm text-gray-400 mt-1">Direct communication with PKCERT Bug Bounty agents</p>
        </div>
        <button onClick={clearChat} className="px-3 py-1.5 text-xs text-gray-400 hover:text-red-400 border border-gray-700 hover:border-red-700 rounded-lg transition-colors">
          Clear Chat
        </button>
      </div>

      {/* Agent Selector */}
      <div className="shrink-0 mb-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {AGENT_OPTIONS.map(ag => (
            <button
              key={ag.value}
              onClick={() => setSelectedAgent(ag.value)}
              className={`text-left p-3 rounded-lg border transition-all ${
                selectedAgent === ag.value
                  ? 'border-indigo-500 bg-indigo-500/10 text-white'
                  : 'border-gray-800 bg-gray-900 text-gray-400 hover:border-gray-600'
              }`}
            >
              <div className="text-xs font-semibold truncate">{ag.label}</div>
              <div className="text-xs text-gray-500 mt-0.5 truncate">{ag.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Chat Window */}
      <div className="flex-1 bg-gray-900 border border-gray-800 rounded-xl flex flex-col overflow-hidden min-h-0">
        <div className="flex-1 p-4 overflow-y-auto space-y-4">
          {messages.map((msg, i) => (
            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[85%] rounded-2xl px-4 py-3 ${
                msg.role === 'user'
                  ? 'bg-indigo-600 text-white rounded-br-none'
                  : 'bg-gray-800 border border-gray-700 text-gray-200 rounded-bl-none'
              }`}>
                {msg.role === 'agent' && (
                  <div className="text-xs text-indigo-400 font-bold mb-1">{msg.agent}</div>
                )}
                <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">{msg.content}</pre>
                <div className="text-xs text-gray-500 mt-1 text-right">{msg.time}</div>
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-gray-800 border border-gray-700 rounded-2xl rounded-bl-none px-4 py-3 flex items-center space-x-2">
                <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" />
                <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }} />
                <span className="ml-2 text-xs text-gray-400">{selectedAgent} is working... (30-120s)</span>
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <form onSubmit={sendMessage} className="p-4 border-t border-gray-800 bg-gray-950 flex space-x-2 shrink-0">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            disabled={isLoading}
            placeholder={isLoading ? `${selectedAgent} is working...` : `Message ${selectedAgent}...`}
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50 placeholder-gray-500"
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg font-medium transition-colors"
          >
            Send
          </button>
        </form>
      </div>

      {taskId && (
        <div className="mt-2 text-xs text-gray-600 shrink-0">
          Last session ID: <a href={`/tasks/${taskId}`} className="text-indigo-500 hover:underline">{taskId}</a>
        </div>
      )}
    </div>
  );
}
