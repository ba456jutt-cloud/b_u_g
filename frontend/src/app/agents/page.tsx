"use client";
import React, { useEffect, useState } from 'react';

export default function AgentsPage() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [agentLogs, setAgentLogs] = useState<any[]>([]);
  
  // Chat state
  const [chatAgent, setChatAgent] = useState<string | null>(null);
  const [chatMessage, setChatMessage] = useState("");
  const [chatHistory, setChatHistory] = useState<{role: 'user' | 'agent', content: string}[]>([]);
  const [isChatting, setIsChatting] = useState(false);

  useEffect(() => {
    fetch('/api/backend?path=agents')
      .then(res => res.json())
      .then(data => {
        if (data.agents) setAgents(data.agents);
        setLoading(false);
      })
      .catch(err => {
        console.error("Error fetching agents", err);
        setLoading(false);
      });
  }, []);

  const handleDeploy = () => {
    // Redirect to new analysis page to start a task
    window.location.href = '/analysis/new';
  };

  const handleLogs = async (agentName: string) => {
    setSelectedAgent(agentName);
    try {
      const res = await fetch(`/api/backend?path=agents/${agentName}/logs`);
      const data = await res.json();
      setAgentLogs(data.logs || []);
    } catch (err) {
      console.error("Failed to fetch agent logs", err);
    }
  };

  const openChat = (agentName: string) => {
    setChatAgent(agentName);
    setChatHistory([{ role: 'agent', content: `Hello! I am ${agentName}. What task would you like me to perform today?` }]);
    setChatMessage("");
  };

  const sendChatMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatMessage.trim() || !chatAgent) return;
    
    const userMsg = chatMessage;
    setChatHistory(prev => [...prev, { role: 'user', content: userMsg }]);
    setChatMessage("");
    setIsChatting(true);
    
    try {
      const res = await fetch(`/api/backend?path=agents/${chatAgent}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMsg })
      });
      const data = await res.json();
      
      setChatHistory(prev => [...prev, { role: 'agent', content: data.response || `Error: ${data.detail}` }]);
    } catch (err) {
      setChatHistory(prev => [...prev, { role: 'agent', content: "Failed to reach the agent. Check backend connection." }]);
    } finally {
      setIsChatting(false);
    }
  };

  if (loading) return <div className="text-white">Loading agents...</div>;

  return (
    <div className="space-y-6 animate-in fade-in duration-500 relative">
      <div className="flex justify-between items-center border-b border-gray-800 pb-4">
        <h2 className="text-3xl font-bold tracking-tight text-white">Agents Configuration</h2>
        <button onClick={handleDeploy} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-md font-medium transition-colors text-white">
          🚀 New Analysis
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {agents.map((agent: string, i) => (
          <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-6 hover:border-indigo-500/50 transition-colors">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-xl font-semibold text-white">{agent}</h3>
                <p className="text-sm text-gray-400">Registered in Framework</p>
              </div>
              <span className="px-2 py-1 text-xs rounded-full bg-green-500/10 text-green-400">
                Online
              </span>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-800 flex justify-between items-center text-sm text-gray-400">
              <span>Ready for tasks</span>
              <div className="space-x-4">
                <button onClick={() => openChat(agent)} className="text-indigo-400 hover:text-indigo-300 font-medium">Chat & Assign</button>
                <button onClick={() => handleLogs(agent)} className="text-gray-400 hover:text-gray-300">Logs &rarr;</button>
              </div>
            </div>
          </div>
        ))}
        {agents.length === 0 && <div className="text-gray-500">No agents found in registry.</div>}
      </div>

      {/* Chat Modal */}
      {chatAgent && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-2xl h-[70vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-800 bg-gray-900">
              <div className="flex items-center space-x-3">
                <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                <h3 className="text-lg font-bold text-white">Direct Chat: {chatAgent}</h3>
              </div>
              <button onClick={() => setChatAgent(null)} className="text-gray-400 hover:text-white text-xl leading-none">&times;</button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-900/50">
              {chatHistory.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[80%] rounded-2xl px-4 py-3 ${msg.role === 'user' ? 'bg-indigo-600 text-white rounded-br-none' : 'bg-gray-800 text-gray-200 border border-gray-700 rounded-bl-none'}`}>
                    <div className="text-xs text-gray-400 mb-1">{msg.role === 'user' ? 'You' : chatAgent}</div>
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                  </div>
                </div>
              ))}
              {isChatting && (
                <div className="flex justify-start">
                  <div className="bg-gray-800 border border-gray-700 rounded-2xl rounded-bl-none px-4 py-3 text-gray-400 flex items-center space-x-2">
                    <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce"></div>
                    <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                    <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                    <span className="ml-2 text-xs">Agent is working... (this may take up to 30 seconds)</span>
                  </div>
                </div>
              )}
            </div>
            
            <form onSubmit={sendChatMessage} className="p-4 border-t border-gray-800 bg-gray-900 flex space-x-2">
              <input 
                type="text" 
                value={chatMessage} 
                onChange={(e) => setChatMessage(e.target.value)} 
                disabled={isChatting}
                placeholder={isChatting ? "Wait for agent to respond..." : "Type a task or instruction..."} 
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
              />
              <button 
                type="submit" 
                disabled={isChatting || !chatMessage.trim()}
                className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg font-medium transition-colors"
              >
                Send
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Agent Logs Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-4xl h-[80vh] flex flex-col shadow-2xl">
            <div className="flex justify-between items-center p-4 border-b border-gray-800">
              <h3 className="text-lg font-bold text-white">History Logs: {selectedAgent}</h3>
              <button onClick={() => setSelectedAgent(null)} className="text-gray-400 hover:text-white">✕</button>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-sm bg-black">
              {agentLogs.length === 0 ? (
                <div className="text-gray-500 text-center mt-10">No logs found for this agent yet.</div>
              ) : (
                agentLogs.map((log: any, idx) => (
                  <div key={idx} className="border-b border-gray-900/50 pb-2">
                    <div className="flex space-x-3 text-xs mb-1">
                      <span className="text-gray-500">{new Date(log.timestamp).toLocaleString()}</span>
                      <span className="text-indigo-400">Task: {log.task_id.substring(0, 8)}...</span>
                      <span className="text-gray-400">Type: {log.log_type}</span>
                    </div>
                    <div className="text-gray-300 whitespace-pre-wrap">{log.content}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
