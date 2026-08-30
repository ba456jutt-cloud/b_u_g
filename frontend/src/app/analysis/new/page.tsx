"use client";
import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

const PRESET_WORKFLOWS = [
  {
    id: 'Full Audit',
    title: '🛡️ Full Security Audit',
    desc: 'Complete 22-Agent Pipeline: Scope → Recon → Crawl → Vuln Analysis → CVE → Attack Chain → PDF Report',
    icon: '🛡️',
    color: 'from-indigo-600 to-purple-600',
    badge: 'Recommended'
  },
  {
    id: 'Reconnaissance',
    title: '🔍 Reconnaissance & Mapping',
    desc: 'Passive OSINT, Nmap port scanning, WAF detection, technology stack fingerprinting & SSL checks',
    icon: '🔍',
    color: 'from-blue-600 to-cyan-600',
    badge: 'Fast'
  },
  {
    id: 'subdomain discovery',
    title: '🌐 Subdomain & DNS Intel',
    desc: 'Subfinder, Assetfinder, Findomain, dnsx, AXFR zone transfer & CNAME takeover checks',
    icon: '🌐',
    color: 'from-emerald-600 to-teal-600',
    badge: 'DNS'
  },
  {
    id: 'web enumeration',
    title: '🕸️ Web Crawl & Dir Brute',
    desc: 'Katana crawler, gau historical URLs, Arjun parameter mining, feroxbuster & ffuf directory enum',
    icon: '🕸️',
    color: 'from-amber-600 to-orange-600',
    badge: 'Web App'
  },
  {
    id: 'CVE Analysis',
    title: '🐛 CVE & Threat Intelligence',
    desc: 'Software version matching against NIST NVD database for real CVSS v3.1 severity scores',
    icon: '🐛',
    color: 'from-rose-600 to-red-600',
    badge: 'Intel'
  },
  {
    id: 'Code Review',
    title: '📝 Secure Code Review (SAST)',
    desc: 'Static Application Security Testing (Semgrep) for Injection, Auth bypass & logic flaws',
    icon: '📝',
    color: 'from-violet-600 to-indigo-600',
    badge: 'SAST'
  },
  {
    id: 'ctf solver',
    title: '🚩 CTF Challenge Solver',
    desc: 'Automated CTF Flag Extractor: Web challenge solver, Base64/Hex/JWT crypto decoders & Stego metadata analyzer',
    icon: '🚩',
    color: 'from-yellow-500 to-amber-600',
    badge: 'CTF Pro'
  }
];


export default function NewAnalysisPage() {
  const router = useRouter();
  const [selectedWorkflow, setSelectedWorkflow] = useState('Full Audit');
  const [target, setTarget] = useState('');
  const [instructions, setInstructions] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!target || target.trim() === '') {
      setError('Please enter a valid target IP address or domain URL.');
      return;
    }

    setIsLoading(true);
    let taskDetails = `Perform ${selectedWorkflow} on target: ${target.trim()}`;
    if (instructions && instructions.trim()) {
      taskDetails += ` Additional instructions: ${instructions.trim()}`;
    }

    try {
      const res = await fetch('/api/tasks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task: taskDetails, workflow: selectedWorkflow })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Backend error: ${res.status}`);
      }

      const data = await res.json();
      if (data.task_id) {
        router.push(`/tasks/${data.task_id}`);
      } else {
        setError(`Unexpected backend response: ${JSON.stringify(data)}`);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to reach the backend server.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-in fade-in duration-500">
      <div className="border-b border-gray-800 pb-4">
        <h2 className="text-3xl font-bold tracking-tight text-white">🚀 Launch Automated Assessment</h2>
        <p className="text-sm text-gray-400 mt-1">Select a preset workflow strategy card and enter your target IP address or domain URL.</p>
      </div>

      <form onSubmit={handleLaunch} className="space-y-6">
        {/* Preset Workflow Strategy Cards */}
        <div>
          <label className="block text-sm font-semibold text-gray-300 mb-3">
            Select Assessment Preset <span className="text-indigo-400">*</span>
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {PRESET_WORKFLOWS.map((wf) => {
              const isSelected = selectedWorkflow === wf.id;
              return (
                <div
                  key={wf.id}
                  onClick={() => setSelectedWorkflow(wf.id)}
                  className={`relative p-5 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'border-indigo-500 bg-gray-900 ring-2 ring-indigo-500/40 shadow-xl'
                      : 'border-gray-800 bg-gray-900/60 hover:border-gray-700 hover:bg-gray-900'
                  }`}
                >
                  {wf.badge && (
                    <span className={`absolute top-3 right-3 text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                      isSelected ? 'bg-indigo-500 text-white' : 'bg-gray-800 text-gray-400'
                    }`}>
                      {wf.badge}
                    </span>
                  )}
                  <div className="text-2xl mb-2">{wf.icon}</div>
                  <h3 className="font-bold text-white text-base">{wf.title}</h3>
                  <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">{wf.desc}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Target Input Container */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <div>
            <label className="block text-sm font-semibold text-gray-200 mb-1">
              Target IP Address or Domain URL <span className="text-rose-400">*</span>
            </label>
            <p className="text-xs text-gray-500 mb-2">Simply enter target hostname or IP (e.g., scanme.nmap.org or 45.33.32.156)</p>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
              placeholder="e.g. scanme.nmap.org or 45.33.32.156"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all font-mono text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Custom Directives <span className="text-gray-500 font-normal">(Optional)</span>
            </label>
            <input
              type="text"
              value={instructions}
              onChange={(e) => setInstructions(e.target.value)}
              placeholder="e.g. Focus on SSL checks, scan top 100 ports..."
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
            />
          </div>

          {error && (
            <div className="p-3 bg-red-900/40 border border-red-700/50 rounded-lg text-red-300 text-sm">
              ⚠️ {error}
            </div>
          )}

          <div className="flex items-center justify-between pt-3 border-t border-gray-800">
            <span className="text-xs text-gray-500">
              Selected Strategy: <strong className="text-indigo-400">{selectedWorkflow}</strong>
            </span>
            <button
              type="submit"
              disabled={isLoading}
              className="px-6 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 rounded-lg font-semibold text-white text-sm shadow-lg shadow-indigo-500/20 flex items-center gap-2 transition-all"
            >
              {isLoading ? (
                <>
                  <span className="animate-spin text-sm">⟳</span> Executing Workflow...
                </>
              ) : (
                '🚀 1-Click Launch Workflow'
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
