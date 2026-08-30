"use client";
import React, { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';

interface ExecutionLog {
  id?: number;
  timestamp: string;
  agent_name: string;
  log_type: 'System' | 'Thought' | 'Action' | 'Observation' | 'Result' | 'Error' | 'Status';
  content: string;
}

interface StepGroup {
  stepNumber: number;
  agentName: string;
  thought?: string;
  action?: string;
  observation?: string;
  result?: string;
  error?: string;
  status: 'running' | 'completed' | 'failed';
  timestamp: string;
}

export default function LiveTaskConsole() {
  const { id } = useParams();
  const [logs, setLogs] = useState<ExecutionLog[]>([]);
  const [status, setStatus] = useState<"Running" | "Completed" | "Cancelled" | "Failed">("Running");
  const [viewMode, setViewMode] = useState<"interactive" | "terminal">("interactive");
  const [cancelling, setCancelling] = useState(false);
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({});
  const endOfLogsRef = useRef<HTMLDivElement>(null);

  // Poll the backend every 2 seconds for new logs
  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await fetch(`/api/backend?path=tasks/${id}/logs`);
        if (res.ok) {
          const data = await res.json();
          if (data.logs && data.logs.length > 0) {
            setLogs(data.logs);
            
            // Check status from latest logs
            const lastLog = data.logs[data.logs.length - 1];
            if (lastLog.log_type === 'Status' && (lastLog.content.includes('Task complete') || lastLog.content.includes('Completed'))) {
              setStatus("Completed");
            } else if (lastLog.content.includes('cancelled') || lastLog.content.includes('Cancelled')) {
              setStatus("Cancelled");
            } else if (lastLog.log_type === 'Error') {
              setStatus("Failed");
            }
          }
        }
      } catch (err) {
        console.error("Error fetching live logs", err);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 2000);
    return () => clearInterval(interval);
  }, [id]);

  useEffect(() => {
    endOfLogsRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const [resuming, setResuming] = useState(false);

  // Cancel task handler
  const handleCancelTask = async () => {
    if (!confirm("Are you sure you want to stop this scan?")) return;
    setCancelling(true);
    try {
      const res = await fetch(`/api/backend?path=tasks/${id}/cancel`, { method: 'POST' });
      if (res.ok) {
        setStatus("Cancelled");
      }
    } catch (err) {
      console.error("Failed to cancel task", err);
    } finally {
      setCancelling(false);
    }
  };

  // Resume task handler
  const handleResumeTask = async () => {
    setResuming(true);
    try {
      const res = await fetch(`/api/backend?path=tasks/${id}/resume`, { method: 'POST' });
      if (res.ok) {
        setStatus("Running");
      }
    } catch (err) {
      console.error("Failed to resume task", err);
    } finally {
      setResuming(false);
    }
  };


  // Group logs into step blocks for interactive view
  const parseStepGroups = (): StepGroup[] => {
    const groups: StepGroup[] = [];
    let currentGroup: Partial<StepGroup> | null = null;
    let stepCount = 0;

    logs.forEach((log) => {
      if (log.log_type === 'Thought' || (log.log_type === 'Action' && !currentGroup?.action)) {
        if (currentGroup && (currentGroup.thought || currentGroup.action)) {
          groups.push(currentGroup as StepGroup);
        }
        stepCount++;
        currentGroup = {
          stepNumber: stepCount,
          agentName: log.agent_name,
          timestamp: log.timestamp,
          status: 'running',
          thought: log.log_type === 'Thought' ? log.content : undefined,
          action: log.log_type === 'Action' ? log.content : undefined,
        };
      } else if (currentGroup) {
        if (log.log_type === 'Thought') currentGroup.thought = log.content;
        if (log.log_type === 'Action') currentGroup.action = log.content;
        if (log.log_type === 'Observation') {
          currentGroup.observation = log.content;
          currentGroup.status = 'completed';
        }
        if (log.log_type === 'Result') {
          currentGroup.result = log.content;
          currentGroup.status = 'completed';
        }
        if (log.log_type === 'Error') {
          currentGroup.error = log.content;
          currentGroup.status = 'failed';
        }
      }
    });

    if (currentGroup && (currentGroup.thought || currentGroup.action || currentGroup.result)) {
      groups.push(currentGroup as StepGroup);
    }

    return groups;
  };

  const stepGroups = parseStepGroups();

  const toggleStep = (stepNum: number) => {
    setExpandedSteps((prev) => ({ ...prev, [stepNum]: !prev[stepNum] }));
  };

  return (
    <div className="h-full flex flex-col space-y-4 font-sans text-slate-100">
      
      {/* ── Top Bar / Header ── */}
      <div className="flex flex-wrap justify-between items-center bg-slate-900/90 border border-slate-800 p-4 rounded-xl shadow-lg gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl font-extrabold bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
              Agent Control Console
            </h2>
            <span className={`text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wider ${
              status === 'Running' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse' :
              status === 'Completed' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
              status === 'Cancelled' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
              'bg-red-500/20 text-red-400 border border-red-500/30'
            }`}>
              {status === 'Running' ? '⚡ RUNNING' : status === 'Completed' ? '✅ COMPLETED' : status === 'Cancelled' ? '⛔ CANCELLED' : '❌ FAILED'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">ID: {id}</p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          {/* View Switcher */}
          <div className="bg-slate-950 p-1 rounded-lg border border-slate-800 flex text-xs font-medium">
            <button
              onClick={() => setViewMode("interactive")}
              className={`px-3 py-1.5 rounded-md transition-all ${viewMode === 'interactive' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}
            >
              🧠 Step Flow
            </button>
            <button
              onClick={() => setViewMode("terminal")}
              className={`px-3 py-1.5 rounded-md transition-all ${viewMode === 'terminal' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}
            >
              💻 Raw Logs
            </button>
          </div>

          {/* Stop / Cancel Button */}
          {status === 'Running' && (
            <button
              onClick={handleCancelTask}
              disabled={cancelling}
              className="px-4 py-2 bg-red-600/90 hover:bg-red-600 text-white text-xs font-bold rounded-lg transition-all shadow-lg hover:shadow-red-500/20 flex items-center gap-2 disabled:opacity-50"
            >
              <span>🛑</span> {cancelling ? 'Stopping...' : 'Stop Scan'}
            </button>
          )}

          {/* Resume Button */}
          {(status === 'Cancelled' || status === 'Failed') && (
            <button
              onClick={handleResumeTask}
              disabled={resuming}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg transition-all shadow-lg hover:shadow-blue-500/20 flex items-center gap-2 disabled:opacity-50"
            >
              <span>▶️</span> {resuming ? 'Resuming...' : 'Resume Scan'}
            </button>
          )}

          {/* View Report (Always Visible) */}
          <button
            onClick={() => window.open(`http://localhost:8000/tasks/${id}/report`, '_blank')}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg transition-all shadow-lg flex items-center gap-2"
          >
            <span>📄</span> View Audit Report
          </button>



          <Link href="/" className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-all">
            ← Dashboard
          </Link>
        </div>
      </div>

      {/* ── Main Display Body ── */}
      {viewMode === "interactive" ? (
        /* INTERACTIVE STEP FLOW VIEW */
        <div className="flex-1 overflow-y-auto space-y-4 pr-1">
          {stepGroups.length === 0 ? (
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-12 text-center text-slate-400">
              {status === 'Cancelled' ? (
                <>
                  <span className="text-4xl block mb-3">⛔</span>
                  <div className="font-bold text-base text-slate-300">Task Cancelled</div>
                  <p className="text-xs text-slate-500 mt-1">This scan task was stopped by the user.</p>
                </>
              ) : status === 'Failed' ? (
                <>
                  <span className="text-4xl block mb-3">❌</span>
                  <div className="font-bold text-base text-red-400">Initialization Failed</div>
                  <p className="text-xs text-slate-500 mt-1">The task failed before generating execution steps.</p>
                </>
              ) : (
                <div className="animate-pulse">
                  <span className="text-4xl block mb-3">⚡</span>
                  <div className="font-bold text-base text-indigo-400">Scan Queued & Starting Agent Pipeline...</div>
                  <p className="text-xs text-slate-400 mt-1">Worker thread is initializing tools and master plan. Logs will appear automatically.</p>
                </div>
              )}
            </div>
          ) : (
            stepGroups.map((group) => {
              const isExpanded = expandedSteps[group.stepNumber] ?? true;
              return (
                <div
                  key={group.stepNumber}
                  className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-lg transition-all hover:border-slate-700"
                >
                  {/* Step Header */}
                  <div
                    onClick={() => toggleStep(group.stepNumber)}
                    className="flex justify-between items-center p-4 bg-slate-950/60 cursor-pointer border-b border-slate-800/60 hover:bg-slate-900/80 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-7 h-7 rounded-lg bg-indigo-600/20 border border-indigo-500/30 text-indigo-400 font-extrabold text-xs flex items-center justify-center">
                        {group.stepNumber}
                      </span>
                      <span className="font-bold text-sm text-slate-200">{group.agentName}</span>
                      {group.action && (
                        <span className="bg-slate-800 text-amber-300 font-mono text-xs px-2.5 py-0.5 rounded border border-amber-500/20">
                          ⚙️ {group.action}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-xs text-slate-500 font-mono">
                        {new Date(group.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="text-slate-400 text-xs">
                        {isExpanded ? '▲' : '▼'}
                      </span>
                    </div>
                  </div>

                  {/* Step Content */}
                  {isExpanded && (
                    <div className="p-4 space-y-4 text-xs">
                      
                      {/* Thought Block */}
                      {group.thought && (
                        <div className="bg-indigo-950/30 border border-indigo-500/20 rounded-lg p-3 space-y-1">
                          <div className="text-indigo-400 font-bold flex items-center gap-1.5 uppercase tracking-wide text-[10px]">
                            <span>🧠</span> Agent Reasoning / Strategy
                          </div>
                          <p className="text-slate-300 whitespace-pre-wrap leading-relaxed">
                            {group.thought}
                          </p>
                        </div>
                      )}

                      {/* Action Block */}
                      {group.action && (
                        <div className="bg-amber-950/20 border border-amber-500/20 rounded-lg p-3 space-y-1 font-mono">
                          <div className="text-amber-400 font-bold flex items-center gap-1.5 uppercase tracking-wide text-[10px]">
                            <span>⚙️</span> Invoked Command / Tool
                          </div>
                          <div className="text-amber-200 bg-black/50 p-2.5 rounded border border-amber-500/10 whitespace-pre-wrap word-break">
                            {group.action}
                          </div>
                        </div>
                      )}

                      {/* Observation / Output Block */}
                      {group.observation && (
                        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1 font-mono">
                          <div className="text-emerald-400 font-bold flex items-center gap-1.5 uppercase tracking-wide text-[10px]">
                            <span>📤</span> Execution Output
                          </div>
                          <pre className="text-slate-300 max-h-60 overflow-y-auto p-2.5 bg-black/60 rounded text-[11px] whitespace-pre-wrap leading-tight scrollbar-thin">
                            {group.observation}
                          </pre>
                        </div>
                      )}

                      {/* Result / Final Output Block */}
                      {group.result && (
                        <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-lg p-3 space-y-1">
                          <div className="text-emerald-400 font-bold flex items-center gap-1.5 uppercase tracking-wide text-[10px]">
                            <span>🎯</span> Result & Finding Deductions
                          </div>
                          <div className="text-emerald-200 whitespace-pre-wrap leading-relaxed">
                            {group.result}
                          </div>
                        </div>
                      )}

                      {/* Error Block */}
                      {group.error && (
                        <div className="bg-red-950/30 border border-red-500/30 rounded-lg p-3 space-y-1">
                          <div className="text-red-400 font-bold flex items-center gap-1.5 uppercase tracking-wide text-[10px]">
                            <span>❌</span> Error Encountered
                          </div>
                          <div className="text-red-300 font-mono whitespace-pre-wrap">
                            {group.error}
                          </div>
                        </div>
                      )}

                    </div>
                  )}
                </div>
              );
            })
          )}
          <div ref={endOfLogsRef} />
        </div>
      ) : (
        /* RAW TERMINAL LOG VIEW */
        <div className="flex-1 bg-black border border-slate-800 rounded-xl font-mono text-xs overflow-hidden flex flex-col shadow-2xl relative">
          <div className="bg-slate-900 border-b border-slate-800 p-2.5 flex items-center justify-between">
            <div className="flex space-x-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-amber-500"></div>
              <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
            </div>
            <span className="text-slate-400 text-xs">agent@bugbounty-copilot:~</span>
            <span></span>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {logs.map((log, index) => (
              <div key={index} className="flex space-x-4 border-b border-slate-900/80 pb-2">
                <span className="text-slate-600 shrink-0 w-20">{new Date(log.timestamp).toLocaleTimeString()}</span>
                <span className="text-indigo-400 shrink-0 w-36 font-bold">[{log.agent_name}]</span>

                {log.log_type === 'Thought' && <span className="text-blue-300 flex-1 whitespace-pre-wrap">{log.content}</span>}
                {log.log_type === 'Action' && <span className="text-amber-400 flex-1 whitespace-pre-wrap font-bold">{log.content}</span>}
                {log.log_type === 'Observation' && <span className="text-slate-300 flex-1 whitespace-pre-wrap">{log.content}</span>}
                {log.log_type === 'Result' && <span className="text-emerald-400 flex-1 whitespace-pre-wrap">{log.content}</span>}
                {log.log_type === 'Error' && <span className="text-red-400 flex-1 whitespace-pre-wrap">{log.content}</span>}
                {log.log_type === 'System' && <span className="text-slate-500 flex-1 whitespace-pre-wrap italic">{log.content}</span>}
                {log.log_type === 'Status' && <span className="text-cyan-400 flex-1 whitespace-pre-wrap font-bold">{log.content}</span>}
              </div>
            ))}
            {status === 'Running' && (
              <div className="flex space-x-4">
                <span className="text-slate-600 shrink-0 w-20">{new Date().toLocaleTimeString()}</span>
                <span className="text-indigo-400 shrink-0 w-36 font-bold">[System]</span>
                <span className="text-emerald-500 flex-1 animate-pulse">_</span>
              </div>
            )}
            <div ref={endOfLogsRef} />
          </div>
        </div>
      )}
    </div>
  );
}
