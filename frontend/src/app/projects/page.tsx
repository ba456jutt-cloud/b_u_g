"use client";
import React, { useEffect, useState } from 'react';
import Link from 'next/link';

export default function ProjectsPage() {
  const [tasks, setTasks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/backend?path=tasks/active')
      .then(r => r.json())
      .then(d => {
        setTasks(d.tasks || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const deleteTask = async (taskId: string) => {
    await fetch(`/api/backend?path=tasks/${taskId}`, { method: 'DELETE' });
    setTasks(prev => prev.filter(t => t.task_id !== taskId));
  };

  const severityColors: any = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/30',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    info: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
  };

  if (loading) return <div className="text-white animate-pulse">Loading projects...</div>;

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center border-b border-gray-800 pb-4">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">🎯 Scan History</h2>
          <p className="text-gray-400 mt-1">All past analysis tasks and their results</p>
        </div>
        <Link href="/" className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg font-medium text-white transition-colors">
          + New Analysis
        </Link>
      </div>

      {tasks.length === 0 ? (
        <div className="text-center py-24 text-gray-500">
          <div className="text-5xl mb-4">🔍</div>
          <p className="text-lg">No scan history yet.</p>
          <p className="text-sm mt-2">Start a new analysis from the dashboard.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {tasks.map((task: any) => (
            <div key={task.task_id} className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-indigo-500/40 transition-colors">
              <div className="flex justify-between items-start">
                <div className="flex-1 min-w-0 mr-4">
                  <div className="flex items-center gap-3 mb-2">
                    <span className="px-2 py-0.5 text-xs rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                      Completed
                    </span>
                    <span className="text-xs text-gray-500 font-mono">{task.task_id?.slice(0, 16)}...</span>
                  </div>
                  <p className="text-gray-200 font-medium line-clamp-2 text-sm">{task.task_name || 'Security Analysis Task'}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                    <span>📅 {task.started_at ? new Date(task.started_at).toLocaleString() : 'Unknown'}</span>
                    <span>🕐 Updated: {task.last_updated ? new Date(task.last_updated).toLocaleString() : 'Unknown'}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Link
                    href={`/tasks/${task.task_id}`}
                    className="px-3 py-1.5 text-xs bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded-lg hover:bg-indigo-600/40 transition-colors"
                  >
                    View Logs
                  </Link>
                  <button
                    onClick={() => window.open(`/api/backend?path=tasks/${task.task_id}/report`, '_blank')}
                    className="px-3 py-1.5 text-xs bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 rounded-lg hover:bg-emerald-600/40 transition-colors"
                  >
                    📄 Report
                  </button>
                  <button
                    onClick={() => deleteTask(task.task_id)}
                    className="px-3 py-1.5 text-xs bg-red-600/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-600/40 transition-colors"
                  >
                    🗑 Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
