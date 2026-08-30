"use client";
import { useEffect, useState } from 'react';
import Link from 'next/link';

// Pure SVG donut chart - no library needed
function DonutChart({ data }: { data: { label: string; value: number; color: string }[] }) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  if (total === 0) return (
    <div className="flex items-center justify-center h-40 text-gray-600 text-sm">No findings yet</div>
  );

  let cumulative = 0;
  const radius = 60;
  const cx = 80;
  const cy = 80;
  const strokeWidth = 20;

  const segments = data.map((d) => {
    const pct = d.value / total;
    const startAngle = cumulative * 2 * Math.PI - Math.PI / 2;
    cumulative += pct;
    const endAngle = cumulative * 2 * Math.PI - Math.PI / 2;
    const x1 = cx + radius * Math.cos(startAngle);
    const y1 = cy + radius * Math.sin(startAngle);
    const x2 = cx + radius * Math.cos(endAngle);
    const y2 = cy + radius * Math.sin(endAngle);
    const largeArc = pct > 0.5 ? 1 : 0;
    return { ...d, x1, y1, x2, y2, largeArc, pct };
  });

  return (
    <div className="flex items-center gap-6">
      <svg width="160" height="160" viewBox="0 0 160 160">
        {segments.filter(s => s.value > 0).map((s, i) => (
          <path
            key={i}
            d={`M ${s.x1} ${s.y1} A ${radius} ${radius} 0 ${s.largeArc} 1 ${s.x2} ${s.y2}`}
            fill="none"
            stroke={s.color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
        ))}
        <text x={cx} y={cy} textAnchor="middle" dominantBaseline="middle" className="fill-white" fontSize="20" fontWeight="bold">
          {total}
        </text>
        <text x={cx} y={cy + 16} textAnchor="middle" dominantBaseline="middle" fill="#6b7280" fontSize="10">
          findings
        </text>
      </svg>
      <div className="space-y-2">
        {data.map((d, i) => (
          <div key={i} className="flex items-center gap-2 text-sm">
            <div className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
            <span className="text-gray-400">{d.label}</span>
            <span className="font-bold text-white ml-auto pl-4">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Home() {
  const [stats, setStats] = useState<any>(null);
  const [basicStats, setBasicStats] = useState({ agents: 0, findings: 0, memory: 0 });
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const safeFetchJson = async (url: string) => {
      try {
        const r = await fetch(url);
        if (!r.ok) return {};
        const text = await r.text();
        return text.startsWith('{') || text.startsWith('[') ? JSON.parse(text) : {};
      } catch {
        return {};
      }
    };

    const fetchDashboardData = async () => {
      try {
        const [agentsRes, findingsRes, memRes, tasksRes, statsRes] = await Promise.all([
          safeFetchJson('/api/backend?path=agents'),
          safeFetchJson('/api/backend?path=findings'),
          safeFetchJson('/api/backend?path=memory'),
          safeFetchJson('/api/backend?path=tasks/active'),
          safeFetchJson('/api/backend?path=stats'),
        ]);

        setBasicStats({
          agents: agentsRes?.agents?.length || 0,
          findings: findingsRes?.findings?.length || 0,
          memory: memRes?.record_counts ? (memRes.record_counts.session_logs + memRes.record_counts.key_findings) : 0,
        });
        setTasks(tasksRes?.tasks || []);
        setStats(statsRes && Object.keys(statsRes).length > 0 ? statsRes : null);
      } catch (error) {
        console.error("Failed to load dashboard data", error);
      } finally {
        setLoading(false);
      }
    };
    fetchDashboardData();
  }, []);

  const severityData = stats ? [
    { label: 'Critical', value: stats.severity_counts?.critical || 0, color: '#dc2626' },
    { label: 'High', value: stats.severity_counts?.high || 0, color: '#ea580c' },
    { label: 'Medium', value: stats.severity_counts?.medium || 0, color: '#d97706' },
    { label: 'Low', value: stats.severity_counts?.low || 0, color: '#2563eb' },
    { label: 'Info', value: stats.severity_counts?.info || 0, color: '#6b7280' },
  ] : [];

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-gray-400 animate-pulse">Loading dashboard...</div>
    </div>
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center border-b border-gray-800 pb-4">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">🛡️ Dashboard</h2>
          <p className="text-gray-400 text-sm mt-1">Bug Bounty Copilot — AI Security Platform</p>
        </div>
        <Link href="/analysis/new" className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 rounded-lg font-semibold transition-colors flex items-center gap-2">
          <span>+</span> New Analysis
        </Link>
      </div>

      {/* Quick Preset Strategy Bar */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
        <div className="flex justify-between items-center">
          <h3 className="text-sm font-bold text-gray-200 flex items-center gap-2">
            <span>⚡</span> Quick Assessment Presets
          </h3>
          <span className="text-xs text-gray-500">Select a preset to launch instantly with IP or URL</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { title: '🛡️ Full Audit', href: '/analysis/new?preset=Full+Audit' },
            { title: '🔍 Reconnaissance', href: '/analysis/new?preset=Reconnaissance' },
            { title: '🌐 Subdomains', href: '/analysis/new?preset=subdomain+discovery' },
            { title: '🕸️ Web Crawl', href: '/analysis/new?preset=web+enumeration' },
            { title: '🐛 CVE Research', href: '/analysis/new?preset=CVE+Analysis' },
            { title: '📝 Code Review', href: '/analysis/new?preset=Code+Review' },
          ].map((p) => (
            <Link
              key={p.title}
              href={p.href}
              className="p-3 bg-gray-800/60 hover:bg-indigo-950/40 border border-gray-700/60 hover:border-indigo-500/60 rounded-lg text-xs font-semibold text-gray-200 text-center transition-all hover:scale-[1.02]"
            >
              {p.title}
            </Link>
          ))}
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Active Agents', value: basicStats.agents, sub: 'In registry', color: 'indigo' },
          { label: 'Total Scans', value: stats?.total_scans || 0, sub: 'All time', color: 'blue' },
          { label: 'Findings', value: stats?.total_findings || basicStats.findings, sub: 'Stored', color: 'orange' },
          { label: 'Memory Records', value: basicStats.memory, sub: 'Interactions', color: 'emerald' },
        ].map(({ label, value, sub, color }) => (
          <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-indigo-500/40 transition-all group">
            <div className="text-gray-400 text-sm group-hover:text-indigo-400 transition-colors">{label}</div>
            <div className="text-3xl font-bold mt-1 text-white">{value}</div>
            <div className="text-xs text-indigo-400 mt-1">{sub}</div>
          </div>
        ))}
      </div>

      {/* Charts + Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Donut Chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <span>📊</span> Findings by Severity
          </h3>
          <DonutChart data={severityData} />
        </div>

        {/* Recent Scans */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <span>🕐</span> Recent Scans
          </h3>
          <div className="space-y-2">
            {(stats?.recent_scans || []).slice(0, 5).map((scan: any) => (
              <Link key={scan.task_id} href={`/tasks/${scan.task_id}`} className="flex items-center justify-between p-3 hover:bg-gray-800 rounded-lg transition-colors group">
                <div className="min-w-0 flex-1">
                  <div className="text-sm text-gray-300 truncate group-hover:text-indigo-400 transition-colors">
                    {scan.task_name?.replace('Received Task: ', '') || 'Analysis Task'}
                  </div>
                  <div className="text-xs text-gray-600">{new Date(scan.started_at).toLocaleString()}</div>
                </div>
                <span className="text-indigo-400 text-xs ml-2 shrink-0">View →</span>
              </Link>
            ))}
            {(!stats?.recent_scans || stats.recent_scans.length === 0) && (
              <p className="text-gray-600 text-sm py-4 text-center">No scans yet. Start a new analysis!</p>
            )}
          </div>
        </div>
      </div>

      {/* Task Queue */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4 border-b border-gray-800 pb-2 text-white flex items-center gap-2">
          <span>⚡</span> Active Task Queue
        </h3>
        <div className="space-y-2">
          {tasks.length === 0 ? (
            <div className="text-gray-500 text-sm py-4 text-center">Queue is empty. Launch a new analysis above.</div>
          ) : (
            tasks.map((task: any) => (
              <div key={task.task_id} className="flex justify-between items-center p-3 hover:bg-gray-800/50 rounded-lg transition-colors border border-transparent hover:border-gray-700">
                <Link href={`/tasks/${task.task_id}`} className="flex-1 min-w-0 mr-4">
                  <div className="font-medium text-gray-200 truncate">{task.task_name?.replace('Received Task: ', '') || 'Unknown Task'}</div>
                  <div className="text-sm text-gray-500 font-mono text-xs">{task.task_id?.slice(0, 24)}...</div>
                </Link>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs text-gray-500">{new Date(task.last_updated).toLocaleTimeString()}</span>
                  <Link href={`/tasks/${task.task_id}`} className="px-2 py-1 text-xs bg-indigo-600/20 text-indigo-400 rounded hover:bg-indigo-600/40 transition-colors">Logs</Link>
                  <button
                    onClick={async () => {
                      await fetch(`/api/backend?path=tasks/${task.task_id}`, { method: 'DELETE' });
                      setTasks(tasks.filter((t: any) => t.task_id !== task.task_id));
                    }}
                    className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-400/10 rounded transition-colors"
                  >
                    🗑
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
