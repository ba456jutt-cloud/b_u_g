"use client";
import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export default function ReportsPage() {
  const router = useRouter();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/backend?path=findings')
      .then(res => res.json())
      .then(data => {
        if (data.findings) setFindings(data.findings);
        setLoading(false);
      })
      .catch(err => {
        console.error("Error fetching findings", err);
        setLoading(false);
      });
  }, []);

  const handleDownload = (taskId: string) => {
    // Open real HTML report via backend API proxy
    window.open(`/api/backend?path=tasks/${taskId}/report`, '_blank');
  };

  const handleGenerate = () => {
    router.push('/analysis/new');
  };

  if (loading) return <div className="text-white">Loading reports...</div>;

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center border-b border-gray-800 pb-4">
        <h2 className="text-3xl font-bold tracking-tight text-white">Reports & Findings</h2>
        <button onClick={handleGenerate} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-md font-medium transition-colors text-white">
          Generate New Report
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-800/50 text-gray-400 text-sm border-b border-gray-800">
              <th className="p-4 font-medium">Finding Title</th>
              <th className="p-4 font-medium">Severity</th>
              <th className="p-4 font-medium">Status</th>
              <th className="p-4 font-medium">Date Discovered</th>
              <th className="p-4 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="text-gray-300 text-sm">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-4 text-gray-500 text-center">No findings or reports available. Launch an analysis.</td>
              </tr>
            ) : (
              findings.map((f: any, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/30 transition-colors">
                  <td className="p-4 font-medium text-white">{f.title}</td>
                  <td className="p-4"><span className={`px-2 py-1 bg-gray-800 rounded text-xs ${f.severity === 'High' ? 'text-red-400' : 'text-orange-400'}`}>{f.severity}</span></td>
                  <td className="p-4">{f.status}</td>
                  <td className="p-4 text-gray-500">{new Date(f.created_at).toLocaleDateString()}</td>
                  <td className="p-4 text-right space-x-3">
                    {f.task_id && (
                      <button onClick={() => handleDownload(f.task_id)} className="text-indigo-400 hover:text-indigo-300 text-xs">📄 View Report</button>
                    )}
                    {f.task_id && (
                      <Link href={`/tasks/${f.task_id}`} className="text-gray-400 hover:text-white text-xs">Logs →</Link>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
