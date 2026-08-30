"use client";
import React, { useEffect, useState } from 'react';

export default function SettingsPage() {
  const [settings, setSettings] = useState<any>(null);
  const [formData, setFormData] = useState({
    gemini_api_key: '',
    deepseek_api_key: '',
    openrouter_api_key: '',
    default_model: ''
  });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetch('/api/backend?path=settings')
      .then(r => r.json())
      .then(d => {
        setSettings(d);
        setFormData(f => ({ ...f, default_model: d.default_model || '' }));
      });
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setMessage('');
    try {
      const body: any = {};
      if (formData.gemini_api_key) body.gemini_api_key = formData.gemini_api_key;
      if (formData.deepseek_api_key) body.deepseek_api_key = formData.deepseek_api_key;
      if (formData.openrouter_api_key) body.openrouter_api_key = formData.openrouter_api_key;
      if (formData.default_model) body.default_model = formData.default_model;

      const res = await fetch('/api/backend?path=settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      setMessage(data.status || 'Saved!');
    } catch {
      setMessage('Error saving settings.');
    } finally {
      setSaving(false);
    }
  };

  const InputField = ({ label, id, type = 'text', placeholder, value, onChange, hint }: any) => (
    <div className="mb-6">
      <label htmlFor={id} className="block text-sm font-medium text-gray-300 mb-2">{label}</label>
      <input
        id={id}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
      />
      {hint && <p className="text-xs text-gray-500 mt-1">{hint}</p>}
    </div>
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="border-b border-gray-800 pb-4">
        <h2 className="text-3xl font-bold tracking-tight text-white">⚙️ Settings</h2>
        <p className="text-gray-400 mt-1">Configure API keys and system preferences</p>
      </div>

      {/* Status Cards */}
      {settings && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { label: 'Gemini API', key: 'gemini_key_set', color: 'emerald' },
            { label: 'DeepSeek API', key: 'deepseek_key_set', color: 'blue' },
            { label: 'OpenRouter API', key: 'openrouter_key_set', color: 'purple' },
          ].map(({ label, key, color }) => (
            <div key={key} className={`bg-gray-900 border rounded-xl p-4 flex items-center space-x-3 ${settings[key] ? `border-${color}-500/40` : 'border-red-500/40'}`}>
              <div className={`w-3 h-3 rounded-full ${settings[key] ? `bg-${color}-500` : 'bg-red-500'}`} />
              <div>
                <div className="text-white font-medium text-sm">{label}</div>
                <div className={`text-xs ${settings[key] ? 'text-emerald-400' : 'text-red-400'}`}>
                  {settings[key] ? 'Configured ✓' : 'Not set'}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <form onSubmit={handleSave} className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* API Keys Section */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <span>🔑</span> API Keys
          </h3>
          <InputField
            label="Gemini API Key"
            id="gemini-key"
            type="password"
            placeholder="AIza..."
            value={formData.gemini_api_key}
            onChange={(e: any) => setFormData(f => ({ ...f, gemini_api_key: e.target.value }))}
            hint="Used for CVEResearchAgent, ReportAgent, SecurityKnowledgeAgent (lighter research tasks)"
          />
          <InputField
            label="DeepSeek API Key"
            id="deepseek-key"
            type="password"
            placeholder="sk-..."
            value={formData.deepseek_api_key}
            onChange={(e: any) => setFormData(f => ({ ...f, deepseek_api_key: e.target.value }))}
            hint="Primary model for heavy agents: MasterAgent, ReconAnalysisAgent, CodeReviewAgent, ToolBuilderAgent"
          />
          <InputField
            label="OpenRouter API Key"
            id="openrouter-key"
            type="password"
            placeholder="sk-or-..."
            value={formData.openrouter_api_key}
            onChange={(e: any) => setFormData(f => ({ ...f, openrouter_api_key: e.target.value }))}
            hint="Used as a flexible multi-model fallback"
          />
        </div>

        {/* Model & System Settings */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <span>🤖</span> Model Configuration
          </h3>
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-300 mb-2">Default Model</label>
            <select
              value={formData.default_model}
              onChange={(e) => setFormData(f => ({ ...f, default_model: e.target.value }))}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="">Current: {settings?.default_model || 'Loading...'}</option>
              <option value="gemini-2.5-flash">gemini-2.5-flash (Recommended — Fast + Smart)</option>
              <option value="gemini-2.0-flash">gemini-2.0-flash (Fast)</option>
              <option value="gemini-2.0-flash-lite">gemini-2.0-flash-lite (Lightest)</option>
            </select>
          </div>

          {/* System Info */}
          <div className="bg-gray-800/50 rounded-lg p-4 space-y-2 text-sm">
            <h4 className="text-gray-300 font-medium mb-3">System Information</h4>
            <div className="flex justify-between">
              <span className="text-gray-400">Memory DB Path</span>
              <span className="text-gray-200 text-xs font-mono">{settings?.memory_db_path?.split('/').pop() || '...'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Agent Loop Max Steps</span>
              <span className="text-gray-200">20</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Tool Timeout</span>
              <span className="text-gray-200">Nmap: 300s, Web: 10s</span>
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="lg:col-span-2">
          {message && (
            <div className={`mb-4 p-4 rounded-lg text-sm ${message.includes('Error') ? 'bg-red-500/10 text-red-400 border border-red-500/30' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'}`}>
              {message}
            </div>
          )}
          <button
            type="submit"
            disabled={saving}
            className="w-full py-3 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 text-white font-semibold rounded-xl transition-colors"
          >
            {saving ? 'Saving...' : '💾 Save Settings'}
          </button>
        </div>
      </form>
    </div>
  );
}
