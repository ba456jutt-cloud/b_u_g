"use client";
import { useEffect, useRef, useState } from "react";
import { useAgentActivity, ActivityEvent } from "@/hooks/useAgentActivity";

// ── Event type config ─────────────────────────────────────────────────────────
const EVENT_CONFIG: Record<
  string,
  { icon: string; color: string; bg: string; label: string }
> = {
  connected:    { icon: "🔌", color: "#22c55e", bg: "#052e16", label: "Connected" },
  tool_start:   { icon: "⚙️", color: "#f59e0b", bg: "#1c1400", label: "Tool Running" },
  tool_output:  { icon: "📤", color: "#60a5fa", bg: "#0c1a2e", label: "Tool Output" },
  tool_error:   { icon: "❌", color: "#f87171", bg: "#1f0707", label: "Tool Error" },
  agent_thought:{ icon: "🧠", color: "#a78bfa", bg: "#130d1f", label: "Thinking" },
  agent_done:   { icon: "✅", color: "#34d399", bg: "#042f1e", label: "Agent Done" },
  agent_step:   { icon: "🔄", color: "#94a3b8", bg: "#0f1923", label: "Step" },
};

// ── Single event row ──────────────────────────────────────────────────────────
function EventRow({ event, index }: { event: ActivityEvent; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = EVENT_CONFIG[event.type] ?? {
    icon: "ℹ️", color: "#94a3b8", bg: "#111827", label: event.type,
  };

  const time = new Date(event.timestamp).toLocaleTimeString("en-US", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });

  // Main summary line
  let summary = "";
  if (event.type === "tool_start") {
    const argsStr = event.args
      ? Object.entries(event.args)
          .slice(0, 2)
          .map(([k, v]) => `${k}=${String(v).slice(0, 40)}`)
          .join(", ")
      : "";
    summary = `${event.tool}(${argsStr})`;
  } else if (event.type === "tool_output") {
    summary = `${event.tool} → ${(event.output ?? "").slice(0, 80).replace(/\n/g, " ")}`;
  } else if (event.type === "tool_error") {
    summary = `${event.tool} failed: ${(event.error ?? "").slice(0, 80)}`;
  } else if (event.type === "agent_thought") {
    summary = (event.thought ?? "").slice(0, 100).replace(/\n/g, " ");
  } else if (event.type === "agent_done") {
    summary = (event.result ?? "").slice(0, 100).replace(/\n/g, " ");
  } else if (event.type === "connected") {
    summary = event.message ?? "Stream connected";
  } else {
    summary = JSON.stringify(event).slice(0, 100);
  }

  // Expandable content
  const hasDetail =
    (event.output && event.output.length > 0) ||
    (event.thought && event.thought.length > 0) ||
    (event.result && event.result.length > 0) ||
    (event.args && Object.keys(event.args).length > 0) ||
    (event.error && event.error.length > 0);

  return (
    <div
      style={{
        borderLeft: `3px solid ${cfg.color}`,
        background: index % 2 === 0 ? cfg.bg : "transparent",
        padding: "6px 10px",
        marginBottom: "2px",
        borderRadius: "0 6px 6px 0",
        cursor: hasDetail ? "pointer" : "default",
        transition: "background 0.15s",
      }}
      onClick={() => hasDetail && setExpanded(!expanded)}
    >
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span style={{ fontSize: "13px", lineHeight: 1 }}>{cfg.icon}</span>
        <span style={{ color: "#64748b", fontSize: "10px", fontFamily: "monospace", flexShrink: 0 }}>
          {time}
        </span>
        {event.agent && (
          <span style={{
            background: "#1e293b", color: "#7dd3fc",
            padding: "1px 6px", borderRadius: "4px",
            fontSize: "10px", fontWeight: 600, flexShrink: 0,
          }}>
            {event.agent.replace("Agent", "").trim()}
          </span>
        )}
        <span style={{
          color: cfg.color, fontSize: "12px", fontFamily: "monospace",
          flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }}>
          {summary}
        </span>
        {hasDetail && (
          <span style={{ color: "#475569", fontSize: "10px", flexShrink: 0 }}>
            {expanded ? "▲" : "▼"}
          </span>
        )}
      </div>

      {/* Expanded detail */}
      {expanded && hasDetail && (
        <div style={{
          marginTop: "6px", padding: "8px",
          background: "#0a0e1a", borderRadius: "4px",
          fontFamily: "monospace", fontSize: "11px",
          color: "#cbd5e1", whiteSpace: "pre-wrap",
          wordBreak: "break-all", maxHeight: "250px",
          overflowY: "auto", lineHeight: "1.5",
        }}>
          {event.type === "tool_start" && event.args && (
            <div>
              <span style={{ color: "#f59e0b" }}>▶ Tool: </span>
              <span style={{ color: "#fbbf24" }}>{event.tool}</span>
              {"\n"}
              <span style={{ color: "#f59e0b" }}>▶ Args: </span>
              {JSON.stringify(event.args, null, 2)}
            </div>
          )}
          {event.output && (
            <div>
              <span style={{ color: "#60a5fa" }}>◀ Output:{"\n"}</span>
              {event.output}
            </div>
          )}
          {event.thought && (
            <div>
              <span style={{ color: "#a78bfa" }}>💭 Thought:{"\n"}</span>
              {event.thought}
            </div>
          )}
          {event.result && (
            <div>
              <span style={{ color: "#34d399" }}>✅ Result:{"\n"}</span>
              {event.result}
            </div>
          )}
          {event.error && (
            <div>
              <span style={{ color: "#f87171" }}>⚠ Error:{"\n"}</span>
              {event.error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Stats bar ─────────────────────────────────────────────────────────────────
function StatsBar({ events }: { events: ActivityEvent[] }) {
  const counts = events.reduce(
    (acc, e) => {
      if (e.type === "tool_start") acc.tools++;
      else if (e.type === "tool_error") acc.errors++;
      else if (e.type === "agent_thought") acc.thoughts++;
      else if (e.type === "agent_done") acc.done++;
      return acc;
    },
    { tools: 0, errors: 0, thoughts: 0, done: 0 }
  );

  return (
    <div style={{ display: "flex", gap: "8px", padding: "6px 10px", flexWrap: "wrap" }}>
      {[
        { label: "Tools", value: counts.tools, color: "#f59e0b" },
        { label: "Thoughts", value: counts.thoughts, color: "#a78bfa" },
        { label: "Done", value: counts.done, color: "#34d399" },
        { label: "Errors", value: counts.errors, color: "#f87171" },
      ].map(({ label, value, color }) => (
        <div key={label} style={{
          display: "flex", alignItems: "center", gap: "4px",
          background: "#1e293b", padding: "2px 8px", borderRadius: "9999px",
        }}>
          <span style={{ color, fontWeight: 700, fontSize: "11px" }}>{value}</span>
          <span style={{ color: "#64748b", fontSize: "10px" }}>{label}</span>
        </div>
      ))}
    </div>
  );
}

// ── Filter tabs ───────────────────────────────────────────────────────────────
const FILTERS = [
  { key: "all", label: "All" },
  { key: "tool_start", label: "⚙ Tools" },
  { key: "tool_output", label: "📤 Output" },
  { key: "agent_thought", label: "🧠 Thoughts" },
  { key: "tool_error", label: "❌ Errors" },
];

// ── Main Panel ────────────────────────────────────────────────────────────────
export default function AgentLiveActivity() {
  const { events, isConnected, clearEvents } = useAgentActivity();
  const [filter, setFilter] = useState("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  const filtered =
    filter === "all"
      ? events
      : events.filter((e) => e.type === filter);

  return (
    <div style={{
      display: "flex", flexDirection: "column",
      height: "100%", background: "#030712",
      borderLeft: "1px solid #1e293b",
      fontFamily: "'Inter', 'JetBrains Mono', monospace",
    }}>
      {/* Header */}
      <div style={{
        padding: "12px 14px 8px",
        borderBottom: "1px solid #1e293b",
        background: "linear-gradient(180deg, #0f172a 0%, #030712 100%)",
      }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "16px" }}>📡</span>
            <span style={{ color: "#f1f5f9", fontWeight: 700, fontSize: "13px", letterSpacing: "0.02em" }}>
              Agent Activity
            </span>
            {/* Connection status dot */}
            <div style={{
              width: "8px", height: "8px", borderRadius: "50%",
              background: isConnected ? "#22c55e" : "#f87171",
              boxShadow: isConnected ? "0 0 6px #22c55e" : "0 0 6px #f87171",
              animation: isConnected ? "pulse 2s infinite" : "none",
            }} />
            <span style={{
              fontSize: "10px",
              color: isConnected ? "#22c55e" : "#f87171",
            }}>
              {isConnected ? "LIVE" : "Reconnecting..."}
            </span>
          </div>
          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
            {/* Auto-scroll toggle */}
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              title="Toggle auto-scroll"
              style={{
                background: autoScroll ? "#1d4ed8" : "#1e293b",
                border: "none", borderRadius: "4px",
                color: "#94a3b8", fontSize: "10px", cursor: "pointer",
                padding: "3px 7px",
              }}
            >
              {autoScroll ? "⬇ Auto" : "⬇ Manual"}
            </button>
            {/* Clear button */}
            <button
              onClick={clearEvents}
              title="Clear events"
              style={{
                background: "#1e293b", border: "none", borderRadius: "4px",
                color: "#94a3b8", fontSize: "11px", cursor: "pointer",
                padding: "3px 7px",
              }}
            >
              🗑
            </button>
          </div>
        </div>

        {/* Stats */}
        <StatsBar events={events} />

        {/* Filter tabs */}
        <div style={{ display: "flex", gap: "4px", marginTop: "6px", flexWrap: "wrap" }}>
          {FILTERS.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              style={{
                background: filter === f.key ? "#1d4ed8" : "#1e293b",
                border: `1px solid ${filter === f.key ? "#3b82f6" : "#334155"}`,
                borderRadius: "4px", color: filter === f.key ? "#eff6ff" : "#64748b",
                fontSize: "10px", cursor: "pointer", padding: "2px 7px",
                fontWeight: filter === f.key ? 600 : 400,
                transition: "all 0.15s",
              }}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Event stream */}
      <div
        ref={scrollRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
          setAutoScroll(atBottom);
        }}
        style={{
          flex: 1, overflowY: "auto", padding: "6px 4px",
          scrollbarWidth: "thin",
          scrollbarColor: "#1e293b #030712",
        }}
      >
        {filtered.length === 0 ? (
          <div style={{
            display: "flex", flexDirection: "column", alignItems: "center",
            justifyContent: "center", height: "120px", color: "#334155",
          }}>
            <span style={{ fontSize: "28px", marginBottom: "8px" }}>📭</span>
            <span style={{ fontSize: "12px" }}>
              {isConnected ? "Waiting for agent activity..." : "Connecting to agent stream..."}
            </span>
            {!isConnected && (
              <span style={{ fontSize: "10px", color: "#1e293b", marginTop: "4px" }}>
                Make sure the backend is running on port 8000
              </span>
            )}
          </div>
        ) : (
          filtered.map((event, i) => (
            <EventRow key={i} event={event} index={i} />
          ))
        )}
      </div>

      {/* Footer — event count */}
      <div style={{
        padding: "4px 10px", borderTop: "1px solid #1e293b",
        background: "#030712", display: "flex", justifyContent: "space-between",
      }}>
        <span style={{ fontSize: "10px", color: "#334155" }}>
          {filtered.length} event{filtered.length !== 1 ? "s" : ""}
          {filter !== "all" ? ` (filtered: ${filter})` : ""}
        </span>
        <span style={{ fontSize: "10px", color: "#1e293b" }}>
          ws://localhost:8000/ws/activity
        </span>
      </div>

      {/* Pulse animation CSS */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}
