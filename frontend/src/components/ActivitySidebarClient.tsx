"use client";
import { useEffect, useState } from "react";
import AgentLiveActivity from "@/components/AgentLiveActivity";

/**
 * Client wrapper for AgentLiveActivity — needed because layout.tsx is a
 * Server Component in Next.js App Router, but WebSocket requires browser APIs.
 */
export default function ActivitySidebarClient() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);
  if (!mounted) return (
    <div style={{
      display: "flex", flexDirection: "column", height: "100%",
      background: "#030712", borderLeft: "1px solid #1e293b",
      alignItems: "center", justifyContent: "center",
    }}>
      <span style={{ fontSize: "24px" }}>📡</span>
      <span style={{ fontSize: "11px", color: "#334155", marginTop: "8px" }}>Loading...</span>
    </div>
  );
  return <AgentLiveActivity />;
}
