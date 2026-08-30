"use client";
import { useEffect, useRef, useState, useCallback } from "react";

export type ActivityEventType =
  | "connected"
  | "tool_start"
  | "tool_output"
  | "tool_error"
  | "agent_thought"
  | "agent_done"
  | "agent_step"
  | "pong";

export interface ActivityEvent {
  type: ActivityEventType;
  timestamp: string;
  agent?: string;
  tool?: string;
  args?: Record<string, string>;
  output?: string;
  error?: string;
  thought?: string;
  result?: string;
  step?: number;
  task_id?: string;
  message?: string;
  source?: string;
}

interface UseAgentActivityReturn {
  events: ActivityEvent[];
  isConnected: boolean;
  clearEvents: () => void;
}

const WS_URL = "ws://localhost:8000/ws/activity";
const MAX_EVENTS = 150; // Keep last 150 events in memory

export function useAgentActivity(): UseAgentActivityReturn {
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const pingRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectRef = useRef<NodeJS.Timeout | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        // Keepalive ping every 15s
        pingRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send("ping");
        }, 15000);
      };

      ws.onmessage = (e) => {
        try {
          const event: ActivityEvent = JSON.parse(e.data);
          if (event.type === "pong") return;
          setEvents((prev) => {
            const next = [...prev, event];
            return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
          });
        } catch {}
      };

      ws.onclose = () => {
        setIsConnected(false);
        if (pingRef.current) clearInterval(pingRef.current);
        // Auto-reconnect after 3 seconds
        reconnectRef.current = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      reconnectRef.current = setTimeout(connect, 3000);
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
      if (pingRef.current) clearInterval(pingRef.current);
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
    };
  }, [connect]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, isConnected, clearEvents };
}
