"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { createClient } from "@/lib/supabaseClient";

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:5000";
const MAX_DISPLAY = 100;
const POLL_INTERVAL = 5000;

// ── Helpers ──────────────────────────────────────────────────

function formatTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return "--:--:--";
  }
}

const METHOD_COLORS = {
  GET: "text-threat-low",
  POST: "text-aegis-glow",
  PUT: "text-cyber-blue",
  PATCH: "text-cyber-purple",
  DELETE: "text-threat-high",
  OPTIONS: "text-text-muted",
  HEAD: "text-text-muted",
};

const TYPE_COLORS = {
  SQLI: "text-threat-high",
  SQL_INJECTION: "text-threat-high",
  XSS: "text-threat-medium",
  PATH_TRAVERSAL: "text-cyber-purple",
  RATE_LIMIT: "text-threat-medium",
  CMD_INJECTION: "text-cyber-teal",
  COMMAND_INJECTION: "text-cyber-teal",
};

function severityClasses(severity) {
  const s = (severity || "").toUpperCase();
  switch (s) {
    case "HIGH":
    case "CRITICAL":
      return "bg-threat-high/20 text-threat-high border border-threat-high/30 severity-high";
    case "MEDIUM":
      return "bg-threat-medium/20 text-threat-medium border border-threat-medium/30 severity-medium";
    case "LOW":
      return "bg-threat-low/20 text-threat-low border border-threat-low/30";
    case "PENDING":
      return "bg-threat-pending/20 text-threat-pending border border-threat-pending/30 severity-pending";
    case "ERROR":
      return "bg-threat-error/20 text-threat-error border border-threat-error/30";
    default:
      return "bg-aegis-panel text-text-muted border border-aegis-border";
  }
}

// ── Component ────────────────────────────────────────────────

export default function RealTimeLogStream({
  initialIncidents = [],
  onIncidentClick,
  onConnectionChange,
}) {
  const [incidents, setIncidents] = useState(initialIncidents);
  const [newIds, setNewIds] = useState(new Set());
  const tableRef = useRef(null);
  const timeoutRef = useRef(null);

  // Mark a row as "new" for animation, then remove after 600ms
  const markNew = useCallback((id) => {
    setNewIds((prev) => new Set(prev).add(id));
    setTimeout(() => {
      setNewIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }, 600);
  }, []);

  // Prepend an incident and cap at MAX_DISPLAY
  const addIncident = useCallback(
    (incident) => {
      setIncidents((prev) => {
        const exists = prev.some((i) => i.id === incident.id);
        if (exists) {
          return prev.map((i) => (i.id === incident.id ? { ...i, ...incident } : i));
        }
        const next = [incident, ...prev].slice(0, MAX_DISPLAY);
        return next;
      });
      markNew(incident.id);
    },
    [markNew]
  );

  useEffect(() => {
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
    const useRealtime = supabaseUrl.length > 0;

    let channel = null;
    let pollTimer = null;

    if (useRealtime) {
      // ── Supabase Realtime ───────────────────────────────
      const supabase = createClient();
      channel = supabase
        .channel("log-stream")
        .on(
          "postgres_changes",
          { event: "INSERT", schema: "public", table: "security_incidents" },
          (payload) => {
            addIncident(payload.new);
          }
        )
        .on(
          "postgres_changes",
          { event: "UPDATE", schema: "public", table: "security_incidents" },
          (payload) => {
            setIncidents((prev) =>
              prev.map((i) =>
                i.id === payload.new.id ? { ...i, ...payload.new } : i
              )
            );
          }
        )
        .subscribe((status) => {
          onConnectionChange?.(status === "SUBSCRIBED");
        });
    } else {
      // ── Polling fallback ────────────────────────────────
      let knownIds = new Set(initialIncidents.map((i) => i.id));

      const poll = async () => {
        try {
          const res = await fetch(`${GATEWAY_URL}/api/incidents?limit=50`);
          if (!res.ok) throw new Error(res.statusText);
          const data = await res.json();
          const items = Array.isArray(data) ? data : data.data || data.incidents || [];

          // Detect new entries
          items.forEach((item) => {
            if (!knownIds.has(item.id)) {
              knownIds.add(item.id);
              markNew(item.id);
            }
          });

          setIncidents(items.slice(0, MAX_DISPLAY));
          onConnectionChange?.(true);
        } catch {
          onConnectionChange?.(false);
        }
      };

      poll();
      pollTimer = setInterval(poll, POLL_INTERVAL);
    }

    return () => {
      if (channel) {
        const supabase = createClient();
        supabase.removeChannel(channel);
      }
      if (pollTimer) clearInterval(pollTimer);
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Render ─────────────────────────────────────────────────

  if (incidents.length === 0) {
    return (
      <div className="p-12 text-center">
        <p className="text-text-muted font-mono text-sm">
          No incidents detected — system nominal
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden">
      <div className="overflow-x-auto" ref={tableRef}>
        <table className="w-full text-left">
          <thead>
            <tr className="bg-aegis-panel">
              <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                Time
              </th>
              <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                IP Address
              </th>
              <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                Method
              </th>
              <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                Path
              </th>
              <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                Type
              </th>
              <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                Severity
              </th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((incident) => {
              const isNew = newIds.has(incident.id);
              const method = (incident.request_method || incident.method || "GET").toUpperCase();
              const type = (
                incident.violation_type ||
                incident.type ||
                ""
              ).toUpperCase();
              const severity = (
                incident.severity_score ||
                incident.severity ||
                ""
              ).toUpperCase();

              return (
                <tr
                  key={incident.id}
                  className={`border-b border-aegis-border hover:bg-aegis-panel/50 cursor-pointer transition-colors ${
                    isNew ? "log-row-new" : ""
                  }`}
                  onClick={() => onIncidentClick?.(incident)}
                >
                  <td className="font-mono text-text-muted text-xs px-4 py-2.5 whitespace-nowrap">
                    {formatTime(incident.created_at || incident.timestamp)}
                  </td>
                  <td className="font-mono text-cyber-blue text-sm px-4 py-2.5 whitespace-nowrap">
                    {incident.ip_address || incident.source_ip || incident.ip || "—"}
                  </td>
                  <td
                    className={`font-mono text-xs px-4 py-2.5 whitespace-nowrap ${
                      METHOD_COLORS[method] || "text-text-secondary"
                    }`}
                  >
                    {method}
                  </td>
                  <td className="font-mono text-text-primary text-sm px-4 py-2.5 truncate max-w-[200px]">
                    {incident.request_path || incident.path || "—"}
                  </td>
                  <td
                    className={`font-mono text-xs uppercase px-4 py-2.5 whitespace-nowrap ${
                      TYPE_COLORS[type] || "text-text-secondary"
                    }`}
                  >
                    {type || "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-block font-mono text-xs px-2 py-0.5 ${severityClasses(
                        severity
                      )}`}
                    >
                      {severity || "—"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
