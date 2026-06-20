"use client";

import { useState, useEffect, useCallback } from "react";
import { createClient } from "@/lib/supabaseClient";

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:5000";

// ── Country flag emoji from ISO 3166-1 alpha-2/3 code ────────
function countryFlag(code) {
  if (!code || code === 'LCL' || code === '---' || code.length < 2) return '🌐';
  // Use first 2 chars for regional indicator
  const c = code.toUpperCase().substring(0, 2);
  return String.fromCodePoint(...[...c].map(ch => 0x1f1e6 + ch.charCodeAt(0) - 65));
}

// ── Helpers ──────────────────────────────────────────────────

function formatTimestamp(ts) {
  try {
    return new Date(ts).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return "—";
  }
}

function severityBadgeClasses(severity) {
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

function violationColor(type) {
  const t = (type || "").toUpperCase();
  switch (t) {
    case "SQLI":
      return "text-threat-high";
    case "XSS":
      return "text-threat-medium";
    case "PATH_TRAVERSAL":
      return "text-cyber-purple";
    case "CMD_INJECTION":
      return "text-cyber-teal";
    case "RATE_LIMIT":
      return "text-threat-medium";
    default:
      return "text-text-secondary";
  }
}

// ── Component ────────────────────────────────────────────────

export default function ThreatModal({ incident, onClose }) {
  const [liveIncident, setLiveIncident] = useState(incident);
  const [replayResult, setReplayResult] = useState(null);
  const [replayLoading, setReplayLoading] = useState(false);
  const [blockResult, setBlockResult] = useState(null);
  const [blockLoading, setBlockLoading] = useState(false);

  // Sync when parent changes the selected incident
  useEffect(() => {
    setLiveIncident(incident);
    setReplayResult(null);
    setBlockResult(null);
  }, [incident]);

  // Subscribe to real-time updates on this specific row
  useEffect(() => {
    if (!incident?.id) return;

    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";

    if (supabaseUrl) {
      const supabase = createClient();
      const channel = supabase
        .channel(`incident-${incident.id}`)
        .on(
          "postgres_changes",
          {
            event: "UPDATE",
            schema: "public",
            table: "security_incidents",
            filter: `id=eq.${incident.id}`,
          },
          (payload) => {
            setLiveIncident((prev) => ({ ...prev, ...payload.new }));
          }
        )
        .subscribe();

      return () => {
        supabase.removeChannel(channel);
      };
    } else {
      // Polling fallback — check every 3s
      const poll = async () => {
        try {
          const res = await fetch(
            `${GATEWAY_URL}/api/incidents/${incident.id}`
          );
          if (res.ok) {
            const { data } = await res.json();
            if (data) {
              setLiveIncident((prev) => ({ ...prev, ...data }));
            }
          }
        } catch {
          // ignore
        }
      };
      const timer = setInterval(poll, 3000);
      return () => clearInterval(timer);
    }
  }, [incident?.id]);

  // Close on Escape key
  useEffect(() => {
    if (!incident) return;

    const handleKeyDown = (e) => {
      if (e.key === "Escape") onClose?.();
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [incident, onClose]);

  // Replay handler
  const handleReplay = useCallback(async () => {
    if (!liveIncident) return;
    setReplayLoading(true);
    try {
      const payload = liveIncident.payload_snapshot
        ? JSON.parse(liveIncident.payload_snapshot)
        : {};
      const res = await fetch(`${GATEWAY_URL}/api/admin/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: liveIncident.request_method,
          path: liveIncident.request_path,
          payload: payload.body || payload,
        }),
      });
      const data = await res.json();
      setReplayResult(data);
    } catch (err) {
      setReplayResult({ error: err.message });
    } finally {
      setReplayLoading(false);
    }
  }, [liveIncident]);

  // Block IP handler
  const handleBlockIP = useCallback(async () => {
    if (!liveIncident?.ip_address) return;
    setBlockLoading(true);
    try {
      const res = await fetch(`${GATEWAY_URL}/api/admin/blocklist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip_address: liveIncident.ip_address,
          reason: `Blocked from incident ${liveIncident.id?.substring(0, 8)} — ${liveIncident.violation_type}`,
        }),
      });
      if (res.ok) {
        setBlockResult({ success: true });
      } else {
        const err = await res.json();
        setBlockResult({ error: err.error || 'Failed' });
      }
    } catch (err) {
      setBlockResult({ error: err.message });
    } finally {
      setBlockLoading(false);
    }
  }, [liveIncident]);

  if (!incident) return null;

  const data = liveIncident || incident;
  const severity = (data.severity_score || "PENDING").toUpperCase();
  const violationType = (data.violation_type || "UNKNOWN").toUpperCase();
  const isPending = severity === "PENDING";
  const isError = severity === "ERROR";

  return (
    <div
      className="modal-backdrop fixed inset-0 z-50 flex items-center justify-center"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose?.();
      }}
    >
      <div
        className="bg-aegis-surface border border-aegis-border max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto animate-fade-up"
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Header ──────────────────────────────────────────── */}
        <div className="px-6 py-4 border-b border-aegis-border flex items-center justify-between">
          <div className="flex items-center gap-3 min-w-0">
            <span
              className={`inline-block font-mono text-xs px-2.5 py-1 uppercase tracking-wider shrink-0 ${severityBadgeClasses(
                severity
              )}`}
            >
              {severity}
            </span>
            <span
              className={`font-mono text-xs uppercase truncate ${violationColor(
                violationType
              )}`}
            >
              {violationType}
            </span>
          </div>

          {/* Close button */}
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary transition-colors p-1 shrink-0"
            aria-label="Close modal"
          >
            <svg
              className="w-5 h-5"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* ── Content ─────────────────────────────────────────── */}
        <div className="px-6 py-5 space-y-6">
          {/* Section Label */}
          <div>
            <h3 className="text-[10px] text-text-muted uppercase tracking-wider font-sans mb-3">
              Request Information
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* IP Address */}
              <div className="min-w-0">
                <span className="text-[10px] text-text-dim uppercase tracking-widest font-sans block mb-1">
                  Source IP
                </span>
                <span className="font-mono text-sm text-cyber-blue truncate block">
                  {data.ip_address || "—"}
                </span>
              </div>

              {/* Method */}
              <div className="min-w-0">
                <span className="text-[10px] text-text-dim uppercase tracking-widest font-sans block mb-1">
                  Method
                </span>
                <span className="font-mono text-sm text-text-primary">
                  {data.request_method || "—"}
                </span>
              </div>

              {/* Path */}
              <div className="sm:col-span-2 min-w-0">
                <span className="text-[10px] text-text-dim uppercase tracking-widest font-sans block mb-1">
                  Request Path
                </span>
                <span className="font-mono text-sm text-text-primary break-all block">
                  {data.request_path || "—"}
                </span>
              </div>

              {/* Geo Location */}
              {(data.country || data.city) && (
                <div className="min-w-0">
                  <span className="text-[10px] text-text-dim uppercase tracking-widest font-sans block mb-1">
                    Origin
                  </span>
                  <span className="font-mono text-sm text-text-secondary">
                    {countryFlag(data.country)} {data.country || '—'} / {data.city || '—'}
                  </span>
                </div>
              )}

              {/* Fingerprint */}
              {data.fingerprint && (
                <div className="min-w-0">
                  <span className="text-[10px] text-text-dim uppercase tracking-widest font-sans block mb-1">
                    Fingerprint
                  </span>
                  <span className="font-mono text-xs text-text-dim">
                    {data.fingerprint}
                  </span>
                </div>
              )}

              {/* Timestamp */}
              <div className="sm:col-span-2 min-w-0">
                <span className="text-[10px] text-text-dim uppercase tracking-widest font-sans block mb-1">
                  Timestamp
                </span>
                <span className="font-mono text-xs text-text-muted">
                  {formatTimestamp(data.created_at)}
                </span>
              </div>
            </div>
          </div>

          {/* ── Payload Snapshot ───────────────────────────────── */}
          {data.payload_snapshot && (
            <div>
              <h3 className="text-[10px] text-text-muted uppercase tracking-wider font-sans mb-3">
                Captured Payload
              </h3>
              <div className="bg-aegis-bg border border-aegis-border p-3 overflow-x-auto">
                <pre className="font-mono text-sm text-threat-high whitespace-pre-wrap break-all leading-relaxed">
                  {data.payload_snapshot}
                </pre>
              </div>
            </div>
          )}

          {/* ── AI Analysis ───────────────────────────────────── */}
          <div>
            <h3 className="text-[10px] text-text-muted uppercase tracking-wider font-sans mb-3">
              AI Threat Assessment
            </h3>

            {isPending ? (
              <div className="space-y-3">
                {/* Skeleton loading */}
                <div className="bg-aegis-panel animate-pulse h-4 w-3/4" />
                <div className="bg-aegis-panel animate-pulse h-4 w-1/2" />
                <div className="bg-aegis-panel animate-pulse h-4 w-2/3" />
                <div className="flex items-center gap-2 mt-4">
                  <div className="w-2 h-2 bg-threat-pending animate-pulse" />
                  <span className="font-mono text-xs text-threat-pending">
                    Analyzing threat vector...
                  </span>
                </div>
              </div>
            ) : isError ? (
              <div className="bg-threat-error/10 border border-threat-error/30 p-3">
                <p className="font-mono text-sm text-threat-error">
                  {data.threat_summary || "Analysis failed"}
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <span
                    className={`inline-block font-mono text-sm px-3 py-1.5 uppercase tracking-wider font-bold ${severityBadgeClasses(
                      severity
                    )}`}
                  >
                    {severity} SEVERITY
                  </span>
                </div>
                <p className="font-mono text-sm text-text-secondary leading-relaxed">
                  {data.threat_summary || "No summary available."}
                </p>
              </div>
            )}
          </div>

          {/* ── Replay Result ─────────────────────────────────── */}
          {replayResult && (
            <div>
              <h3 className="text-[10px] text-text-muted uppercase tracking-wider font-sans mb-3">
                Replay Result
              </h3>
              <div className="bg-aegis-bg border border-aegis-border p-3 overflow-x-auto">
                <pre className="font-mono text-xs text-text-secondary whitespace-pre-wrap break-all leading-relaxed">
                  {JSON.stringify(replayResult, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* ── Footer ──────────────────────────────────────────── */}
        <div className="px-6 py-3 border-t border-aegis-border flex items-center justify-between flex-wrap gap-2">
          <span className="font-mono text-[10px] text-text-dim uppercase tracking-widest">
            Incident ID: {data.id?.substring(0, 8) || "—"}
          </span>
          <div className="flex items-center gap-2">
            {/* Replay Button */}
            <button
              id="replay-btn"
              onClick={handleReplay}
              disabled={replayLoading}
              className="text-xs font-mono text-cyber-blue border border-cyber-blue/30 bg-cyber-blue/10 hover:bg-cyber-blue/20 transition-colors px-3 py-1 disabled:opacity-50"
            >
              {replayLoading ? '...' : '▶ Replay'}
            </button>

            {/* Block IP Button */}
            <button
              id="block-ip-btn"
              onClick={handleBlockIP}
              disabled={blockLoading || blockResult?.success}
              className={`text-xs font-mono border transition-colors px-3 py-1 disabled:opacity-50 ${
                blockResult?.success
                  ? 'text-cyber-green border-cyber-green/30 bg-cyber-green/10'
                  : 'text-threat-high border-threat-high/30 bg-threat-high/10 hover:bg-threat-high/20'
              }`}
            >
              {blockResult?.success ? '✓ Blocked' : blockLoading ? '...' : '⊘ Block IP'}
            </button>

            {/* Dismiss */}
            <button
              onClick={onClose}
              className="text-xs font-sans text-text-muted hover:text-text-primary transition-colors px-3 py-1 border border-aegis-border hover:border-aegis-border-light"
            >
              Dismiss
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
