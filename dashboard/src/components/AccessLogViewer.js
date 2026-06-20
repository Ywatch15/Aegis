"use client";

import { useState, useEffect, useCallback } from "react";

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:5000";

const PAGE_SIZE = 100;

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
  DELETE: "text-threat-high",
};

function statusColor(code) {
  const n = Number(code);
  if (n === 200) return "text-threat-low";
  if (n === 403) return "text-threat-high";
  if (n === 429) return "text-threat-medium";
  if (n === 500) return "text-threat-error";
  return "text-text-secondary";
}

// ── Component ────────────────────────────────────────────────

export default function AccessLogViewer() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);

  // Filters
  const [methodFilter, setMethodFilter] = useState("");
  const [ipFilter, setIpFilter] = useState("");

  // ── Fetch ────────────────────────────────────────────────

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("limit", String(PAGE_SIZE));
      params.set("offset", String(offset));
      if (methodFilter) params.set("method", methodFilter);
      if (ipFilter.trim()) params.set("ip_address", ipFilter.trim());

      const res = await fetch(
        `${GATEWAY_URL}/api/admin/access-log?${params.toString()}`
      );
      if (!res.ok) throw new Error(res.statusText);
      const json = await res.json();
      const items = Array.isArray(json.data) ? json.data : [];
      setLogs(items);
      setHasMore(items.length >= PAGE_SIZE);
    } catch {
      setLogs([]);
      setHasMore(false);
    } finally {
      setLoading(false);
    }
  }, [offset, methodFilter, ipFilter]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Reset offset when filters change
  useEffect(() => {
    setOffset(0);
  }, [methodFilter, ipFilter]);

  // ── Pagination ───────────────────────────────────────────

  const handlePrev = () => {
    setOffset((prev) => Math.max(0, prev - PAGE_SIZE));
  };

  const handleNext = () => {
    setOffset((prev) => prev + PAGE_SIZE);
  };

  const handleRefresh = () => {
    fetchLogs();
  };

  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  // ── Render ───────────────────────────────────────────────

  return (
    <div className="overflow-hidden">
      {/* ── Filter Bar ────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-aegis-border bg-aegis-panel/50">
        <div className="flex flex-col min-w-0">
          <label
            htmlFor="access-log-method-filter"
            className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
          >
            Method
          </label>
          <select
            id="access-log-method-filter"
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 focus:border-aegis-glow/50 focus:outline-none appearance-none w-28"
          >
            <option value="">All</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>
        </div>

        <div className="flex flex-col min-w-0">
          <label
            htmlFor="access-log-ip-filter"
            className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
          >
            IP Address
          </label>
          <input
            id="access-log-ip-filter"
            type="text"
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
            placeholder="Filter by IP"
            className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 w-40 focus:border-aegis-glow/50 focus:outline-none"
          />
        </div>

        <div className="flex flex-col min-w-0">
          <span className="text-[10px] text-transparent mb-1 select-none">
            &nbsp;
          </span>
          <button
            id="access-log-refresh-btn"
            onClick={handleRefresh}
            className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 hover:border-aegis-border-light transition-colors flex items-center gap-1.5"
          >
            <svg
              className="w-3.5 h-3.5"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            Refresh
          </button>
        </div>
      </div>

      {/* ── Table ─────────────────────────────────────────── */}
      {loading ? (
        <div className="p-12 text-center">
          <span className="text-text-muted font-mono text-sm">Loading...</span>
        </div>
      ) : logs.length === 0 ? (
        <div className="p-12 text-center space-y-2">
          <p className="text-text-muted font-mono text-sm">
            No access logs found
          </p>
          <p className="text-text-dim font-mono text-xs">
            Enable LOG_ALL_REQUESTS=true to log clean traffic
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-aegis-panel">
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Time
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  IP
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Method
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Path
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Status
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Latency
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Fingerprint
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Country
                </th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, idx) => {
                const method = (
                  log.method ||
                  log.request_method ||
                  "GET"
                ).toUpperCase();
                const status = log.status_code || log.status || "—";
                const latency =
                  log.latency_ms ?? log.latency ?? log.response_time ?? null;
                const fingerprint =
                  log.fingerprint || log.browser_fingerprint || "";
                const country =
                  log.country_code || log.country || "";
                const ip =
                  log.ip_address || log.source_ip || log.ip || "—";
                const path =
                  log.request_path || log.path || "—";
                const timestamp =
                  log.created_at || log.timestamp || null;

                return (
                  <tr
                    key={`${ip}-${idx}`}
                    className="border-b border-aegis-border hover:bg-aegis-panel/50 transition-colors"
                  >
                    {/* Time */}
                    <td className="font-mono text-text-muted text-xs px-4 py-2.5 whitespace-nowrap">
                      {timestamp ? formatTime(timestamp) : "—"}
                    </td>

                    {/* IP */}
                    <td className="font-mono text-cyber-blue text-sm px-4 py-2.5 whitespace-nowrap">
                      {ip}
                    </td>

                    {/* Method */}
                    <td
                      className={`font-mono text-xs px-4 py-2.5 whitespace-nowrap ${
                        METHOD_COLORS[method] || "text-text-secondary"
                      }`}
                    >
                      {method}
                    </td>

                    {/* Path */}
                    <td
                      className="font-mono text-text-primary text-sm px-4 py-2.5 truncate max-w-[200px]"
                      title={path}
                    >
                      {path}
                    </td>

                    {/* Status */}
                    <td
                      className={`font-mono text-sm px-4 py-2.5 whitespace-nowrap ${statusColor(
                        status
                      )}`}
                    >
                      {status}
                    </td>

                    {/* Latency */}
                    <td className="font-mono text-xs text-text-muted px-4 py-2.5 whitespace-nowrap">
                      {latency !== null ? `${latency}ms` : "—"}
                    </td>

                    {/* Fingerprint */}
                    <td
                      className="font-mono text-xs text-text-dim px-4 py-2.5 whitespace-nowrap"
                      title={fingerprint}
                    >
                      {fingerprint
                        ? fingerprint.substring(0, 8)
                        : "—"}
                    </td>

                    {/* Country */}
                    <td className="text-sm px-4 py-2.5 whitespace-nowrap">
                      {country || "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Pagination ────────────────────────────────────── */}
      {!loading && logs.length > 0 && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-aegis-border bg-aegis-panel/50">
          <button
            id="access-log-prev-btn"
            onClick={handlePrev}
            disabled={offset === 0}
            className="font-mono text-xs text-text-muted hover:text-text-primary border border-aegis-border px-3 py-1.5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← Prev
          </button>

          <span className="font-mono text-xs text-text-dim">
            Page {currentPage}
          </span>

          <button
            id="access-log-next-btn"
            onClick={handleNext}
            disabled={!hasMore}
            className="font-mono text-xs text-text-muted hover:text-text-primary border border-aegis-border px-3 py-1.5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
