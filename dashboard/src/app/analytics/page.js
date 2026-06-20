"use client";

import { useState, useEffect, useMemo } from "react";
import nextDynamic from "next/dynamic";

// Lazy-load Recharts to reduce initial bundle
const AreaChart = nextDynamic(
  () => import("recharts").then((m) => m.AreaChart),
  { ssr: false }
);
const Area = nextDynamic(() => import("recharts").then((m) => m.Area), {
  ssr: false,
});
const XAxis = nextDynamic(() => import("recharts").then((m) => m.XAxis), {
  ssr: false,
});
const YAxis = nextDynamic(() => import("recharts").then((m) => m.YAxis), {
  ssr: false,
});
const Tooltip = nextDynamic(() => import("recharts").then((m) => m.Tooltip), {
  ssr: false,
});
const ResponsiveContainer = nextDynamic(
  () => import("recharts").then((m) => m.ResponsiveContainer),
  { ssr: false }
);
const PieChart = nextDynamic(() => import("recharts").then((m) => m.PieChart), {
  ssr: false,
});
const Pie = nextDynamic(() => import("recharts").then((m) => m.Pie), {
  ssr: false,
});
const Cell = nextDynamic(() => import("recharts").then((m) => m.Cell), {
  ssr: false,
});
const BarChart = nextDynamic(() => import("recharts").then((m) => m.BarChart), {
  ssr: false,
});
const Bar = nextDynamic(() => import("recharts").then((m) => m.Bar), {
  ssr: false,
});

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:5000";

const TIME_RANGES = [
  { label: "1H", hours: 1 },
  { label: "6H", hours: 6 },
  { label: "24H", hours: 24 },
  { label: "7D", hours: 168 },
];

const VIOLATION_COLORS = {
  SQLI: "#ef4444",
  XSS: "#f59e0b",
  PATH_TRAVERSAL: "#a855f7",
  CMD_INJECTION: "#2dd4bf",
  RATE_LIMIT: "#6366f1",
};

const SEVERITY_COLORS = {
  HIGH: "#ef4444",
  MEDIUM: "#f59e0b",
  LOW: "#22c55e",
  PENDING: "#6366f1",
  ERROR: "#9333ea",
};

function exportCSV(incidents) {
  if (incidents.length === 0) return;
  const headers = ['id','created_at','ip_address','request_method','request_path','violation_type','severity_score','threat_summary','country','city','fingerprint'];
  const rows = incidents.map(i => headers.map(h => {
    const val = String(i[h] ?? '').replace(/"/g, '""');
    return `"${val}"`;
  }).join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `aegis-incidents-${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AnalyticsPage() {
  const [incidents, setIncidents] = useState([]);
  const [selectedRange, setSelectedRange] = useState(24);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchIncidents = async () => {
      setIsLoading(true);
      try {
        const res = await fetch(`${GATEWAY_URL}/api/incidents?limit=500`);
        if (res.ok) {
          const { data } = await res.json();
          setIncidents(data || []);
        }
      } catch {
        // Gateway may not be running
      } finally {
        setIsLoading(false);
      }
    };
    fetchIncidents();
  }, []);

  // Filter by time range
  const filteredIncidents = useMemo(() => {
    const cutoff = Date.now() - selectedRange * 60 * 60 * 1000;
    return incidents.filter(
      (i) => new Date(i.created_at).getTime() > cutoff
    );
  }, [incidents, selectedRange]);

  // Incidents over time (bucketed)
  const timeSeriesData = useMemo(() => {
    const bucketCount = selectedRange <= 1 ? 12 : selectedRange <= 6 ? 24 : selectedRange <= 24 ? 24 : 28;
    const bucketSize = (selectedRange * 60 * 60 * 1000) / bucketCount;
    const now = Date.now();
    const buckets = [];

    for (let i = bucketCount - 1; i >= 0; i--) {
      const start = now - (i + 1) * bucketSize;
      const end = now - i * bucketSize;
      const count = filteredIncidents.filter((inc) => {
        const t = new Date(inc.created_at).getTime();
        return t >= start && t < end;
      }).length;

      const label = new Date(end).toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });

      buckets.push({ time: label, incidents: count });
    }

    return buckets;
  }, [filteredIncidents, selectedRange]);

  // Threat type distribution
  const typeDistribution = useMemo(() => {
    const counts = {};
    filteredIncidents.forEach((i) => {
      counts[i.violation_type] = (counts[i.violation_type] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({
      name,
      value,
    }));
  }, [filteredIncidents]);

  // Severity breakdown
  const severityBreakdown = useMemo(() => {
    const counts = {};
    filteredIncidents.forEach((i) => {
      const s = i.severity_score || "PENDING";
      counts[s] = (counts[s] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({
      name,
      value,
    }));
  }, [filteredIncidents]);

  // Top attacked paths
  const topPaths = useMemo(() => {
    const counts = {};
    filteredIncidents.forEach((i) => {
      counts[i.request_path] = (counts[i.request_path] || 0) + 1;
    });
    return Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([path, count]) => ({ path, count }));
  }, [filteredIncidents]);

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-aegis-panel border border-aegis-border p-3">
          <p className="font-mono text-xs text-text-muted">{label}</p>
          <p className="font-mono text-sm text-cyber-blue">
            {payload[0].value} incidents
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="min-h-screen bg-aegis-bg bg-hex-grid">
      {/* ── Header ───────────────────────────────────────── */}
      <header className="border-b border-aegis-border bg-aegis-surface/80 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <svg
              className="w-8 h-8 text-aegis-glow"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <path d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11.25C17.25 23.15 21 18.25 21 13V7l-9-5z" />
              <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <div>
              <h1 className="text-lg font-semibold text-text-primary tracking-tight">
                Aegis<span className="text-aegis-glow">API</span>
              </h1>
              <p className="text-[10px] text-text-muted uppercase tracking-[0.2em]">
                Threat Analytics
              </p>
            </div>
          </div>

          <nav className="flex items-center gap-1">
            <a
              href="/"
              className="px-3 py-1.5 text-xs font-medium text-text-muted hover:text-text-secondary transition-colors"
            >
              MONITOR
            </a>
            <a
              href="/analytics"
              className="px-3 py-1.5 text-xs font-medium text-cyber-blue border border-cyber-blue/30 bg-cyber-blue/5 hover:bg-cyber-blue/10 transition-colors"
            >
              ANALYTICS
            </a>
            <a
              href="/admin"
              className="px-3 py-1.5 text-xs font-medium text-text-muted hover:text-text-secondary transition-colors"
            >
              ADMIN
            </a>
          </nav>
        </div>
      </header>

      {/* ── Main Content ─────────────────────────────────── */}
      <main className="max-w-[1600px] mx-auto px-6 py-6 space-y-6">
        {/* Time Range Selector */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className="text-sm font-medium text-text-primary">
            Historical Threat Analysis
          </h2>
          <div className="flex items-center gap-1">
            {TIME_RANGES.map((range) => (
              <button
                key={range.label}
                onClick={() => setSelectedRange(range.hours)}
                className={`px-3 py-1 text-xs font-mono transition-colors ${
                  selectedRange === range.hours
                    ? "bg-aegis-glow/20 text-aegis-glow border border-aegis-glow/30"
                    : "text-text-muted hover:text-text-secondary border border-transparent"
                }`}
              >
                {range.label}
              </button>
            ))}
            <button
              id="csv-export-btn"
              onClick={() => exportCSV(filteredIncidents)}
              disabled={filteredIncidents.length === 0}
              className="ml-3 px-3 py-1 text-xs font-mono text-cyber-green border border-cyber-green/30 bg-cyber-green/10 hover:bg-cyber-green/20 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
            >
              ↓ CSV
            </button>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 bg-aegis-glow animate-pulse" />
              <span className="font-mono text-sm text-text-muted">
                Loading analytics data...
              </span>
            </div>
          </div>
        ) : (
          <>
            {/* Incidents Over Time */}
            <div className="border border-aegis-border bg-aegis-surface p-4">
              <h3 className="text-xs text-text-muted uppercase tracking-wider font-sans mb-4">
                Incidents Over Time
              </h3>
              <div className="h-[250px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeSeriesData}>
                    <defs>
                      <linearGradient
                        id="incidentGradient"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor="#3b82f6"
                          stopOpacity={0.3}
                        />
                        <stop
                          offset="100%"
                          stopColor="#3b82f6"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="time"
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 10 }}
                    />
                    <YAxis
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 10 }}
                      width={30}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Area
                      type="monotone"
                      dataKey="incidents"
                      stroke="#3b82f6"
                      strokeWidth={2}
                      fill="url(#incidentGradient)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Threat Type Distribution */}
              <div className="border border-aegis-border bg-aegis-surface p-4">
                <h3 className="text-xs text-text-muted uppercase tracking-wider font-sans mb-4">
                  Threat Type Distribution
                </h3>
                {typeDistribution.length > 0 ? (
                  <div className="h-[250px] flex items-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={typeDistribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={90}
                          paddingAngle={2}
                          dataKey="value"
                        >
                          {typeDistribution.map((entry, idx) => (
                            <Cell
                              key={idx}
                              fill={
                                VIOLATION_COLORS[entry.name] || "#64748b"
                              }
                            />
                          ))}
                        </Pie>
                        <Tooltip
                          content={({ payload }) => {
                            if (payload && payload.length) {
                              return (
                                <div className="bg-aegis-panel border border-aegis-border p-2">
                                  <p className="font-mono text-xs text-text-primary">
                                    {payload[0].name}: {payload[0].value}
                                  </p>
                                </div>
                              );
                            }
                            return null;
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="space-y-2 ml-4">
                      {typeDistribution.map((item) => (
                        <div
                          key={item.name}
                          className="flex items-center gap-2"
                        >
                          <div
                            className="w-2.5 h-2.5"
                            style={{
                              backgroundColor:
                                VIOLATION_COLORS[item.name] || "#64748b",
                            }}
                          />
                          <span className="font-mono text-xs text-text-secondary">
                            {item.name}
                          </span>
                          <span className="font-mono text-xs text-text-muted ml-auto">
                            {item.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="h-[250px] flex items-center justify-center">
                    <span className="font-mono text-sm text-text-muted">
                      No data in selected range
                    </span>
                  </div>
                )}
              </div>

              {/* Severity Breakdown */}
              <div className="border border-aegis-border bg-aegis-surface p-4">
                <h3 className="text-xs text-text-muted uppercase tracking-wider font-sans mb-4">
                  Severity Breakdown
                </h3>
                {severityBreakdown.length > 0 ? (
                  <div className="h-[250px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={severityBreakdown} layout="vertical">
                        <XAxis
                          type="number"
                          axisLine={false}
                          tickLine={false}
                          tick={{ fontSize: 10 }}
                        />
                        <YAxis
                          type="category"
                          dataKey="name"
                          axisLine={false}
                          tickLine={false}
                          tick={{ fontSize: 11 }}
                          width={70}
                        />
                        <Tooltip
                          content={({ payload }) => {
                            if (payload && payload.length) {
                              return (
                                <div className="bg-aegis-panel border border-aegis-border p-2">
                                  <p className="font-mono text-xs text-text-primary">
                                    {payload[0].payload.name}:{" "}
                                    {payload[0].value}
                                  </p>
                                </div>
                              );
                            }
                            return null;
                          }}
                        />
                        <Bar dataKey="value" radius={0}>
                          {severityBreakdown.map((entry, idx) => (
                            <Cell
                              key={idx}
                              fill={
                                SEVERITY_COLORS[entry.name] || "#64748b"
                              }
                            />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="h-[250px] flex items-center justify-center">
                    <span className="font-mono text-sm text-text-muted">
                      No data in selected range
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Top Attacked Paths */}
            <div className="border border-aegis-border bg-aegis-surface">
              <div className="px-4 py-3 border-b border-aegis-border">
                <h3 className="text-xs text-text-muted uppercase tracking-wider font-sans">
                  Most Targeted Endpoints
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="bg-aegis-panel">
                      <th className="px-4 py-2 text-left text-[10px] text-text-muted uppercase tracking-wider font-mono font-normal">
                        Rank
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] text-text-muted uppercase tracking-wider font-mono font-normal">
                        Path
                      </th>
                      <th className="px-4 py-2 text-right text-[10px] text-text-muted uppercase tracking-wider font-mono font-normal">
                        Hits
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {topPaths.length > 0 ? (
                      topPaths.map((item, idx) => (
                        <tr
                          key={item.path}
                          className="border-b border-aegis-border last:border-b-0 hover:bg-aegis-panel/50 transition-colors"
                        >
                          <td className="px-4 py-2 font-mono text-xs text-text-muted">
                            {String(idx + 1).padStart(2, "0")}
                          </td>
                          <td className="px-4 py-2 font-mono text-sm text-cyber-blue">
                            {item.path}
                          </td>
                          <td className="px-4 py-2 font-mono text-sm text-text-primary text-right">
                            {item.count}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td
                          colSpan={3}
                          className="px-4 py-8 text-center font-mono text-sm text-text-muted"
                        >
                          No attack data in selected range
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
