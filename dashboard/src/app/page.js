"use client";

import { useState, useEffect, useCallback } from "react";
import MetricCards from "@/components/MetricCards";
import RealTimeLogStream from "@/components/RealTimeLogStream";
import ThreatModal from "@/components/ThreatModal";

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:5000";

export default function DashboardPage() {
  const [stats, setStats] = useState({
    total: 0,
    blocked: 0,
    rate_limited: 0,
    recent_5min: 0,
  });
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [currentTime, setCurrentTime] = useState("");

  // Fetch stats periodically
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(`${GATEWAY_URL}/api/stats`);
        if (res.ok) {
          const { data } = await res.json();
          setStats(data);
        }
      } catch {
        // Gateway may not be running
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  // Live clock
  useEffect(() => {
    const updateTime = () => {
      setCurrentTime(
        new Date().toLocaleTimeString("en-US", {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleIncidentClick = useCallback((incident) => {
    setSelectedIncident(incident);
  }, []);

  const handleConnectionChange = useCallback((connected) => {
    setIsConnected(connected);
  }, []);

  return (
    <div className="min-h-screen bg-aegis-bg bg-hex-grid">
      {/* ── Header ───────────────────────────────────────── */}
      <header className="border-b border-aegis-border bg-aegis-surface/80 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {/* Shield Icon */}
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
                Security Operations Center
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            {/* Live Clock */}
            <span className="font-mono text-sm text-text-muted hidden sm:block">
              {currentTime}
            </span>

            {/* Connection Status */}
            <div className="flex items-center gap-2">
              <div
                className={
                  isConnected ? "status-dot-online" : "status-dot-offline"
                }
              />
              <span className="text-xs text-text-muted font-mono hidden sm:block">
                {isConnected ? "LIVE" : "POLL"}
              </span>
            </div>

            {/* Nav Links */}
            <nav className="flex items-center gap-1">
              <a
                href="/"
                className="px-3 py-1.5 text-xs font-medium text-cyber-blue border border-cyber-blue/30 bg-cyber-blue/5 hover:bg-cyber-blue/10 transition-colors"
              >
                MONITOR
              </a>
              <a
                href="/analytics"
                className="px-3 py-1.5 text-xs font-medium text-text-muted hover:text-text-secondary transition-colors"
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
        </div>
      </header>

      {/* ── Main Content ─────────────────────────────────── */}
      <main className="max-w-[1600px] mx-auto px-6 py-6 space-y-6">
        {/* Metric Cards */}
        <MetricCards stats={stats} isConnected={isConnected} />

        {/* Real-Time Log Stream */}
        <div className="border border-aegis-border bg-aegis-surface">
          <div className="px-4 py-3 border-b border-aegis-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <svg
                className="w-4 h-4 text-cyber-green"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
              </svg>
              <h2 className="text-sm font-medium text-text-primary">
                Live Threat Feed
              </h2>
            </div>
            <span className="text-[10px] font-mono text-text-muted uppercase tracking-wider">
              Real-time Incident Stream
            </span>
          </div>

          <RealTimeLogStream
            initialIncidents={[]}
            onIncidentClick={handleIncidentClick}
            onConnectionChange={handleConnectionChange}
          />
        </div>
      </main>

      {/* ── Threat Detail Modal ──────────────────────────── */}
      <ThreatModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />
    </div>
  );
}
