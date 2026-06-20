"use client";

import { useState } from "react";
import BlocklistManager from "@/components/BlocklistManager";
import WAFRuleManager from "@/components/WAFRuleManager";
import AccessLogViewer from "@/components/AccessLogViewer";

// ── Tab definitions ──────────────────────────────────────────

const TABS = [
  { key: "ip", label: "IP Management" },
  { key: "waf", label: "WAF Rules" },
  { key: "logs", label: "Access Logs" },
];

// ── Component ────────────────────────────────────────────────

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState("ip");

  return (
    <div className="min-h-screen bg-aegis-bg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* ── Header ──────────────────────────────────────── */}
        <div className="mb-6">
          <a
            href="/"
            id="admin-back-link"
            className="text-aegis-glow hover:text-aegis-glow/80 font-mono text-sm transition-colors inline-block mb-4"
          >
            ← Dashboard
          </a>
          <h1 className="text-2xl font-mono text-text-primary">
            Admin Panel
          </h1>
          <p className="text-text-muted text-sm font-sans mt-1">
            System Configuration &amp; Security Management
          </p>
        </div>

        {/* ── Tab Bar ─────────────────────────────────────── */}
        <div className="flex border-b border-aegis-border mb-0">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              id={`admin-tab-${tab.key}`}
              onClick={() => setActiveTab(tab.key)}
              className={`px-4 py-2 text-xs uppercase font-mono tracking-wider border transition-colors ${
                activeTab === tab.key
                  ? "bg-aegis-glow/20 text-aegis-glow border-aegis-glow"
                  : "bg-aegis-panel border-aegis-border text-text-muted hover:text-text-secondary"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Tab Content ─────────────────────────────────── */}
        <div className="bg-aegis-surface border border-aegis-border border-t-0 p-0 overflow-hidden">
          {activeTab === "ip" && <BlocklistManager />}
          {activeTab === "waf" && <WAFRuleManager />}
          {activeTab === "logs" && <AccessLogViewer />}
        </div>
      </div>
    </div>
  );
}
