"use client";

import { useState, useEffect, useCallback } from "react";

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:5000";

// ── Helpers ──────────────────────────────────────────────────

function formatDate(ts) {
  try {
    return new Date(ts).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return "—";
  }
}

// ── Component ────────────────────────────────────────────────

export default function BlocklistManager() {
  const [activeTab, setActiveTab] = useState("blocklist");
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [ipInput, setIpInput] = useState("");
  const [noteInput, setNoteInput] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // ── Fetch ────────────────────────────────────────────────

  const fetchEntries = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(
        `${GATEWAY_URL}/api/admin/${activeTab}`
      );
      if (!res.ok) throw new Error(res.statusText);
      const json = await res.json();
      setEntries(Array.isArray(json.data) ? json.data : []);
    } catch {
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [activeTab]);

  useEffect(() => {
    fetchEntries();
  }, [fetchEntries]);

  // ── Add ──────────────────────────────────────────────────

  const handleAdd = async (e) => {
    e.preventDefault();
    const trimmedIp = ipInput.trim();
    if (!trimmedIp) return;

    setSubmitting(true);
    try {
      const body =
        activeTab === "blocklist"
          ? { ip_address: trimmedIp, reason: noteInput.trim() || undefined }
          : { ip_address: trimmedIp, note: noteInput.trim() || undefined };

      const res = await fetch(`${GATEWAY_URL}/api/admin/${activeTab}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(res.statusText);
      setIpInput("");
      setNoteInput("");
      await fetchEntries();
    } catch {
      // silent
    } finally {
      setSubmitting(false);
    }
  };

  // ── Remove ───────────────────────────────────────────────

  const handleRemove = async (ipAddress) => {
    try {
      const res = await fetch(`${GATEWAY_URL}/api/admin/${activeTab}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip_address: ipAddress }),
      });
      if (!res.ok) throw new Error(res.statusText);
      await fetchEntries();
    } catch {
      // silent
    }
  };

  // ── Tab helpers ──────────────────────────────────────────

  const tabs = [
    { key: "blocklist", label: "Blocklist" },
    { key: "allowlist", label: "Allowlist" },
  ];

  const noteLabel = activeTab === "blocklist" ? "Reason" : "Note";

  // ── Render ───────────────────────────────────────────────

  return (
    <div className="overflow-hidden">
      {/* ── Tabs ──────────────────────────────────────────── */}
      <div className="flex border-b border-aegis-border">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            id={`blocklist-tab-${tab.key}`}
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

      {/* ── Add Form ──────────────────────────────────────── */}
      <form
        onSubmit={handleAdd}
        className="flex flex-wrap items-end gap-3 p-4 border-b border-aegis-border bg-aegis-panel/50"
      >
        <div className="flex flex-col min-w-0">
          <label
            htmlFor="blocklist-ip-input"
            className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
          >
            IP Address
          </label>
          <input
            id="blocklist-ip-input"
            type="text"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="192.168.1.1"
            className="font-mono bg-aegis-panel border border-aegis-border text-text-primary px-3 py-2 text-sm w-44 focus:border-aegis-glow/50 focus:outline-none"
          />
        </div>

        <div className="flex flex-col min-w-0 flex-1">
          <label
            htmlFor="blocklist-note-input"
            className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
          >
            {noteLabel}
          </label>
          <input
            id="blocklist-note-input"
            type="text"
            value={noteInput}
            onChange={(e) => setNoteInput(e.target.value)}
            placeholder={
              activeTab === "blocklist"
                ? "Reason for blocking"
                : "Note for allowlisting"
            }
            className="font-mono bg-aegis-panel border border-aegis-border text-text-primary px-3 py-2 text-sm focus:border-aegis-glow/50 focus:outline-none"
          />
        </div>

        <button
          id="blocklist-add-btn"
          type="submit"
          disabled={submitting || !ipInput.trim()}
          className="bg-aegis-glow/20 text-aegis-glow border border-aegis-glow/30 px-4 py-2 text-xs font-mono uppercase hover:bg-aegis-glow/30 transition-colors disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
        >
          {submitting ? "Adding..." : "Add"}
        </button>
      </form>

      {/* ── Table ─────────────────────────────────────────── */}
      {loading ? (
        <div className="p-12 text-center">
          <span className="text-text-muted font-mono text-sm">Loading...</span>
        </div>
      ) : entries.length === 0 ? (
        <div className="p-12 text-center">
          <span className="text-text-muted font-mono text-sm">
            No IPs in {activeTab}
          </span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-aegis-panel">
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  IP Address
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  {noteLabel}
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Added
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Action
                </th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry, idx) => {
                const ip =
                  entry.ip_address || entry.ip || "—";
                const note =
                  activeTab === "blocklist"
                    ? entry.reason || "—"
                    : entry.note || "—";
                const added =
                  entry.created_at ||
                  entry.added_at ||
                  entry.timestamp ||
                  null;

                return (
                  <tr
                    key={`${ip}-${idx}`}
                    className="border-b border-aegis-border hover:bg-aegis-panel/50 transition-colors"
                  >
                    <td className="font-mono text-cyber-blue text-sm px-4 py-2.5 whitespace-nowrap">
                      {ip}
                    </td>
                    <td
                      className="text-text-secondary font-mono text-sm px-4 py-2.5 truncate max-w-[200px]"
                      title={note}
                    >
                      {note}
                    </td>
                    <td className="font-mono text-text-muted text-xs px-4 py-2.5 whitespace-nowrap">
                      {added ? formatDate(added) : "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        id={`blocklist-remove-${idx}`}
                        onClick={() => handleRemove(ip)}
                        className="text-threat-high hover:text-threat-high/80 text-xs font-mono transition-colors"
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
