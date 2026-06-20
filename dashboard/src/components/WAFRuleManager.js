"use client";

import { useState, useEffect, useCallback } from "react";

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:5000";

// ── Helpers ──────────────────────────────────────────────────

const CATEGORY_COLORS = {
  SQLI: "text-threat-high",
  SQL_INJECTION: "text-threat-high",
  XSS: "text-threat-medium",
  PATH_TRAVERSAL: "text-cyber-purple",
  CMD_INJECTION: "text-cyber-teal",
  COMMAND_INJECTION: "text-cyber-teal",
};

function categoryColor(cat) {
  return CATEGORY_COLORS[(cat || "").toUpperCase()] || "text-text-secondary";
}

function severityBadgeClasses(severity) {
  const s = (severity || "").toUpperCase();
  switch (s) {
    case "HIGH":
    case "CRITICAL":
      return "bg-threat-high/20 text-threat-high border border-threat-high/30";
    case "MEDIUM":
      return "bg-threat-medium/20 text-threat-medium border border-threat-medium/30";
    case "LOW":
      return "bg-threat-low/20 text-threat-low border border-threat-low/30";
    default:
      return "bg-aegis-panel text-text-muted border border-aegis-border";
  }
}

const CATEGORIES = [
  "SQLI",
  "XSS",
  "PATH_TRAVERSAL",
  "CMD_INJECTION",
  "RATE_LIMIT",
  "CUSTOM",
];

const SEVERITIES = ["HIGH", "MEDIUM", "LOW"];

// ── Component ────────────────────────────────────────────────

export default function WAFRuleManager() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Form fields
  const [formName, setFormName] = useState("");
  const [formCategory, setFormCategory] = useState("CUSTOM");
  const [formPattern, setFormPattern] = useState("");
  const [formSeverity, setFormSeverity] = useState("MEDIUM");
  const [formDescription, setFormDescription] = useState("");

  // ── Fetch ────────────────────────────────────────────────

  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${GATEWAY_URL}/api/admin/waf-rules`);
      if (!res.ok) throw new Error(res.statusText);
      const json = await res.json();
      setRules(Array.isArray(json.data) ? json.data : []);
    } catch {
      setRules([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  // ── Toggle ───────────────────────────────────────────────

  const handleToggle = async (rule) => {
    const newEnabled = !rule.enabled;
    // Optimistic update
    setRules((prev) =>
      prev.map((r) =>
        r.id === rule.id ? { ...r, enabled: newEnabled } : r
      )
    );
    try {
      const res = await fetch(
        `${GATEWAY_URL}/api/admin/waf-rules/${rule.id}/toggle`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: newEnabled }),
        }
      );
      if (!res.ok) throw new Error(res.statusText);
    } catch {
      // Revert on failure
      setRules((prev) =>
        prev.map((r) =>
          r.id === rule.id ? { ...r, enabled: !newEnabled } : r
        )
      );
    }
  };

  // ── Delete ───────────────────────────────────────────────

  const handleDelete = async (ruleId) => {
    try {
      const res = await fetch(
        `${GATEWAY_URL}/api/admin/waf-rules/${ruleId}`,
        { method: "DELETE" }
      );
      if (!res.ok) throw new Error(res.statusText);
      setRules((prev) => prev.filter((r) => r.id !== ruleId));
    } catch {
      // silent
    }
  };

  // ── Add ──────────────────────────────────────────────────

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!formName.trim() || !formPattern.trim()) return;

    setSubmitting(true);
    try {
      const res = await fetch(`${GATEWAY_URL}/api/admin/waf-rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: formName.trim(),
          category: formCategory,
          pattern: formPattern.trim(),
          severity: formSeverity,
          description: formDescription.trim() || undefined,
        }),
      });
      if (!res.ok) throw new Error(res.statusText);
      setFormName("");
      setFormCategory("CUSTOM");
      setFormPattern("");
      setFormSeverity("MEDIUM");
      setFormDescription("");
      setShowForm(false);
      await fetchRules();
    } catch {
      // silent
    } finally {
      setSubmitting(false);
    }
  };

  // ── Derived counts ──────────────────────────────────────

  const activeCount = rules.filter((r) => r.enabled).length;
  const totalCount = rules.length;

  // ── Render ───────────────────────────────────────────────

  return (
    <div className="overflow-hidden">
      {/* ── Header ────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-aegis-border bg-aegis-panel/50">
        <span className="text-text-muted font-mono text-xs">
          WAF Rules ({activeCount} active / {totalCount} total)
        </span>
        <button
          id="waf-toggle-add-form"
          onClick={() => setShowForm((prev) => !prev)}
          className="text-aegis-glow font-mono text-xs hover:text-aegis-glow/80 transition-colors"
        >
          {showForm ? "− Cancel" : "+ Add Custom Rule"}
        </button>
      </div>

      {/* ── Add Rule Form (collapsible) ───────────────────── */}
      {showForm && (
        <form
          onSubmit={handleAdd}
          className="p-4 border-b border-aegis-border bg-aegis-panel/30 space-y-3"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="flex flex-col min-w-0">
              <label
                htmlFor="waf-form-name"
                className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
              >
                Name
              </label>
              <input
                id="waf-form-name"
                type="text"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="Rule name"
                className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 focus:border-aegis-glow/50 focus:outline-none"
              />
            </div>

            <div className="flex flex-col min-w-0">
              <label
                htmlFor="waf-form-category"
                className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
              >
                Category
              </label>
              <select
                id="waf-form-category"
                value={formCategory}
                onChange={(e) => setFormCategory(e.target.value)}
                className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 focus:border-aegis-glow/50 focus:outline-none appearance-none"
              >
                {CATEGORIES.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex flex-col min-w-0">
            <label
              htmlFor="waf-form-pattern"
              className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
            >
              Pattern
            </label>
            <textarea
              id="waf-form-pattern"
              value={formPattern}
              onChange={(e) => setFormPattern(e.target.value)}
              placeholder="Regex pattern"
              rows={2}
              className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 resize-none focus:border-aegis-glow/50 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="flex flex-col min-w-0">
              <label
                htmlFor="waf-form-severity"
                className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
              >
                Severity
              </label>
              <select
                id="waf-form-severity"
                value={formSeverity}
                onChange={(e) => setFormSeverity(e.target.value)}
                className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 focus:border-aegis-glow/50 focus:outline-none appearance-none"
              >
                {SEVERITIES.map((sev) => (
                  <option key={sev} value={sev}>
                    {sev}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex flex-col min-w-0">
              <label
                htmlFor="waf-form-description"
                className="text-[10px] text-text-dim uppercase tracking-widest font-sans mb-1"
              >
                Description
              </label>
              <input
                id="waf-form-description"
                type="text"
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                placeholder="Optional description"
                className="bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm px-3 py-2 focus:border-aegis-glow/50 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              id="waf-submit-rule"
              type="submit"
              disabled={submitting || !formName.trim() || !formPattern.trim()}
              className="bg-aegis-glow/20 text-aegis-glow border border-aegis-glow/30 px-4 py-2 text-xs font-mono uppercase hover:bg-aegis-glow/30 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {submitting ? "Saving..." : "Save Rule"}
            </button>
          </div>
        </form>
      )}

      {/* ── Table ─────────────────────────────────────────── */}
      {loading ? (
        <div className="p-12 text-center">
          <span className="text-text-muted font-mono text-sm">Loading...</span>
        </div>
      ) : rules.length === 0 ? (
        <div className="p-12 text-center">
          <span className="text-text-muted font-mono text-sm">
            No WAF rules configured
          </span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-aegis-panel">
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Status
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Name
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Category
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Pattern
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Severity
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Source
                </th>
                <th className="text-text-muted text-xs uppercase tracking-wider font-mono px-4 py-3 font-medium">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => {
                const isEnabled = rule.enabled !== false;
                const ruleCategory = (
                  rule.category || ""
                ).toUpperCase();
                const ruleSeverity = (
                  rule.severity || ""
                ).toUpperCase();
                const ruleSource = (
                  rule.source || "built-in"
                ).toLowerCase();
                const isCustom = ruleSource === "custom";

                return (
                  <tr
                    key={rule.id}
                    className="border-b border-aegis-border hover:bg-aegis-panel/50 transition-colors"
                  >
                    {/* Status toggle */}
                    <td className="px-4 py-2.5">
                      <button
                        id={`waf-toggle-${rule.id}`}
                        onClick={() => handleToggle(rule)}
                        className={`font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 transition-colors ${
                          isEnabled
                            ? "bg-cyber-green/20 text-cyber-green border border-cyber-green/30"
                            : "bg-threat-high/20 text-threat-high border border-threat-high/30"
                        }`}
                      >
                        {isEnabled ? "ON" : "OFF"}
                      </button>
                    </td>

                    {/* Name */}
                    <td className="font-mono text-text-primary text-sm px-4 py-2.5 whitespace-nowrap">
                      {rule.name || "—"}
                    </td>

                    {/* Category */}
                    <td
                      className={`font-mono text-xs uppercase px-4 py-2.5 whitespace-nowrap ${categoryColor(
                        ruleCategory
                      )}`}
                    >
                      {ruleCategory || "—"}
                    </td>

                    {/* Pattern */}
                    <td
                      className="font-mono text-text-muted text-xs px-4 py-2.5 truncate max-w-[250px]"
                      title={rule.pattern || ""}
                    >
                      {rule.pattern || "—"}
                    </td>

                    {/* Severity */}
                    <td className="px-4 py-2.5">
                      <span
                        className={`inline-block font-mono text-xs px-2 py-0.5 uppercase ${severityBadgeClasses(
                          ruleSeverity
                        )}`}
                      >
                        {ruleSeverity || "—"}
                      </span>
                    </td>

                    {/* Source */}
                    <td className="font-mono text-xs text-text-dim px-4 py-2.5 whitespace-nowrap">
                      {ruleSource}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-2.5">
                      {isCustom ? (
                        <button
                          id={`waf-delete-${rule.id}`}
                          onClick={() => handleDelete(rule.id)}
                          className="text-threat-high hover:text-threat-high/80 text-xs font-mono transition-colors"
                        >
                          Delete
                        </button>
                      ) : (
                        <span className="text-text-dim text-xs font-mono">
                          —
                        </span>
                      )}
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
