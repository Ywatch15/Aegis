"use client";

// ── Inline SVG Icons ─────────────────────────────────────────

function ShieldCheckIcon({ className, color }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M12 2l7 4v5c0 5.25-3.5 9.74-7 11-3.5-1.26-7-5.75-7-11V6l7-4Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function ShieldExclamationIcon({ className, color }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M12 2l7 4v5c0 5.25-3.5 9.74-7 11-3.5-1.26-7-5.75-7-11V6l7-4Z" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

function ClockIcon({ className, color }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  );
}

function ActivityPulseIcon({ className, color }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

const ICON_MAP = {
  total: ShieldCheckIcon,
  blocked: ShieldExclamationIcon,
  rate_limited: ClockIcon,
  recent_5min: ActivityPulseIcon,
};

// ── Component ────────────────────────────────────────────────

export default function MetricCards({ stats = {}, isConnected }) {
  const cardDefs = [
    { key: "total",        label: "Requests Analyzed", accent: "#3b82f6" },
    { key: "blocked",      label: "Threats Blocked",   accent: "#ef4444" },
    { key: "rate_limited", label: "Rate Limited",      accent: "#f59e0b" },
    { key: "recent_5min",  label: "Active (5min)",     accent: "#00ff88" },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cardDefs.map((card) => {
        const Icon = ICON_MAP[card.key];
        const value = stats[card.key] ?? 0;

        return (
          <div
            key={card.key}
            className="bg-aegis-surface border border-aegis-border p-5 card-hover"
            style={{ borderTopWidth: "2px", borderTopColor: card.accent }}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-text-secondary text-xs uppercase tracking-wider font-sans">
                {card.label}
              </span>
              <Icon className="w-5 h-5" color={card.accent} />
            </div>

            <div
              className="text-3xl font-mono font-bold text-text-primary animate-fade-up"
              key={value}
            >
              {typeof value === "number" ? value.toLocaleString() : value}
            </div>

            {/* Connection indicator — only on the last card */}
            {card.key === "recent_5min" && typeof isConnected === "boolean" && (
              <div className="flex items-center gap-2 mt-2">
                <span
                  className={
                    isConnected ? "status-dot-online" : "status-dot-offline"
                  }
                />
                <span className="text-text-muted text-xs font-mono">
                  {isConnected ? "Live" : "Disconnected"}
                </span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
