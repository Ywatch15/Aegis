// ============================================================
// AegisAPI — Prometheus Metrics Exporter
// Exposes /metrics endpoint for monitoring tools
// Uses prom-client (open-source, no paid services)
// ============================================================

import client from 'prom-client';

// Collect default Node.js metrics (CPU, memory, event loop, etc.)
client.collectDefaultMetrics({ prefix: 'aegis_' });

// ── Custom Counters ─────────────────────────────────────────

export const requestsTotal = new client.Counter({
    name: 'aegis_requests_total',
    help: 'Total number of HTTP requests received',
    labelNames: ['method', 'path', 'status'],
});

export const blockedTotal = new client.Counter({
    name: 'aegis_blocked_total',
    help: 'Total number of requests blocked by WAF',
    labelNames: ['violation_type'],
});

export const rateLimitedTotal = new client.Counter({
    name: 'aegis_rate_limited_total',
    help: 'Total number of requests rate-limited',
});

// ── Custom Histograms ───────────────────────────────────────

export const requestDuration = new client.Histogram({
    name: 'aegis_request_duration_seconds',
    help: 'HTTP request duration in seconds',
    labelNames: ['method', 'path', 'status'],
    buckets: [0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1],
});

// ── Custom Gauges ───────────────────────────────────────────

export const activeConnections = new client.Gauge({
    name: 'aegis_active_connections',
    help: 'Number of active HTTP connections',
});

export const uptimeGauge = new client.Gauge({
    name: 'aegis_uptime_seconds',
    help: 'Gateway uptime in seconds',
});

// Update uptime every 5s
setInterval(() => {
    uptimeGauge.set(process.uptime());
}, 5000);

// ── Metrics Handler ─────────────────────────────────────────

/**
 * Express route handler for GET /metrics
 * Returns Prometheus-format text
 */
export async function metricsHandler(req, res) {
    try {
        res.set('Content-Type', client.register.contentType);
        const metrics = await client.register.metrics();
        res.end(metrics);
    } catch (err) {
        res.status(500).end(`# Error collecting metrics: ${err.message}`);
    }
}
