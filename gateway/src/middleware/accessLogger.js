// ============================================================
// AegisAPI — Access Logger Middleware
// Logs ALL requests (clean + blocked) when LOG_ALL_REQUESTS=true
// Non-blocking — inserts via setImmediate, never slows requests
// ============================================================

import db from '../config/database.js';
import { lookupIP } from '../services/geoip.js';
import { requestsTotal, requestDuration } from '../services/metrics.js';

const ENABLED = (process.env.LOG_ALL_REQUESTS || 'false').toLowerCase() === 'true';

/**
 * Access logger middleware.
 * Wraps res.end() to capture status code and timing after the response is sent.
 */
export default function accessLogger(req, res, next) {
    const start = process.hrtime.bigint();

    // Hook into res.end to capture response data
    const originalEnd = res.end;
    res.end = function (...args) {
        originalEnd.apply(this, args);

        const elapsed = Number(process.hrtime.bigint() - start) / 1e6; // ms
        const status = res.statusCode;
        const method = req.method;
        const path = req.originalUrl || req.url;

        // Always update Prometheus metrics (even when logging is off)
        const metricPath = path.split('?')[0]; // strip query for cardinality
        requestsTotal.inc({ method, path: metricPath, status });
        requestDuration.observe(
            { method, path: metricPath, status },
            elapsed / 1000 // convert ms to seconds
        );

        // Only log to DB if enabled
        if (!ENABLED) return;

        setImmediate(async () => {
            try {
                const geo = lookupIP(req.ip);
                await db.insertAccessLog({
                    ip_address: req.ip,
                    method,
                    path,
                    status_code: status,
                    latency_ms: Math.round(elapsed * 100) / 100,
                    user_agent: (req.headers['user-agent'] || '').substring(0, 500),
                    fingerprint: req.fingerprint || null,
                    country: geo.country,
                    city: geo.city,
                });
            } catch (err) {
                // Never crash the gateway for logging failures
                console.error('[AEGIS:ACCESS] Log insert error:', err.message);
            }
        });
    };

    next();
}
