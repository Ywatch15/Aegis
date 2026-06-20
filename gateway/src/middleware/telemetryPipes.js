// ============================================================
// AegisAPI — Asynchronous Telemetry Pipeline
// Non-blocking event-driven logger decoupled from request lifecycle
// Enriched with geo + fingerprint data
// ============================================================

import { EventEmitter } from 'node:events';
import db from '../config/database.js';
import { lookupIP } from '../services/geoip.js';

// ── Shared event bus for telemetry ──────────────────────────
// Used by rateLimiter and payloadScrubber to fire incidents,
// and by aiAnalyst to pick them up for analysis.
export const telemetryEmitter = new EventEmitter();

// Prevent memory leak warnings — multiple listeners attach
telemetryEmitter.setMaxListeners(20);

/**
 * Fire-and-forget telemetry push.
 * Called from middleware via event emission — never blocks the HTTP response.
 *
 * Flow:
 *   1. Middleware emits 'incident:trigger' with incident data
 *   2. This handler enriches with geo data and inserts the row into DB
 *   3. Emits 'incident:created' with the row ID for the AI analyzer
 */
telemetryEmitter.on('incident:trigger', async (incidentData) => {
    // Use setImmediate to ensure this runs off the current request stack
    setImmediate(async () => {
        try {
            // Enrich with geolocation data
            const geo = lookupIP(incidentData.ip_address);

            const enrichedData = {
                ...incidentData,
                country: geo.country,
                city: geo.city,
            };

            const row = await db.insertIncident(enrichedData);

            if (row && row.id) {
                console.log(`[AEGIS:TELEMETRY] Incident logged: ${row.id} [${incidentData.violation_type}] from ${incidentData.ip_address} (${geo.country}/${geo.city})`);

                // Signal the AI analyzer to pick up this incident
                telemetryEmitter.emit('incident:created', {
                    id: row.id,
                    ip_address: incidentData.ip_address,
                    request_path: incidentData.request_path,
                    request_method: incidentData.request_method,
                    violation_type: incidentData.violation_type,
                    payload_snapshot: incidentData.payload_snapshot,
                    country: geo.country,
                    city: geo.city,
                });
            }
        } catch (err) {
            // Swallow all errors — telemetry must NEVER crash the gateway
            console.error('[AEGIS:TELEMETRY] Failed to log incident:', err.message);
        }
    });
});

/**
 * Convenience function for middleware to trigger telemetry.
 * @param {import('express').Request} req - Express request object
 * @param {string} violationType - 'SQLI' | 'XSS' | 'PATH_TRAVERSAL' | 'CMD_INJECTION' | 'RATE_LIMIT' | etc.
 */
export function triggerAsyncTelemetry(req, violationType) {
    const payloadSnapshot = JSON.stringify({
        body: req.body,
        query: req.query,
        params: req.params,
    }).substring(0, 1000); // Cap at 1KB to avoid storing massive payloads

    telemetryEmitter.emit('incident:trigger', {
        ip_address: req.ip,
        request_path: req.originalUrl || req.url,
        request_method: req.method,
        violation_type: violationType,
        payload_snapshot: payloadSnapshot,
        fingerprint: req.fingerprint || null,
    });
}
