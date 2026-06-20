// ============================================================
// AegisAPI — WAF Payload Scrubber Middleware
// Deep-inspects request body, query, params, and URL path
// Uses hot-reloadable rule engine (falls back to hardcoded sigs)
// ============================================================

import { detectThreatFromRules } from '../utils/ruleEngine.js';
import { detectThreat as detectThreatFallback } from '../utils/signatures.js';
import { blockedTotal } from '../services/metrics.js';
import { triggerAsyncTelemetry } from './telemetryPipes.js';

/**
 * Detect threat — prefer rule engine, fallback to hardcoded.
 */
function detect(input) {
    const ruleResult = detectThreatFromRules(input);
    if (ruleResult) return ruleResult.type;

    // Fallback to hardcoded signatures (in case rule engine hasn't loaded)
    return detectThreatFallback(input);
}

/**
 * Express middleware — deep-inspects all input surfaces for threats.
 */
export default function payloadScrubber(req, res, next) {
    try {
        // Inspect each input source independently
        const urlThreat = detect(decodeURIComponent(req.originalUrl || req.url));
        const bodyThreat = req.body ? detect(JSON.stringify(req.body)) : null;
        const queryThreat = req.query ? detect(JSON.stringify(req.query)) : null;
        const paramsThreat = req.params ? detect(JSON.stringify(req.params)) : null;

        const threatDetected = urlThreat || bodyThreat || queryThreat || paramsThreat;

        if (threatDetected) {
            // Determine which input source contained the threat
            const source = urlThreat ? 'url' : bodyThreat ? 'body' : queryThreat ? 'query' : 'params';

            console.log(
                `[AEGIS:WAF] Blocked ${threatDetected} from ${req.ip} in ${source} → ${req.method} ${req.originalUrl || req.url}`
            );

            // Update Prometheus metrics
            blockedTotal.inc({ violation_type: threatDetected });

            // Fire telemetry BEFORE sending 403 — post-response middleware
            // is unreachable because we return here without calling next()
            triggerAsyncTelemetry(req, threatDetected);

            return res.status(403).json({
                error: 'Forbidden',
                message: `Request blocked: ${threatDetected} detected`,
                violation: threatDetected,
                source,
            });
        }

        next();
    } catch (err) {
        // WAF must never crash the gateway — fail-open on error
        console.error('[AEGIS:WAF] Scrubber error — failing open:', err.message);
        next();
    }
}
