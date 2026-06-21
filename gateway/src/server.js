// ============================================================
// AegisAPI — Gateway Entry Point (Performance-Optimized)
// Express 5 reverse-proxy with:
//   - Cluster mode (multi-core scaling)
//   - Gzip compression
//   - Body size early-reject
//   - Graceful shutdown
// ============================================================

import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// Load .env from project root (two levels up from gateway/src/)
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
dotenv.config({ path: resolve(__dirname, '../../.env') });

import cluster from 'node:cluster';
import os from 'node:os';
import crypto from 'node:crypto';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';

// ── Cluster Mode ────────────────────────────────────────────
// Fork workers per CPU core. Redis-backed state (rate limits,
// blocklist) is shared across all workers automatically.
const ENABLE_CLUSTER = process.env.CLUSTER_MODE === 'true';
const WORKER_COUNT = parseInt(process.env.CLUSTER_WORKERS || '0', 10) || os.cpus().length;

if (ENABLE_CLUSTER && cluster.isPrimary) {
    console.log('');
    console.log('  ╔══════════════════════════════════════════╗');
    console.log('  ║        AegisAPI — Gateway v1.1.0         ║');
    console.log('  ║   WAF · Rate Limiter · AI Analyzer       ║');
    console.log('  ║   Cluster Mode: ON                       ║');
    console.log('  ╚══════════════════════════════════════════╝');
    console.log('');
    console.log(`[AEGIS:CLUSTER] Forking ${WORKER_COUNT} workers on ${os.cpus().length} CPU cores`);

    for (let i = 0; i < WORKER_COUNT; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code) => {
        console.error(`[AEGIS:CLUSTER] Worker ${worker.process.pid} died (code: ${code}). Restarting...`);
        cluster.fork();
    });
} else {
    // ── Single worker (or non-cluster mode) ─────────────────
    startWorker();
}

async function startWorker() {
    // ── Services ────────────────────────────────────────────
    const { initAIAnalyst } = await import('./services/aiAnalyst.js');
    const { metricsHandler } = await import('./services/metrics.js');
    const { lookupIP } = await import('./services/geoip.js');
    const { initRuleEngine, getRuleCount, getCacheStats } = await import('./utils/ruleEngine.js');

    // ── Middleware ───────────────────────────────────────────
    const { default: rateLimiter, clearBlocklistCache, clearAllowlistCache } = await import('./middleware/rateLimiter.js');
    const { default: payloadScrubber } = await import('./middleware/payloadScrubber.js');
    const { default: fingerprintMiddleware } = await import('./middleware/fingerprint.js');
    const { default: accessLogger } = await import('./middleware/accessLogger.js');

    // ── Database ────────────────────────────────────────────
    const { default: db } = await import('./config/database.js');
    const { detectThreat } = await import('./utils/signatures.js');
    const { detectThreatFromRules } = await import('./utils/ruleEngine.js');

    const app = express();
    const PORT = process.env.PORT || 5000;

    // ── Performance: trust proxy for correct req.ip behind reverse proxy
    app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? true : false);

    // ── Gzip/Brotli compression for ALL responses ───────────
    // Reduces JSON payload sizes by ~70%, huge win for dashboard API
    app.use(compression({
        level: 1,           // Fast compression (speed > ratio)
        threshold: 512,     // Only compress responses > 512 bytes
        filter: (req, res) => {
            // Skip compression for SSE/streaming
            if (req.headers['accept'] === 'text/event-stream') return false;
            return compression.filter(req, res);
        },
    }));

    // ── Security headers ────────────────────────────────────
    app.use(helmet());
    app.use(cors({
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Aegis-Key'],
    }));

    // ── Body size early-reject ──────────────────────────────
    // Reject oversized payloads BEFORE parsing (saves CPU)
    app.use((req, res, next) => {
        const contentLength = parseInt(req.headers['content-length'] || '0', 10);
        if (contentLength > 1048576) { // 1MB
            return res.status(413).json({
                error: 'Payload Too Large',
                message: 'Request body exceeds 1MB limit',
            });
        }
        next();
    });

    // ── Body parsing (skip for GET/HEAD/OPTIONS) ────────────
    app.use((req, res, next) => {
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
        express.json({ limit: '1mb' })(req, res, next);
    });
    app.use(express.urlencoded({ extended: true, limit: '1mb' }));

    // ── Fingerprinting + Access Logger ──────────────────────
    app.use(fingerprintMiddleware);
    app.use(accessLogger);

    // ── Health & Metrics (before WAF) ───────────────────────
    app.get('/health', (req, res) => {
        const cacheStats = getCacheStats();
        res.json({
            status: 'operational',
            gateway: 'AegisAPI',
            version: '1.1.0',
            uptime: Math.floor(process.uptime()),
            backend: db.backend,
            waf_rules: getRuleCount(),
            waf_cache: cacheStats,
            pid: process.pid,
            cluster: ENABLE_CLUSTER,
            timestamp: new Date().toISOString(),
        });
    });

    app.get('/metrics', metricsHandler);

    // ── API: Incidents ──────────────────────────────────────
    app.get('/api/incidents', async (req, res) => {
        const { limit, offset, violation_type, severity_score } = req.query;
        const incidents = await db.getIncidents({
            limit: parseInt(limit || '50', 10),
            offset: parseInt(offset || '0', 10),
            violation_type, severity_score,
        });
        res.json({ data: incidents });
    });

    app.get('/api/incidents/:id', async (req, res) => {
        const incident = await db.getIncidentById(req.params.id);
        if (!incident) return res.status(404).json({ error: 'Incident not found' });
        res.json({ data: incident });
    });

    app.get('/api/stats', async (req, res) => {
        const stats = await db.getIncidentStats();
        res.json({ data: stats });
    });

    // ── Admin: Blocklist ────────────────────────────────────
    app.get('/api/admin/blocklist', async (req, res) => {
        res.json({ data: await db.getBlockedIPs() });
    });

    app.post('/api/admin/blocklist', async (req, res) => {
        const { ip_address, reason } = req.body || {};
        if (!ip_address) return res.status(400).json({ error: 'ip_address required' });
        const result = await db.addBlockedIP(ip_address, reason || 'Manual block');
        clearBlocklistCache();
        res.status(201).json({ data: result });
    });

    app.delete('/api/admin/blocklist', async (req, res) => {
        const { ip_address } = req.body || {};
        if (!ip_address) return res.status(400).json({ error: 'ip_address required' });
        await db.removeBlockedIP(ip_address);
        clearBlocklistCache();
        res.json({ message: `IP ${ip_address} removed from blocklist` });
    });

    // ── Admin: Allowlist ────────────────────────────────────
    app.get('/api/admin/allowlist', async (req, res) => {
        res.json({ data: await db.getAllowedIPs() });
    });

    app.post('/api/admin/allowlist', async (req, res) => {
        const { ip_address, note } = req.body || {};
        if (!ip_address) return res.status(400).json({ error: 'ip_address required' });
        const result = await db.addAllowedIP(ip_address, note);
        clearAllowlistCache();
        res.status(201).json({ data: result });
    });

    app.delete('/api/admin/allowlist', async (req, res) => {
        const { ip_address } = req.body || {};
        if (!ip_address) return res.status(400).json({ error: 'ip_address required' });
        await db.removeAllowedIP(ip_address);
        clearAllowlistCache();
        res.json({ message: `IP ${ip_address} removed from allowlist` });
    });

    // ── Admin: Access Logs ──────────────────────────────────
    app.get('/api/admin/access-log', async (req, res) => {
        const { limit, offset, method, ip_address } = req.query;
        const logs = await db.getAccessLogs({
            limit: parseInt(limit || '100', 10),
            offset: parseInt(offset || '0', 10),
            method, ip_address,
        });
        res.json({ data: logs });
    });

    // ── Admin: WAF Rules ────────────────────────────────────
    app.get('/api/admin/waf-rules', async (req, res) => {
        res.json({ data: await db.getWAFRules() });
    });

    app.post('/api/admin/waf-rules', async (req, res) => {
        const { name, category, pattern, severity, description, enabled } = req.body || {};
        if (!name || !category || !pattern) {
            return res.status(400).json({ error: 'name, category, and pattern required' });
        }
        try { new RegExp(pattern, 'i'); } catch (e) {
            return res.status(400).json({ error: `Invalid regex: ${e.message}` });
        }
        const result = await db.upsertWAFRule({
            name, category, pattern, severity: severity || 'MEDIUM',
            description: description || '', enabled: enabled !== false, source: 'custom',
        });
        res.status(201).json({ data: result });
    });

    app.put('/api/admin/waf-rules/:id/toggle', async (req, res) => {
        const { enabled } = req.body || {};
        if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled (boolean) required' });
        res.json({ data: await db.toggleWAFRule(req.params.id, enabled) });
    });

    app.delete('/api/admin/waf-rules/:id', async (req, res) => {
        await db.deleteWAFRule(req.params.id);
        res.json({ message: 'Rule deleted' });
    });

    // ── Admin: Replay ───────────────────────────────────────
    app.post('/api/admin/replay', async (req, res) => {
        const { method, path, payload } = req.body || {};
        if (!method || !path) return res.status(400).json({ error: 'method and path required' });

        const inputs = [path, JSON.stringify(payload || {})];
        const results = [];
        for (const input of inputs) {
            const ruleResult = detectThreatFromRules(input);
            const sigResult = detectThreat(input);
            if (ruleResult) results.push({ source: input === path ? 'path' : 'payload', ...ruleResult });
            else if (sigResult) results.push({ source: input === path ? 'path' : 'payload', type: sigResult, severity: 'MEDIUM', ruleName: 'builtin' });
        }
        res.json({ replay: true, method, path, threats_found: results.length, detections: results, clean: results.length === 0 });
    });

    // ── Admin: GeoIP ────────────────────────────────────────
    app.get('/api/admin/geoip/:ip', (req, res) => {
        res.json({ data: lookupIP(req.params.ip) });
    });

    // ── WAF Pipeline ────────────────────────────────────────
    app.use('/api/{*splat}', rateLimiter);
    app.use('/api/{*splat}', payloadScrubber);

    // ── Protected Routes ────────────────────────────────────
    app.get('/api/test', (req, res) => {
        res.json({
            message: 'AegisAPI test — request passed WAF',
            ip: req.ip, fingerprint: req.fingerprint,
            timestamp: new Date().toISOString(),
        });
    });

    app.post('/api/test', (req, res) => {
        res.json({
            message: 'POST passed WAF',
            receivedBody: req.body,
            ip: req.ip, fingerprint: req.fingerprint,
        });
    });

    app.all('/api/{*splat}', (req, res) => {
        res.json({
            message: 'Request forwarded through AegisAPI',
            method: req.method, path: req.originalUrl,
            ip: req.ip, fingerprint: req.fingerprint,
            timestamp: new Date().toISOString(),
        });
    });


    // ── Error handler ───────────────────────────────────────
    app.use((err, req, res, _next) => {
        console.error('[AEGIS:ERROR]', err.stack || err.message);
        res.status(500).json({
            error: 'Internal Server Error',
            message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong',
        });
    });

    // ── Global handlers ─────────────────────────────────────
    process.on('unhandledRejection', (reason) => {
        console.error('[AEGIS:FATAL] Unhandled rejection:', reason);
    });

    // ── Graceful Shutdown ───────────────────────────────────
    let server;

    async function shutdown(signal) {
        console.log(`\n[AEGIS:GATEWAY] ${signal} received — shutting down gracefully...`);
        if (server) {
            server.close(async () => {
                try { await db.close(); } catch { /* ignore */ }
                console.log('[AEGIS:GATEWAY] Shutdown complete');
                process.exit(0);
            });
            // Force exit after 10s
            setTimeout(() => {
                console.error('[AEGIS:GATEWAY] Forced shutdown after timeout');
                process.exit(1);
            }, 10000);
        } else {
            process.exit(0);
        }
    }

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    // ── Start Server ────────────────────────────────────────
    if (!ENABLE_CLUSTER) {
        console.log('');
        console.log('  ╔══════════════════════════════════════════╗');
        console.log('  ║        AegisAPI — Gateway v1.1.0         ║');
        console.log('  ║   WAF · Rate Limiter · AI Analyzer       ║');
        console.log('  ╚══════════════════════════════════════════╝');
        console.log('');
    }

    await initRuleEngine();
    initAIAnalyst();

    server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`[AEGIS:GATEWAY] Worker ${process.pid} listening on port ${PORT}`);
        console.log(`[AEGIS:GATEWAY] Health:  http://localhost:${PORT}/health`);
        console.log(`[AEGIS:GATEWAY] Metrics: http://localhost:${PORT}/metrics`);
        console.log('');
    });

    // ── Keep-Alive tuning ───────────────────────────────────
    server.keepAliveTimeout = 65000;     // Slightly above typical LB timeout (60s)
    server.headersTimeout = 66000;       // Must be > keepAliveTimeout
}
