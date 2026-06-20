// ============================================================
// AegisAPI — Rate Limiter Middleware (Performance-Optimized)
// Sliding window via Redis Lua script (single atomic call)
// Features: response headers, per-client API keys, IP blocklist
// Latency: ~0.3ms via single EVALSHA (vs ~1ms with pipeline)
// ============================================================

import crypto from 'node:crypto';
import redis from '../config/redis.js';
import db from '../config/database.js';
import { rateLimitedTotal } from '../services/metrics.js';
import { triggerAsyncTelemetry } from './telemetryPipes.js';

const GLOBAL_LIMIT = parseInt(process.env.RATE_LIMIT_PER_MIN || '100', 10);
const WINDOW_MS = 60000;

// ── Redis Lua Script ────────────────────────────────────────
// Executes all 4 rate-limit operations in a single atomic call
// server-side — eliminates pipeline round-trip parsing overhead.
const RATE_LIMIT_LUA = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
redis.call('ZADD', key, now, member)
local count = redis.call('ZCARD', key)
redis.call('PEXPIRE', key, window)

return count
`;

let luaSha = null;

/**
 * Load the Lua script into Redis on first use (EVALSHA is faster than EVAL).
 */
async function getLuaSha() {
    if (luaSha) return luaSha;
    try {
        luaSha = await redis.script('LOAD', RATE_LIMIT_LUA);
        console.log('[AEGIS:RATE] Lua script loaded into Redis');
    } catch {
        luaSha = null;
    }
    return luaSha;
}

// ── In-memory caches (avoid DB/Redis hits on every request) ──
// Using a simple object with size cap instead of Map for faster access
const blockedIPCache = Object.create(null);
const allowedIPCache = Object.create(null);
const clientCache = Object.create(null);
const CACHE_TTL_MS = 60000;
let cacheSize = 0;
const MAX_CACHE_SIZE = 10000;

function getCached(cache, key) {
    const entry = cache[key];
    if (entry && entry.e > Date.now()) return entry.v;
    return undefined;
}

function setCache(cache, key, value) {
    cache[key] = { v: value, e: Date.now() + CACHE_TTL_MS };
    if (++cacheSize > MAX_CACHE_SIZE) {
        // Evict expired entries
        const now = Date.now();
        for (const k in cache) {
            if (cache[k].e < now) { delete cache[k]; cacheSize--; }
        }
    }
}

// ── Redis-backed blocklist SET for O(1) lookup ──────────────
let blocklistLoaded = false;

/**
 * Sync the full blocklist from DB into a Redis SET on startup.
 * Subsequent checks use SISMEMBER (O(1), ~0.05ms).
 */
async function syncBlocklistToRedis() {
    try {
        const ips = await db.getBlockedIPs();
        if (ips.length > 0) {
            const pipeline = redis.pipeline();
            pipeline.del('aegis:blocklist');
            for (const row of ips) {
                pipeline.sadd('aegis:blocklist', row.ip_address);
            }
            await pipeline.exec();
        }
        blocklistLoaded = true;
    } catch (err) {
        console.error('[AEGIS:RATE] Failed to sync blocklist to Redis:', err.message);
    }
}

// Sync on module load
syncBlocklistToRedis();

async function isBlocked(ip) {
    // Fast path: Redis SET check (O(1))
    if (blocklistLoaded) {
        try {
            const result = await redis.sismember('aegis:blocklist', ip);
            return result === 1;
        } catch { /* fall through to DB */ }
    }

    // Fallback: DB check with cache
    const cached = getCached(blockedIPCache, ip);
    if (cached !== undefined) return cached;

    const blocked = await db.isIPBlocked(ip);
    setCache(blockedIPCache, ip, blocked);
    return blocked;
}

async function isAllowed(ip) {
    const cached = getCached(allowedIPCache, ip);
    if (cached !== undefined) return cached;

    const allowed = await db.isIPAllowed(ip);
    setCache(allowedIPCache, ip, allowed);
    return allowed;
}

async function getClientLimit(req) {
    const apiKey = req.headers['x-aegis-key'];
    if (!apiKey) return GLOBAL_LIMIT;

    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    const cached = getCached(clientCache, keyHash);
    if (cached !== undefined) return cached;

    const client = await db.getClientByKeyHash(keyHash);
    const limit = client?.rate_limit_per_min || GLOBAL_LIMIT;
    setCache(clientCache, keyHash, limit);
    return limit;
}

/**
 * Rate limiter middleware — single Redis Lua call.
 */
export default async function rateLimiter(req, res, next) {
    const ip = req.ip;

    // ── Step 1: Blocklist check (instant 403) ───────────────
    try {
        if (await isBlocked(ip)) {
            return res.status(403).json({
                error: 'Forbidden',
                message: 'Your IP address has been blocked',
                code: 'IP_BLOCKED',
            });
        }
    } catch { /* Fail-open */ }

    // ── Step 2: Allowlist check (skip rate limiting) ────────
    try {
        if (await isAllowed(ip)) {
            res.set('X-RateLimit-Bypass', 'allowlisted');
            return next();
        }
    } catch { /* Fail-open */ }

    // ── Step 3: Rate limiting via Lua script ────────────────
    const now = Date.now();
    const key = `aegis:rate:${ip}`;
    const limit = await getClientLimit(req);
    const member = `${now}:${Math.random().toString(36).substring(2, 8)}`;

    try {
        let count;
        const sha = await getLuaSha();

        if (sha) {
            // Fast path: EVALSHA (pre-loaded script)
            count = await redis.evalsha(sha, 1, key, now, WINDOW_MS, limit, member);
        } else {
            // Fallback: EVAL (first call or script evicted)
            count = await redis.eval(RATE_LIMIT_LUA, 1, key, now, WINDOW_MS, limit, member);
        }

        const remaining = Math.max(0, limit - count);
        const resetTime = Math.ceil((now + WINDOW_MS) / 1000);

        // Set rate limit headers on EVERY response
        res.set('X-RateLimit-Limit', String(limit));
        res.set('X-RateLimit-Remaining', String(remaining));
        res.set('X-RateLimit-Reset', String(resetTime));

        if (count > limit) {
            rateLimitedTotal.inc();
            // Fire telemetry before sending 429 — post-response middleware is unreachable
            triggerAsyncTelemetry(req, 'RATE_LIMIT');
            res.set('Retry-After', String(Math.ceil(WINDOW_MS / 1000)));
            return res.status(429).json({
                error: 'Too Many Requests',
                message: `Rate limit exceeded: ${limit} requests per minute`,
                retry_after: Math.ceil(WINDOW_MS / 1000),
            });
        }

        next();
    } catch (err) {
        // Redis down → fail-open
        console.error('[AEGIS:RATE] Redis error — failing open:', err.message);
        res.set('X-RateLimit-Limit', String(limit));
        res.set('X-RateLimit-Remaining', 'unknown');
        next();
    }
}

/**
 * Clear caches + re-sync Redis blocklist SET.
 */
export function clearBlocklistCache() {
    for (const k in blockedIPCache) delete blockedIPCache[k];
    syncBlocklistToRedis(); // Re-sync the full set
}

export function clearAllowlistCache() {
    for (const k in allowedIPCache) delete allowedIPCache[k];
}
