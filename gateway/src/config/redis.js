// ============================================================
// AegisAPI — Redis Client Configuration
// Singleton ioredis client with error handling and reconnect
// ============================================================

import Redis from 'ioredis';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

const redis = new Redis(REDIS_URL, {
    maxRetriesPerRequest: 1,        // Optimization: reduce timeout-induced spikes
    retryStrategy(times) {
        const delay = Math.min(times * 200, 5000);
        console.log(`[AEGIS:REDIS] Reconnect attempt #${times} in ${delay}ms`);
        return delay;
    },
    connectTimeout: 5000,
    commandTimeout: 2000,
    enableReadyCheck: true,
    lazyConnect: false,
});

redis.on('connect', () => {
    console.log('[AEGIS:REDIS] Connected to Redis');
});

redis.on('ready', () => {
    console.log('[AEGIS:REDIS] Redis client ready');
});

redis.on('error', (err) => {
    console.error('[AEGIS:REDIS] Connection error:', err.message);
});

redis.on('close', () => {
    console.log('[AEGIS:REDIS] Connection closed');
});

export default redis;
