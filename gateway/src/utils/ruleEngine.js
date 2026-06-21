// ============================================================
// AegisAPI — WAF Rule Engine (Performance-Optimized)
// Hot-reloadable rules with LRU cache + combined regex
// Latency: ~0.01ms cached, ~0.1ms uncached
// ============================================================

import db from '../config/database.js';
import { threatSignatures as defaultSignatures } from './signatures.js';
import { owaspRules } from './owaspRules.js';

// ── LRU Detection Cache ─────────────────────────────────────
// If the same input was scanned before, return cached result instantly.
// Scanners/bots send identical payloads — this eliminates redundant regex work.
const LRU_MAX = 2048;
const lruCache = new Map();

function lruGet(key) {
    const val = lruCache.get(key);
    if (val !== undefined) {
        // Move to end (most recently used)
        lruCache.delete(key);
        lruCache.set(key, val);
        return val;
    }
    return undefined;
}

function lruSet(key, val) {
    if (lruCache.size >= LRU_MAX) {
        // Evict oldest (first entry)
        const firstKey = lruCache.keys().next().value;
        lruCache.delete(firstKey);
    }
    lruCache.set(key, val);
}

// ── Fast Pre-Filter ─────────────────────────────────────────
// Quick string checks BEFORE running regex. If none of these
// substrings are present, the input is almost certainly clean.
// indexOf is ~10x faster than regex.test() for simple patterns.
const FAST_INDICATORS = [
    // SQLi
    'select', 'union', 'insert', 'update', 'delete', 'drop', '--', "'",
    'exec', 'execute', 'xp_', 'sp_', 'cast(', 'convert(', 'benchmark', 'sleep(',
    'waitfor', 'having', 'order by', 'group by', 'load_file', '0x',
    // XSS
    '<script', 'javascript:', 'onerror', 'onload', 'onclick', 'onmouse',
    'onfocus', 'document.', 'window.', 'alert(', 'eval(', 'settimeout',
    'setinterval', 'fromcharcode', 'atob(', 'btoa(', 'data:text',
    // Path Traversal
    '../', '..\\', '%2e', '/etc/', '/proc/', '\\windows\\', '\\system32\\',
    '.htaccess', '.htpasswd', '.git', '.env',
    // Command Injection
    '&&', '||', ';', '`', '$(', 'wget', 'curl', 'chmod', 'chown',
    'netcat', '/bin/', 'bash', 'python -e', 'perl -e', 'ruby -e',
    // SSRF
    '://127.', '://0.', '://10.', '://192.168.', '://localhost',
    '://169.254.169.254', '://metadata.google',
    // XXE / SSTI / Log4Shell / NoSQL
    '<!doctype', '<!entity', 'system', '{{', '${jndi', '$gt', '$ne', '$regex',
];

// Pre-compute lowercase indicators for case-insensitive matching
const LOWER_INDICATORS = FAST_INDICATORS.map(s => s.toLowerCase());

/**
 * Fast check: does the input contain ANY suspicious substring?
 * Returns false if the input is clean (skip all regex).
 */
function mightBeThreat(input) {
    const lower = input.toLowerCase();
    for (let i = 0; i < LOWER_INDICATORS.length; i++) {
        if (lower.indexOf(LOWER_INDICATORS[i]) !== -1) return true;
    }
    return false;
}

// ── Combined Regex Per Category ─────────────────────────────
// Instead of testing 50+ individual regex, combine all patterns
// per category into a single alternation regex. Reduces .test()
// calls from 50+ to ~10 (one per category).

/** @type {Map<string, { regex: RegExp, rules: Array<{id,name,severity}> }>} */
let compiledRules = new Map();
let initialized = false;
const RELOAD_INTERVAL_MS = 60000;

/**
 * Compile DB rows into combined regex per category.
 */
function compileRules(rows) {
    // Group patterns by category
    const groups = new Map();

    for (const row of rows) {
        if (!row.enabled) continue;
        if (!groups.has(row.category)) {
            groups.set(row.category, { patterns: [], rules: [] });
        }
        // Strip (?i) inline flags — JS uses the 'i' flag on RegExp constructor instead
        const cleanPattern = row.pattern.replace(/\(\?i\)/g, '');
        groups.get(row.category).patterns.push(cleanPattern);
        groups.get(row.category).rules.push({
            id: row.id, name: row.name, severity: row.severity,
        });
    }

    // Combine patterns into single regex per category
    const ruleMap = new Map();
    for (const [category, { patterns, rules }] of groups) {
        try {
            const combined = new RegExp(patterns.join('|'), 'i');
            ruleMap.set(category, { regex: combined, rules });
        } catch (err) {
            console.error(`[AEGIS:RULES] Failed to compile ${category}:`, err.message);
            // Fall back to individual patterns
            for (let i = 0; i < patterns.length; i++) {
                try {
                    const single = new RegExp(patterns[i], 'i');
                    const key = `${category}_${i}`;
                    ruleMap.set(key, { regex: single, rules: [rules[i]] });
                } catch { /* skip bad pattern */ }
            }
        }
    }

    return ruleMap;
}

function buildFallbackRules() {
    const ruleMap = new Map();
    for (const [category, regex] of Object.entries(defaultSignatures)) {
        ruleMap.set(category, {
            regex,
            rules: [{ id: null, name: `builtin-${category}`, severity: 'MEDIUM' }],
        });
    }
    return ruleMap;
}

async function seedRulesIfEmpty() {
    try {
        const existing = await db.getWAFRules();
        if (existing && existing.length > 0) return;

        console.log('[AEGIS:RULES] Seeding WAF rules table with defaults + OWASP CRS...');
        const builtinEntries = Object.entries(defaultSignatures);
        for (const [category, regex] of builtinEntries) {
            await db.upsertWAFRule({
                name: `BUILTIN-${category}`, category,
                pattern: regex.source, enabled: true,
                severity: category === 'SQLI' || category === 'CMD_INJECTION' ? 'HIGH' : 'MEDIUM',
                description: `Built-in ${category} detection pattern`, source: 'builtin',
            });
        }
        for (const rule of owaspRules) {
            await db.upsertWAFRule({
                name: rule.name, category: rule.category,
                pattern: rule.pattern, enabled: true,
                severity: rule.severity, description: rule.description, source: 'owasp',
            });
        }
        console.log(`[AEGIS:RULES] Seeded ${builtinEntries.length} builtin + ${owaspRules.length} OWASP rules`);
    } catch (err) {
        console.error('[AEGIS:RULES] Failed to seed rules:', err.message);
    }
}

async function loadRules() {
    try {
        const rows = await db.getWAFRules();
        if (rows && rows.length > 0) {
            compiledRules = compileRules(rows);
            if (!initialized) {
                console.log(`[AEGIS:RULES] Loaded ${rows.length} rules → ${compiledRules.size} combined patterns`);
            }
        } else {
            compiledRules = buildFallbackRules();
            if (!initialized) console.log('[AEGIS:RULES] Using hardcoded fallback');
        }
        initialized = true;
        // Clear LRU cache when rules change
        lruCache.clear();
    } catch (err) {
        if (!initialized) {
            compiledRules = buildFallbackRules();
            console.warn('[AEGIS:RULES] DB unreachable — using fallback:', err.message);
            initialized = true;
        }
    }
}

export async function initRuleEngine() {
    await seedRulesIfEmpty();
    await loadRules();
    setInterval(loadRules, RELOAD_INTERVAL_MS);
}

/**
 * Detect threats using fast pre-filter + LRU cache + combined regex.
 * @param {string} input
 * @returns {{ type: string, severity: string, ruleName: string }|null}
 */
export function detectThreatFromRules(input) {
    if (!input || typeof input !== 'string' || input.length === 0) return null;

    // ── LRU cache check (~0.001ms) ──────────────────────────
    const cached = lruGet(input);
    if (cached !== undefined) return cached; // null = clean, object = threat

    // ── Fast pre-filter (~0.01ms) ───────────────────────────
    // If no suspicious substrings found, skip all regex
    if (!mightBeThreat(input)) {
        lruSet(input, null);
        return null;
    }

    // ── Combined regex scan (~0.1ms) ────────────────────────
    if (compiledRules.size === 0) compiledRules = buildFallbackRules();

    for (const [category, { regex, rules }] of compiledRules) {
        if (regex.test(input)) {
            const result = {
                type: category.replace(/_\d+$/, ''), // Strip fallback suffix
                severity: rules[0]?.severity || 'MEDIUM',
                ruleName: rules[0]?.name || category,
            };
            lruSet(input, result);
            return result;
        }
    }

    lruSet(input, null);
    return null;
}

export function getRuleCount() {
    let total = 0;
    for (const { rules } of compiledRules.values()) {
        total += rules.length;
    }
    return total;
}

export function getCacheStats() {
    return { size: lruCache.size, max: LRU_MAX };
}
