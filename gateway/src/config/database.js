// ============================================================
// AegisAPI — Dual-Mode Database Adapter
// Supabase Cloud (primary) ↔ Local Postgres (fallback)
// Exports a unified interface — callers never know which backend is active
// ============================================================

import { createClient } from '@supabase/supabase-js';
import pg from 'pg';

const { Pool } = pg;

// ── Detect active backend ───────────────────────────────────
const useSupabase = !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);

let supabase = null;
let pgPool = null;

if (useSupabase) {
    supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY
    );
    console.log('[AEGIS:DB] Using Supabase Cloud backend');
} else {
    pgPool = new Pool({
        host: process.env.LOCAL_PG_HOST || 'localhost',
        port: parseInt(process.env.LOCAL_PG_PORT || '5433', 10),
        user: process.env.LOCAL_PG_USER || 'aegis',
        password: process.env.LOCAL_PG_PASSWORD || 'aegis_secure_password',
        database: process.env.LOCAL_PG_DATABASE || 'aegisdb',
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
    });

    pgPool.on('error', (err) => {
        console.error('[AEGIS:DB] Unexpected Postgres pool error:', err.message);
    });

    console.log('[AEGIS:DB] Using local Postgres fallback backend');
}

// ── Helper: Supabase query or Postgres query ────────────────

async function sbFrom(table) {
    return supabase.from(table);
}

// ── Unified Database Interface ──────────────────────────────

const db = {

    // ================================================================
    // SECURITY INCIDENTS
    // ================================================================

    async insertIncident(incident) {
        const row = {
            ip_address: incident.ip_address,
            request_path: incident.request_path,
            request_method: incident.request_method,
            violation_type: incident.violation_type,
            payload_snapshot: incident.payload_snapshot || null,
            severity_score: 'PENDING',
            threat_summary: 'Analyzing...',
            country: incident.country || null,
            city: incident.city || null,
            fingerprint: incident.fingerprint || null,
        };

        try {
            if (useSupabase) {
                const { data, error } = await supabase
                    .from('security_incidents')
                    .insert(row)
                    .select()
                    .single();
                if (error) throw error;
                return data;
            } else {
                const result = await pgPool.query(
                    `INSERT INTO security_incidents 
                        (ip_address, request_path, request_method, violation_type, payload_snapshot, severity_score, threat_summary, country, city, fingerprint)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     RETURNING *`,
                    [row.ip_address, row.request_path, row.request_method, row.violation_type, row.payload_snapshot, row.severity_score, row.threat_summary, row.country, row.city, row.fingerprint]
                );
                return result.rows[0];
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to insert incident:', err.message);
            return null;
        }
    },

    async updateIncident(id, updates) {
        try {
            if (useSupabase) {
                const { data, error } = await supabase
                    .from('security_incidents')
                    .update(updates)
                    .eq('id', id)
                    .select()
                    .single();
                if (error) throw error;
                return data;
            } else {
                const setClauses = [];
                const values = [];
                let paramIndex = 1;
                const allowedColumns = ['severity_score', 'threat_summary'];

                for (const [key, value] of Object.entries(updates)) {
                    if (!allowedColumns.includes(key)) continue;
                    setClauses.push(`${key} = $${paramIndex}`);
                    values.push(value);
                    paramIndex++;
                }

                if (setClauses.length === 0) return null;

                values.push(id);
                const result = await pgPool.query(
                    `UPDATE security_incidents SET ${setClauses.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
                    values
                );
                return result.rows[0] || null;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to update incident:', err.message);
            return null;
        }
    },

    async getIncidentById(id) {
        try {
            if (useSupabase) {
                const { data, error } = await supabase
                    .from('security_incidents')
                    .select('*')
                    .eq('id', id)
                    .single();
                if (error) throw error;
                return data;
            } else {
                const result = await pgPool.query(
                    'SELECT * FROM security_incidents WHERE id = $1',
                    [id]
                );
                return result.rows[0] || null;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to fetch incident by ID:', err.message);
            return null;
        }
    },

    async getIncidents({ limit = 50, offset = 0, violation_type, severity_score } = {}) {
        try {
            if (useSupabase) {
                let query = supabase
                    .from('security_incidents')
                    .select('*')
                    .order('created_at', { ascending: false })
                    .range(offset, offset + limit - 1);

                if (violation_type) query = query.eq('violation_type', violation_type);
                if (severity_score) query = query.eq('severity_score', severity_score);

                const { data, error } = await query;
                if (error) throw error;
                return data || [];
            } else {
                const conditions = [];
                const values = [];
                let paramIndex = 1;

                if (violation_type) {
                    conditions.push(`violation_type = $${paramIndex++}`);
                    values.push(violation_type);
                }
                if (severity_score) {
                    conditions.push(`severity_score = $${paramIndex++}`);
                    values.push(severity_score);
                }

                const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
                values.push(limit, offset);

                const result = await pgPool.query(
                    `SELECT * FROM security_incidents ${where} ORDER BY created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
                    values
                );
                return result.rows;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to fetch incidents:', err.message);
            return [];
        }
    },

    async getIncidentStats() {
        try {
            if (useSupabase) {
                const [totalRes, blockedRes, rateLimitRes, recentRes] = await Promise.all([
                    supabase.from('security_incidents').select('id', { count: 'exact', head: true }),
                    supabase.from('security_incidents').select('id', { count: 'exact', head: true }).neq('violation_type', 'RATE_LIMIT'),
                    supabase.from('security_incidents').select('id', { count: 'exact', head: true }).eq('violation_type', 'RATE_LIMIT'),
                    supabase.from('security_incidents').select('id', { count: 'exact', head: true }).gte('created_at', new Date(Date.now() - 5 * 60 * 1000).toISOString()),
                ]);

                return {
                    total: totalRes.count || 0,
                    blocked: blockedRes.count || 0,
                    rate_limited: rateLimitRes.count || 0,
                    recent_5min: recentRes.count || 0,
                };
            } else {
                const result = await pgPool.query(`
                    SELECT
                        COUNT(*)::int AS total,
                        COUNT(*) FILTER (WHERE violation_type != 'RATE_LIMIT')::int AS blocked,
                        COUNT(*) FILTER (WHERE violation_type = 'RATE_LIMIT')::int AS rate_limited,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '5 minutes')::int AS recent_5min
                    FROM security_incidents
                `);
                return result.rows[0];
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to fetch stats:', err.message);
            return { total: 0, blocked: 0, rate_limited: 0, recent_5min: 0 };
        }
    },

    // ================================================================
    // IP BLOCKLIST
    // ================================================================

    async getBlockedIPs() {
        try {
            if (useSupabase) {
                const { data, error } = await supabase.from('blocked_ips').select('*').order('created_at', { ascending: false });
                if (error) throw error;
                return data || [];
            } else {
                const result = await pgPool.query('SELECT * FROM blocked_ips ORDER BY created_at DESC');
                return result.rows;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to fetch blocked IPs:', err.message);
            return [];
        }
    },

    async isIPBlocked(ip) {
        try {
            if (useSupabase) {
                const { data, error } = await supabase
                    .from('blocked_ips')
                    .select('id')
                    .eq('ip_address', ip)
                    .maybeSingle();
                if (error) throw error;
                return !!data;
            } else {
                const result = await pgPool.query(
                    'SELECT 1 FROM blocked_ips WHERE ip_address = $1 AND (expires_at IS NULL OR expires_at > NOW())',
                    [ip]
                );
                return result.rows.length > 0;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to check blocked IP:', err.message);
            return false;
        }
    },

    async addBlockedIP(ip, reason = 'Manual block', blockedBy = 'system') {
        try {
            const row = { ip_address: ip, reason, blocked_by: blockedBy };
            if (useSupabase) {
                const { data, error } = await supabase.from('blocked_ips').upsert(row, { onConflict: 'ip_address' }).select().single();
                if (error) throw error;
                return data;
            } else {
                const result = await pgPool.query(
                    `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES ($1, $2, $3)
                     ON CONFLICT (ip_address) DO UPDATE SET reason = $2, blocked_by = $3
                     RETURNING *`,
                    [ip, reason, blockedBy]
                );
                return result.rows[0];
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to add blocked IP:', err.message);
            return null;
        }
    },

    async removeBlockedIP(ip) {
        try {
            if (useSupabase) {
                const { error } = await supabase.from('blocked_ips').delete().eq('ip_address', ip);
                if (error) throw error;
                return true;
            } else {
                await pgPool.query('DELETE FROM blocked_ips WHERE ip_address = $1', [ip]);
                return true;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to remove blocked IP:', err.message);
            return false;
        }
    },

    // ================================================================
    // IP ALLOWLIST
    // ================================================================

    async getAllowedIPs() {
        try {
            if (useSupabase) {
                const { data, error } = await supabase.from('allowed_ips').select('*').order('created_at', { ascending: false });
                if (error) throw error;
                return data || [];
            } else {
                const result = await pgPool.query('SELECT * FROM allowed_ips ORDER BY created_at DESC');
                return result.rows;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to fetch allowed IPs:', err.message);
            return [];
        }
    },

    async isIPAllowed(ip) {
        try {
            if (useSupabase) {
                const { data } = await supabase.from('allowed_ips').select('id').eq('ip_address', ip).maybeSingle();
                return !!data;
            } else {
                const result = await pgPool.query('SELECT 1 FROM allowed_ips WHERE ip_address = $1', [ip]);
                return result.rows.length > 0;
            }
        } catch (err) {
            return false;
        }
    },

    async addAllowedIP(ip, note = '') {
        try {
            if (useSupabase) {
                const { data, error } = await supabase.from('allowed_ips').upsert({ ip_address: ip, note }, { onConflict: 'ip_address' }).select().single();
                if (error) throw error;
                return data;
            } else {
                const result = await pgPool.query(
                    `INSERT INTO allowed_ips (ip_address, note) VALUES ($1, $2)
                     ON CONFLICT (ip_address) DO UPDATE SET note = $2
                     RETURNING *`,
                    [ip, note]
                );
                return result.rows[0];
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to add allowed IP:', err.message);
            return null;
        }
    },

    async removeAllowedIP(ip) {
        try {
            if (useSupabase) {
                await supabase.from('allowed_ips').delete().eq('ip_address', ip);
            } else {
                await pgPool.query('DELETE FROM allowed_ips WHERE ip_address = $1', [ip]);
            }
            return true;
        } catch (err) {
            console.error('[AEGIS:DB] Failed to remove allowed IP:', err.message);
            return false;
        }
    },

    // ================================================================
    // ACCESS LOG
    // ================================================================

    async insertAccessLog(entry) {
        try {
            if (useSupabase) {
                await supabase.from('access_log').insert(entry);
            } else {
                await pgPool.query(
                    `INSERT INTO access_log (ip_address, method, path, status_code, latency_ms, user_agent, fingerprint, country, city)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                    [entry.ip_address, entry.method, entry.path, entry.status_code, entry.latency_ms, entry.user_agent, entry.fingerprint, entry.country, entry.city]
                );
            }
        } catch (err) {
            // Silently fail — access logging must never crash the gateway
        }
    },

    async getAccessLogs({ limit = 100, offset = 0, method, ip_address } = {}) {
        try {
            if (useSupabase) {
                let query = supabase.from('access_log').select('*').order('created_at', { ascending: false }).range(offset, offset + limit - 1);
                if (method) query = query.eq('method', method);
                if (ip_address) query = query.eq('ip_address', ip_address);
                const { data, error } = await query;
                if (error) throw error;
                return data || [];
            } else {
                const conditions = [];
                const values = [];
                let pi = 1;
                if (method) { conditions.push(`method = $${pi++}`); values.push(method); }
                if (ip_address) { conditions.push(`ip_address = $${pi++}`); values.push(ip_address); }
                const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
                values.push(limit, offset);
                const result = await pgPool.query(
                    `SELECT * FROM access_log ${where} ORDER BY created_at DESC LIMIT $${pi++} OFFSET $${pi}`,
                    values
                );
                return result.rows;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to fetch access logs:', err.message);
            return [];
        }
    },

    // ================================================================
    // WAF RULES
    // ================================================================

    async getWAFRules() {
        try {
            if (useSupabase) {
                const { data, error } = await supabase.from('waf_rules').select('*').order('category');
                if (error) throw error;
                return data || [];
            } else {
                const result = await pgPool.query('SELECT * FROM waf_rules ORDER BY category, name');
                return result.rows;
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to fetch WAF rules:', err.message);
            return [];
        }
    },

    async upsertWAFRule(rule) {
        try {
            if (useSupabase) {
                const { data, error } = await supabase.from('waf_rules').upsert({
                    ...rule,
                    updated_at: new Date().toISOString(),
                }).select().single();
                if (error) throw error;
                return data;
            } else {
                const result = await pgPool.query(
                    `INSERT INTO waf_rules (name, category, pattern, enabled, severity, description, source)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)
                     ON CONFLICT (id) DO UPDATE SET
                        name = $1, category = $2, pattern = $3, enabled = $4,
                        severity = $5, description = $6, updated_at = NOW()
                     RETURNING *`,
                    [rule.name, rule.category, rule.pattern, rule.enabled, rule.severity, rule.description, rule.source || 'custom']
                );
                return result.rows[0];
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to upsert WAF rule:', err.message);
            return null;
        }
    },

    async toggleWAFRule(id, enabled) {
        try {
            if (useSupabase) {
                const { data, error } = await supabase.from('waf_rules').update({ enabled, updated_at: new Date().toISOString() }).eq('id', id).select().single();
                if (error) throw error;
                return data;
            } else {
                const result = await pgPool.query(
                    'UPDATE waf_rules SET enabled = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
                    [enabled, id]
                );
                return result.rows[0];
            }
        } catch (err) {
            console.error('[AEGIS:DB] Failed to toggle WAF rule:', err.message);
            return null;
        }
    },

    async deleteWAFRule(id) {
        try {
            if (useSupabase) {
                await supabase.from('waf_rules').delete().eq('id', id);
            } else {
                await pgPool.query('DELETE FROM waf_rules WHERE id = $1', [id]);
            }
            return true;
        } catch (err) {
            console.error('[AEGIS:DB] Failed to delete WAF rule:', err.message);
            return false;
        }
    },

    // ================================================================
    // CLIENT CONFIG (Per-Client API Keys)
    // ================================================================

    async getClientByKeyHash(keyHash) {
        try {
            if (useSupabase) {
                const { data } = await supabase.from('clients_config').select('*').eq('api_key_hash', keyHash).eq('is_active', true).maybeSingle();
                return data;
            } else {
                const result = await pgPool.query(
                    'SELECT * FROM clients_config WHERE api_key_hash = $1 AND is_active = TRUE',
                    [keyHash]
                );
                return result.rows[0] || null;
            }
        } catch (err) {
            return null;
        }
    },

    // ================================================================
    // UTILITIES
    // ================================================================

    async close() {
        if (pgPool) {
            await pgPool.end();
            console.log('[AEGIS:DB] Postgres pool closed');
        }
    },

    get backend() {
        return useSupabase ? 'supabase' : 'local-postgres';
    }
};

export default db;
