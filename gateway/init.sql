-- ============================================================
-- AegisAPI — Database Schema Initialization
-- Runs automatically on local Postgres container first start
-- For Supabase: run this manually in SQL Editor
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- 1. Multi-tenant client configuration
-- Stores API key hashes and per-client rate limits
-- ============================================================
CREATE TABLE IF NOT EXISTS clients_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_name VARCHAR(100) NOT NULL,
    api_key_hash VARCHAR(64) UNIQUE NOT NULL,
    rate_limit_per_min INT DEFAULT 100,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 2. Security incidents ledger
-- Every WAF block and rate-limit hit is recorded here
-- ============================================================
CREATE TABLE IF NOT EXISTS security_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address VARCHAR(45) NOT NULL,
    request_path TEXT NOT NULL,
    request_method VARCHAR(10) NOT NULL,
    violation_type VARCHAR(50) NOT NULL,
    payload_snapshot TEXT,
    severity_score VARCHAR(10) DEFAULT 'PENDING',
    threat_summary TEXT DEFAULT 'Analyzing...',
    country VARCHAR(3),
    city VARCHAR(100),
    fingerprint VARCHAR(16),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 3. User profiles (extends Supabase Auth)
-- For local Postgres: stores basic user data
-- ============================================================
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 4. IP Blocklist
-- Blocked IPs get instant 403 before any processing
-- ============================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason TEXT DEFAULT 'Manual block',
    blocked_by VARCHAR(100) DEFAULT 'system',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 5. IP Allowlist
-- Allowed IPs bypass rate limiting (not WAF)
-- ============================================================
CREATE TABLE IF NOT EXISTS allowed_ips (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    note TEXT DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 6. Access Log
-- Full request log (clean + blocked) for forensics
-- ============================================================
CREATE TABLE IF NOT EXISTS access_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address VARCHAR(45) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    status_code INT NOT NULL,
    latency_ms REAL,
    user_agent TEXT,
    fingerprint VARCHAR(16),
    country VARCHAR(3),
    city VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 7. WAF Rules (hot-reloadable)
-- Regex patterns loaded from DB instead of hardcoded
-- ============================================================
CREATE TABLE IF NOT EXISTS waf_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    pattern TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    severity VARCHAR(10) DEFAULT 'MEDIUM' CHECK (severity IN ('HIGH', 'MEDIUM', 'LOW')),
    description TEXT DEFAULT '',
    source VARCHAR(20) DEFAULT 'custom' CHECK (source IN ('builtin', 'owasp', 'custom')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Performance Indexes
-- ============================================================

-- Composite index — faster filtered analytics (Optimization #1)
CREATE INDEX IF NOT EXISTS idx_incidents_created_type
    ON security_incidents(created_at DESC, violation_type);

-- Fast lookups by source IP (incident investigation)
CREATE INDEX IF NOT EXISTS idx_incidents_ip
    ON security_incidents(ip_address);

-- Fast time-ordered reads (dashboard feed, descending)
CREATE INDEX IF NOT EXISTS idx_incidents_created_at
    ON security_incidents(created_at DESC);

-- Fast filtering by violation type (analytics)
CREATE INDEX IF NOT EXISTS idx_incidents_violation_type
    ON security_incidents(violation_type);

-- Fast filtering by severity (priority triage)
CREATE INDEX IF NOT EXISTS idx_incidents_severity
    ON security_incidents(severity_score);

-- Blocklist IP lookup (must be fast — on every request)
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip
    ON blocked_ips(ip_address);

-- Access log time-ordered reads
CREATE INDEX IF NOT EXISTS idx_access_log_created_at
    ON access_log(created_at DESC);

-- WAF rules — enabled rules by category
CREATE INDEX IF NOT EXISTS idx_waf_rules_category
    ON waf_rules(category, enabled);
