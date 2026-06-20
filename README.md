<![CDATA[<div align="center">

# ⛨ AegisAPI

**Self-hosted, low-latency Web Application Firewall (WAF) & Dynamic Rate-Limiting Engine with AI-powered threat analysis.**

[![Node.js](https://img.shields.io/badge/Node.js-22+-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![Express](https://img.shields.io/badge/Express-5-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Postgres](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```
    ╔═══════════════════════════════════════════════╗
    ║          ⛨  AegisAPI Gateway v1.1.0           ║
    ║                                               ║
    ║   WAF Engine    ✓  SQLi / XSS / Traversal     ║
    ║   Rate Limiter  ✓  Sliding-window (Redis)     ║
    ║   AI Analyzer   ✓  Multi-provider (NIM/GPT)   ║
    ║   Dashboard     ✓  Real-time SOC interface     ║
    ╚═══════════════════════════════════════════════╝
```

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Quick Start (Docker)](#quick-start-docker-compose)
- [Local Development](#local-development-without-docker)
- [Environment Variables](#environment-variables)
- [AI Provider Setup](#swapping-ai-providers)
- [API Endpoints](#api-endpoints)
- [Testing](#testing-with-curl)
- [K6 Stress Testing](#k6-stress-testing)
- [Project Structure](#project-structure)
- [Dashboard Pages](#dashboard-pages)
- [Network Ports](#network-ports)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

AegisAPI is a **reverse-proxy security gateway** that sits in front of your APIs and provides:

- 🛡️ **WAF (Web Application Firewall)** — Blocks SQL injection, XSS, path traversal, command injection, SSRF, XXE, SSTI, Log4Shell, and NoSQL injection using 50+ OWASP CRS-derived regex rules
- ⏱️ **Sliding Window Rate Limiting** — Redis-backed with atomic Lua scripts for sub-millisecond enforcement
- 🤖 **AI Threat Analysis** — Automatic severity scoring and technical summaries via any OpenAI-compatible LLM
- 📊 **Real-Time SOC Dashboard** — Next.js 16 interface with live threat feed, analytics charts, and admin controls
- 🌍 **IP Geolocation** — Automatic country/city enrichment for every incident
- 🔐 **Authentication & RBAC** — Supabase Auth with admin/analyst/viewer roles

The gateway is designed to be **self-hosted**, **provider-agnostic**, and **zero-config** for local development.

---

## Architecture

```
[Incoming HTTP Request]
         │
         ▼
    [server.js] ──► [rateLimiter.js] ──► Redis ZSET Pipeline
         │
         ▼ (If Allowed)
    [payloadScrubber.js] ──► [ruleEngine.js] Combined Regex Engine
         │
         ├──► (If Malicious → 403 + Async Telemetry)
         │
         ▼ (If Clean → next())
    [Target API Response]
         │
         ▼ (Post-Response, Non-blocking)
    [telemetryPipes.js] ──► Database Insert (PENDING)
                                  │
                     ┌────────────┴────────────┐
                     ▼                         ▼
              [aiAnalyst.js]          [Supabase / Postgres]
              (NVIDIA NIM /                    │
               OpenAI / Groq)                  ▼
                     │                 [Next.js Dashboard]
                     └─── UPDATE ──────► Real-time Feed
```

**Request Lifecycle:**
1. Request hits the gateway on port 5000
2. **Fingerprinting** — generates a client fingerprint from headers
3. **Blocklist check** — instant 403 if IP is blocked (Redis SET, O(1))
4. **Rate limiting** — sliding window counter via Redis Lua script
5. **WAF scan** — LRU cache → fast pre-filter → combined regex per category
6. Clean requests pass through; blocked requests get 403 + async telemetry
7. Telemetry pipeline enriches with GeoIP and inserts to database
8. AI analyzer picks up the incident for severity scoring (batched, 3s window)

---

## Features

| Feature | Description |
|---------|-------------|
| **WAF Engine** | 50+ regex rules covering OWASP Top 10 attack vectors |
| **Hot-Reloadable Rules** | WAF rules stored in DB, reloaded every 60s, editable via admin API |
| **LRU Detection Cache** | 2048-entry cache eliminates redundant regex for repeated payloads |
| **Sliding Window Rate Limiter** | Redis ZSET + Lua script for atomic, sub-ms enforcement |
| **Per-Client Rate Limits** | API key-based limits via `X-Aegis-Key` header |
| **IP Blocklist/Allowlist** | Instant 403 for blocked IPs; rate-limit bypass for allowed IPs |
| **AI Threat Analyzer** | Batch-mode severity scoring via any OpenAI-compatible API |
| **Request Fingerprinting** | SHA-256 hash of browser headers for bot detection |
| **IP Geolocation** | In-memory MaxMind GeoLite2 lookup (zero network calls) |
| **Prometheus Metrics** | `/metrics` endpoint for Grafana/Datadog integration |
| **Cluster Mode** | Multi-core scaling via Node.js cluster module |
| **Graceful Shutdown** | SIGTERM/SIGINT handling with 10s timeout |
| **Real-Time Dashboard** | Live threat feed via Supabase Realtime or polling fallback |
| **Analytics Charts** | Time-series, pie charts, bar charts, top attacked endpoints |
| **Admin Panel** | IP management, WAF rule CRUD, access log viewer |
| **Request Replay** | Re-test past payloads against current WAF rules |
| **CSV Export** | Client-side incident export to CSV |
| **Auth & RBAC** | Supabase Auth with admin/analyst/viewer roles |
| **Dual-Mode Database** | Supabase Cloud ↔ Local Postgres with zero code changes |
| **Gzip Compression** | Automatic response compression (~70% smaller payloads) |

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Gateway** | Express 5 (Node.js 22) | HTTP server, middleware pipeline |
| **Rate Limiter** | Redis 7 + ioredis | Sliding window ZSET + Lua scripts |
| **WAF** | Custom regex engine | Pattern matching with LRU cache |
| **Database** | PostgreSQL 16 / Supabase | Incident storage, WAF rules, user profiles |
| **AI** | OpenAI-compatible API | Threat severity analysis |
| **GeoIP** | geoip-lite (MaxMind) | IP geolocation |
| **Metrics** | prom-client | Prometheus metrics exporter |
| **Dashboard** | Next.js 16 (React 19) | SOC interface |
| **Charts** | Recharts | Analytics visualizations |
| **Auth** | Supabase Auth (@supabase/ssr) | JWT sessions, RBAC |
| **Styling** | Tailwind CSS 4 | Cybersecurity dark theme |
| **Containerization** | Docker + Docker Compose | Multi-service orchestration |

---

## Quick Start (Docker Compose)

```bash
# 1. Clone and configure
git clone https://github.com/your-username/aegisapi.git
cd aegisapi
cp .env.example .env
# Edit .env with your API keys (or leave empty for local-only mode)

# 2. Start all services
docker compose up -d

# 3. Verify
curl http://localhost:5000/health      # Gateway health check
open http://localhost:3000              # Dashboard
```

This starts 4 containers: Redis, Postgres, Gateway, and Dashboard.

---

## Local Development (Without Docker)

### Prerequisites

- **Node.js 18+** (22 recommended)
- **Redis** running on port 6379
- **Docker** (for Postgres, or use Supabase Cloud)

### Gateway

```bash
cd gateway
npm install
npm run dev        # Starts on port 5000 with nodemon (hot-reload)
```

### Dashboard

```bash
cd dashboard
npm install
npm run dev        # Starts on port 3000 with Next.js dev server
```

### Database (Local Postgres via Docker)

```bash
docker compose up aegis-cache aegis-db -d
# Starts Redis + Postgres only, gateway/dashboard run natively
```

The `init.sql` schema runs automatically on the Postgres container's first start.

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `5000` | Gateway listen port |
| `NODE_ENV` | No | `development` | Environment mode |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis connection string |
| `SUPABASE_URL` | No | — | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | No | — | Supabase service role key (server-side) |
| `SUPABASE_ANON_KEY` | No | — | Supabase anon key |
| `LOCAL_PG_HOST` | No | `localhost` | Local Postgres host |
| `LOCAL_PG_PORT` | No | `5433` | Local Postgres port |
| `LOCAL_PG_USER` | No | `aegis` | Local Postgres user |
| `LOCAL_PG_PASSWORD` | No | `aegis_secure_password` | Local Postgres password |
| `LOCAL_PG_DATABASE` | No | `aegisdb` | Local Postgres database |
| `AI_PROVIDER_BASE_URL` | No | — | OpenAI-compatible API endpoint |
| `AI_PROVIDER_API_KEY` | No | — | API key for AI provider |
| `AI_PROVIDER_MODEL` | No | `meta/llama-3.1-70b-instruct` | AI model name |
| `LOG_ALL_REQUESTS` | No | `false` | Log all requests to access_log table |
| `RATE_LIMIT_PER_MIN` | No | `100` | Global rate limit per IP per minute |
| `CLUSTER_MODE` | No | `false` | Enable multi-core clustering |
| `CLUSTER_WORKERS` | No | `0` (auto) | Number of cluster workers |
| `TRUST_PROXY` | No | `false` | Trust X-Forwarded-For header |
| `CORS_ORIGIN` | No | `*` | Allowed CORS origin |
| `NEXT_PUBLIC_SUPABASE_URL` | No | — | Supabase URL (dashboard client-side) |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | No | — | Supabase anon key (dashboard) |
| `NEXT_PUBLIC_GATEWAY_URL` | No | `http://localhost:5000` | Gateway URL for dashboard API calls |

> **Note:** All credentials are optional. Without Supabase, the gateway uses local Postgres. Without AI keys, incidents stay in PENDING state. The system is fully functional with zero external dependencies (just Redis + Postgres via Docker).

---

## Swapping AI Providers

Change 3 environment variables — zero code changes:

| Provider | `AI_PROVIDER_BASE_URL` | `AI_PROVIDER_MODEL` |
|----------|----------------------|---------------------|
| **NVIDIA NIM** | `https://integrate.api.nvidia.com/v1` | `meta/llama-3.1-70b-instruct` |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o-mini` |
| **Groq** | `https://api.groq.com/openai/v1` | `llama-3.1-70b-versatile` |
| **Mistral** | `https://api.mistral.ai/v1` | `mistral-small-latest` |
| **Ollama (local)** | `http://localhost:11434/v1` | `llama3.1` |

---

## API Endpoints

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Gateway health check (bypasses WAF) |
| `GET` | `/metrics` | Prometheus metrics (text format) |

### Data

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/incidents` | List incidents (`?limit=50&offset=0&violation_type=SQLI`) |
| `GET` | `/api/incidents/:id` | Get incident by ID |
| `GET` | `/api/stats` | Aggregate stats for dashboard cards |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/blocklist` | List blocked IPs |
| `POST` | `/api/admin/blocklist` | Block an IP (`{ ip_address, reason }`) |
| `DELETE` | `/api/admin/blocklist` | Unblock an IP (`{ ip_address }`) |
| `GET` | `/api/admin/allowlist` | List allowed IPs |
| `POST` | `/api/admin/allowlist` | Allow an IP (`{ ip_address, note }`) |
| `DELETE` | `/api/admin/allowlist` | Remove allowed IP (`{ ip_address }`) |
| `GET` | `/api/admin/access-log` | View access logs (`?limit=100&method=POST`) |
| `GET` | `/api/admin/waf-rules` | List all WAF rules |
| `POST` | `/api/admin/waf-rules` | Create/update rule (`{ name, category, pattern }`) |
| `PUT` | `/api/admin/waf-rules/:id/toggle` | Toggle rule enabled (`{ enabled }`) |
| `DELETE` | `/api/admin/waf-rules/:id` | Delete a WAF rule |
| `POST` | `/api/admin/replay` | Replay a request through WAF (`{ method, path, payload }`) |
| `GET` | `/api/admin/geoip/:ip` | GeoIP lookup for any IP |

### Protected (WAF + Rate Limiter)

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/api/test` | Test endpoint (passes through WAF) |
| `ALL` | `/api/*` | Catch-all — all `/api/` routes pass through the security pipeline |

---

## Testing with curl

```bash
# ✅ Health check
curl http://localhost:5000/health

# ✅ Clean request (passes WAF)
curl http://localhost:5000/api/test

# 🛡️ SQLi blocked → 403
curl -X POST http://localhost:5000/api/test \
  -H "Content-Type: application/json" \
  -d '{"q":"UNION SELECT * FROM users"}'

# 🛡️ XSS blocked → 403
curl "http://localhost:5000/api/test?q=<script>alert(1)</script>"

# 🛡️ Path traversal blocked → 403
curl "http://localhost:5000/api/test?file=../../../etc/passwd"

# 🛡️ Command injection blocked → 403
curl -X POST http://localhost:5000/api/test \
  -H "Content-Type: application/json" \
  -d '{"cmd":"; cat /etc/passwd"}'

# ⏱️ Rate limit test (send 105 rapid requests)
for i in $(seq 1 105); do
  curl -s -o /dev/null -w "%{http_code} " http://localhost:5000/api/test
done
# Last few should return 429
```

---

## K6 Stress Testing

```bash
# Install K6: https://grafana.com/docs/k6/latest/set-up/install-k6/
k6 run gateway/tests/stress-test.k6.js

# With custom gateway URL:
k6 run -e GATEWAY_URL=http://localhost:5000 gateway/tests/stress-test.k6.js
```

**Test Scenarios:**

| # | Scenario | VUs | Duration | Pass Criteria |
|---|----------|-----|----------|---------------|
| 1 | Throughput baseline | 200 | 30s | p95 < 50ms |
| 2 | Rate limit burst | 1 | 150 reqs | Verify 429 |
| 3 | WAF: SQLi | 50 | 10s | >95% blocked |
| 4 | WAF: XSS | 50 | 10s | >95% blocked |
| 5 | WAF: Path traversal | 50 | 10s | >95% blocked |
| 6 | Mixed traffic | 100 | 60s | 80% clean / 20% malicious |

---

## Project Structure

```
aegisapi/
├── docker-compose.yml              # Multi-container orchestration
├── .env.example                    # Environment template
├── .gitignore                      # Git ignore rules
├── README.md                       # This file
│
├── gateway/                        # Express 5 WAF Engine
│   ├── Dockerfile                  # Production container
│   ├── package.json                # Dependencies (express, ioredis, pg, etc.)
│   ├── init.sql                    # Database schema (7 tables + indexes)
│   ├── src/
│   │   ├── server.js               # Entry point (cluster mode, routes, shutdown)
│   │   ├── config/
│   │   │   ├── redis.js            # ioredis client (singleton, reconnect logic)
│   │   │   └── database.js         # Dual-mode Supabase/Postgres adapter
│   │   ├── middleware/
│   │   │   ├── rateLimiter.js      # Sliding-window rate limiter (Redis Lua)
│   │   │   ├── payloadScrubber.js  # WAF pattern matcher (deep input scan)
│   │   │   ├── telemetryPipes.js   # Async non-blocking incident logger
│   │   │   ├── fingerprint.js      # Request header fingerprinting
│   │   │   └── accessLogger.js     # Full request logger (opt-in)
│   │   ├── services/
│   │   │   ├── aiAnalyst.js        # Multi-provider AI threat analyzer
│   │   │   ├── geoip.js            # IP geolocation (MaxMind in-memory)
│   │   │   └── metrics.js          # Prometheus metrics exporter
│   │   └── utils/
│   │       ├── signatures.js       # Hardcoded regex threat dictionary
│   │       ├── ruleEngine.js       # Hot-reloadable WAF rule engine + LRU
│   │       └── owaspRules.js       # OWASP CRS curated subset (~50 rules)
│   └── tests/
│       └── stress-test.k6.js       # K6 load test suite (6 scenarios)
│
└── dashboard/                      # Next.js 16 SOC Dashboard
    ├── Dockerfile                  # Multi-stage production build
    ├── package.json                # Dependencies (next, react, recharts, supabase)
    ├── next.config.mjs             # Standalone output mode
    ├── postcss.config.mjs          # Tailwind CSS 4 via PostCSS
    ├── eslint.config.mjs           # ESLint 9 flat config
    ├── src/
    │   ├── middleware.js            # Auth route guard (Supabase session + RBAC)
    │   ├── app/
    │   │   ├── layout.js           # Root layout (Inter + JetBrains Mono fonts)
    │   │   ├── globals.css         # Cybersecurity design system (dark theme)
    │   │   ├── page.js             # Main dashboard (live threat feed + metrics)
    │   │   ├── analytics/page.js   # Historical charts (time-series, pie, bar)
    │   │   ├── admin/
    │   │   │   ├── layout.js       # Admin metadata
    │   │   │   └── page.js         # Admin panel (tabs: IP, WAF, Logs)
    │   │   ├── login/page.js       # Sign in page
    │   │   ├── signup/page.js      # Registration page
    │   │   └── auth/callback/route.js  # OAuth/email confirmation handler
    │   ├── components/
    │   │   ├── MetricCards.js       # Dashboard stat cards (4 metrics)
    │   │   ├── RealTimeLogStream.js # Live incident table (realtime/polling)
    │   │   ├── ThreatModal.js      # Incident detail overlay + replay + block
    │   │   ├── BlocklistManager.js # IP blocklist/allowlist CRUD
    │   │   ├── WAFRuleManager.js   # WAF rule editor (add/toggle/delete)
    │   │   └── AccessLogViewer.js  # Access log table with filters
    │   └── lib/
    │       ├── supabaseClient.js   # Browser Supabase client
    │       └── supabaseServer.js   # Server Supabase client
    └── public/                     # Static assets
```

---

## Dashboard Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | **Monitor** | Live threat feed, metric cards, real-time incident table |
| `/analytics` | **Analytics** | Time-series chart, threat type pie chart, severity bar chart, top endpoints |
| `/admin` | **Admin** | Tabbed panel: IP Management, WAF Rules, Access Logs |
| `/login` | **Login** | Supabase email/password authentication |
| `/signup` | **Signup** | New operator registration |

---

## Network Ports

| Service | Port | Purpose |
|---------|------|---------|
| Gateway | `5000` | WAF + Rate Limiting + API |
| Dashboard | `3000` | Next.js SOC Interface |
| Redis | `6379` | Rate limiter ZSET storage |
| Postgres | `5433` | Local fallback database |

---

## Deployment

### Gateway → Railway / Render / Fly.io

1. Set root directory to `gateway`
2. Build command: `npm ci --omit=dev`
3. Start command: `node src/server.js`
4. Add environment variables (Redis URL, Supabase keys, AI provider)
5. Set `TRUST_PROXY=true` and `CORS_ORIGIN=https://your-dashboard.vercel.app`

### Dashboard → Vercel

1. Set root directory to `dashboard`
2. Framework preset: Next.js (auto-detected)
3. Add `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `NEXT_PUBLIC_GATEWAY_URL`

### Redis → Upstash / Railway / Redis Cloud

Use any managed Redis provider and set the `REDIS_URL` environment variable.

### Database → Supabase

1. Create a project at [supabase.com](https://supabase.com)
2. Run `gateway/init.sql` in the SQL Editor
3. Enable Realtime replication on `security_incidents` for live feed

---

## Database Schema

| Table | Purpose | Rows |
|-------|---------|------|
| `security_incidents` | Every WAF block and rate-limit event | Grows with traffic |
| `clients_config` | Per-client API keys and rate limits | Manual entries |
| `profiles` | User accounts (extends Supabase Auth) | Per user |
| `blocked_ips` | IP blocklist (instant 403) | Manual/auto entries |
| `allowed_ips` | IP allowlist (bypass rate limiting) | Manual entries |
| `access_log` | Full request log (opt-in via `LOG_ALL_REQUESTS`) | Grows with traffic |
| `waf_rules` | Hot-reloadable WAF regex patterns | ~55 default rules |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation
- `perf:` — Performance improvement
- `refactor:` — Code refactoring
- `test:` — Tests
- `chore:` — Maintenance

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with security in mind** ⛨

</div>
]]>
