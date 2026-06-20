// ============================================================
// AegisAPI — OWASP Core Rule Set (Curated Subset)
// ~50 high-value patterns from the OWASP CRS project
// Source: https://coreruleset.org/ (Apache 2.0 license — 100% free)
// ============================================================

/**
 * Curated OWASP CRS patterns organized by category.
 * Each entry: { name, pattern (string for RegExp constructor), severity, description }
 */
export const owaspRules = [
    // ── SQLi Advanced ───────────────────────────────────────
    { name: 'OWASP-SQLI-001', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:union\\s+(?:all\\s+)?select\\s)', description: 'UNION SELECT injection' },
    { name: 'OWASP-SQLI-002', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:;\\s*(?:drop|alter|create|truncate)\\s)', description: 'DDL injection via semicolon' },
    { name: 'OWASP-SQLI-003', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:(?:benchmark|sleep|waitfor|delay)\\s*\\()', description: 'Time-based blind SQLi' },
    { name: 'OWASP-SQLI-004', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:convert\\s*\\(|cast\\s*\\()', description: 'Type casting injection' },
    { name: 'OWASP-SQLI-005', category: 'SQLI', severity: 'MEDIUM', pattern: '(?i)(?:having\\s+\\d+\\s*=)', description: 'HAVING clause injection' },
    { name: 'OWASP-SQLI-006', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:group\\s+by\\s+.+\\s+having)', description: 'GROUP BY HAVING injection' },
    { name: 'OWASP-SQLI-007', category: 'SQLI', severity: 'MEDIUM', pattern: '(?i)(?:order\\s+by\\s+\\d+)', description: 'ORDER BY column enumeration' },
    { name: 'OWASP-SQLI-008', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:into\\s+(?:out|dump)file)', description: 'File write via SQL' },
    { name: 'OWASP-SQLI-009', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:load_file\\s*\\(|load\\s+data\\s+infile)', description: 'File read via SQL' },
    { name: 'OWASP-SQLI-010', category: 'SQLI', severity: 'HIGH', pattern: '(?i)(?:0x[0-9a-f]{8,})', description: 'Hex-encoded SQL payload' },
    { name: 'OWASP-SQLI-011', category: 'SQLI', severity: 'MEDIUM', pattern: '(?i)(?:(?:\\/\\*!|\\*\\/))', description: 'MySQL conditional comment injection' },

    // ── XSS Advanced ────────────────────────────────────────
    { name: 'OWASP-XSS-001', category: 'XSS', severity: 'HIGH', pattern: '(?i)(?:<script[^>]*>[\\s\\S]*?<\\/script>)', description: 'Full script block injection' },
    { name: 'OWASP-XSS-002', category: 'XSS', severity: 'MEDIUM', pattern: '(?i)(?:on(?:error|load|click|mouse|focus|blur|key|submit|reset|change|input|drag|drop|touch)\\s*=)', description: 'DOM event handler injection' },
    { name: 'OWASP-XSS-003', category: 'XSS', severity: 'HIGH', pattern: '(?i)(?:javascript\\s*:\\s*(?:alert|confirm|prompt|eval|document|window))', description: 'JavaScript URI with dangerous function' },
    { name: 'OWASP-XSS-004', category: 'XSS', severity: 'MEDIUM', pattern: '(?i)(?:<(?:img|input|body|svg|video|audio|source|iframe|embed|object)[^>]+on\\w+\\s*=)', description: 'Event handler on HTML element' },
    { name: 'OWASP-XSS-005', category: 'XSS', severity: 'HIGH', pattern: '(?i)(?:document\\.(?:cookie|domain|write|location))', description: 'DOM property access' },
    { name: 'OWASP-XSS-006', category: 'XSS', severity: 'HIGH', pattern: '(?i)(?:window\\.(?:location|open|eval|execScript))', description: 'Window object manipulation' },
    { name: 'OWASP-XSS-007', category: 'XSS', severity: 'MEDIUM', pattern: '(?i)(?:(?:set|get)(?:Timeout|Interval)\\s*\\(["\'])', description: 'Timer-based XSS' },
    { name: 'OWASP-XSS-008', category: 'XSS', severity: 'HIGH', pattern: '(?i)(?:String\\.fromCharCode|atob\\s*\\(|btoa\\s*\\()', description: 'Encoded XSS payload' },
    { name: 'OWASP-XSS-009', category: 'XSS', severity: 'MEDIUM', pattern: '(?i)(?:data\\s*:\\s*(?:text\\/html|application\\/x?html))', description: 'Data URI XSS' },

    // ── Path Traversal / LFI ────────────────────────────────
    { name: 'OWASP-LFI-001', category: 'PATH_TRAVERSAL', severity: 'HIGH', pattern: '(?:(?:\\.\\.[\\/\\\\]){3,})', description: 'Deep path traversal (3+ levels)' },
    { name: 'OWASP-LFI-002', category: 'PATH_TRAVERSAL', severity: 'HIGH', pattern: '(?i)(?:\\/etc\\/(?:passwd|shadow|hosts|group|issue|motd))', description: 'Linux sensitive file access' },
    { name: 'OWASP-LFI-003', category: 'PATH_TRAVERSAL', severity: 'HIGH', pattern: '(?i)(?:\\/proc\\/(?:self|version|cpuinfo|meminfo|mounts))', description: 'Linux procfs access' },
    { name: 'OWASP-LFI-004', category: 'PATH_TRAVERSAL', severity: 'HIGH', pattern: '(?i)(?:(?:c|d):\\\\(?:windows|winnt|boot\\.ini|autoexec))', description: 'Windows system file access' },
    { name: 'OWASP-LFI-005', category: 'PATH_TRAVERSAL', severity: 'MEDIUM', pattern: '(?i)(?:%(?:00|0a|0d|25))', description: 'Null byte / CRLF in path' },
    { name: 'OWASP-LFI-006', category: 'PATH_TRAVERSAL', severity: 'MEDIUM', pattern: '(?i)(?:\\.(?:htaccess|htpasswd|git|svn|env))', description: 'Hidden config file access' },

    // ── Command Injection Advanced ──────────────────────────
    { name: 'OWASP-CMD-001', category: 'CMD_INJECTION', severity: 'HIGH', pattern: '(?i)(?:;\\s*(?:(?:net(?:stat)?|ifconfig|ip\\s+addr|whoami|id|uname|hostname|pwd)\\b))', description: 'System recon command' },
    { name: 'OWASP-CMD-002', category: 'CMD_INJECTION', severity: 'HIGH', pattern: '(?i)(?:(?:\\||;|&&|\\|\\|)\\s*(?:nc|ncat|netcat|socat)\\s)', description: 'Netcat reverse shell' },
    { name: 'OWASP-CMD-003', category: 'CMD_INJECTION', severity: 'HIGH', pattern: '(?i)(?:(?:bash|sh|zsh|csh|ksh|dash)\\s+-[ci])', description: 'Interactive shell spawn' },
    { name: 'OWASP-CMD-004', category: 'CMD_INJECTION', severity: 'HIGH', pattern: '(?i)(?:(?:python|perl|ruby|php|node)\\s+-e)', description: 'Scripting language one-liner' },
    { name: 'OWASP-CMD-005', category: 'CMD_INJECTION', severity: 'HIGH', pattern: '(?i)(?:(?:chmod|chown|chgrp)\\s+(?:\\d{3,4}|[ugoa]))', description: 'Permission modification' },
    { name: 'OWASP-CMD-006', category: 'CMD_INJECTION', severity: 'HIGH', pattern: '(?i)(?:(?:cron|at)\\s|crontab)', description: 'Scheduled task injection' },

    // ── SSRF (Server-Side Request Forgery) ───────────────────
    { name: 'OWASP-SSRF-001', category: 'SSRF', severity: 'HIGH', pattern: '(?i)(?:(?:https?|ftp|gopher|dict|ldap):\\/\\/(?:127\\.|0\\.|10\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.|192\\.168\\.))', description: 'SSRF to private IP' },
    { name: 'OWASP-SSRF-002', category: 'SSRF', severity: 'HIGH', pattern: '(?i)(?:(?:https?|ftp):\\/\\/(?:localhost|0\\.0\\.0\\.0|\\[::1?\\]))', description: 'SSRF to localhost' },
    { name: 'OWASP-SSRF-003', category: 'SSRF', severity: 'MEDIUM', pattern: '(?i)(?:(?:https?:\\/\\/169\\.254\\.169\\.254))', description: 'AWS metadata SSRF' },
    { name: 'OWASP-SSRF-004', category: 'SSRF', severity: 'MEDIUM', pattern: '(?i)(?:(?:https?:\\/\\/metadata\\.google))', description: 'GCP metadata SSRF' },

    // ── HTTP Protocol Attacks ───────────────────────────────
    { name: 'OWASP-PROTO-001', category: 'PROTOCOL', severity: 'HIGH', pattern: '(?i)(?:(?:transfer-encoding|content-length)\\s*:\\s*(?:chunked|\\d+).*(?:transfer-encoding|content-length))', description: 'HTTP request smuggling' },
    { name: 'OWASP-PROTO-002', category: 'PROTOCOL', severity: 'MEDIUM', pattern: '(?:\\r\\n\\r\\n|\\n\\n)', description: 'Header injection via CRLF in value' },

    // ── XML/XXE ─────────────────────────────────────────────
    { name: 'OWASP-XXE-001', category: 'XXE', severity: 'HIGH', pattern: '(?i)(?:<!(?:DOCTYPE|ENTITY)[^>]*(?:SYSTEM|PUBLIC))', description: 'XXE entity declaration' },
    { name: 'OWASP-XXE-002', category: 'XXE', severity: 'HIGH', pattern: '(?i)(?:<!ENTITY\\s+\\S+\\s+SYSTEM)', description: 'External entity injection' },

    // ── Template Injection ──────────────────────────────────
    { name: 'OWASP-SSTI-001', category: 'SSTI', severity: 'HIGH', pattern: '(?:\\{\\{.*(?:__|import|exec|eval|system|popen|subprocess).*\\}\\})', description: 'Server-side template injection' },
    { name: 'OWASP-SSTI-002', category: 'SSTI', severity: 'MEDIUM', pattern: '(?:\\$\\{.*(?:Runtime|ProcessBuilder|exec).*\\})', description: 'Java expression language injection' },

    // ── Log4Shell / JNDI ────────────────────────────────────
    { name: 'OWASP-LOG4J-001', category: 'LOG4SHELL', severity: 'HIGH', pattern: '(?i)(?:\\$\\{(?:jndi|lower|upper|env|sys|java)\\s*:)', description: 'Log4Shell / JNDI injection' },
    { name: 'OWASP-LOG4J-002', category: 'LOG4SHELL', severity: 'HIGH', pattern: '(?i)(?:\\$\\{j\\$\\{[^}]*\\}ndi)', description: 'Obfuscated JNDI injection' },

    // ── NoSQL Injection ─────────────────────────────────────
    { name: 'OWASP-NOSQL-001', category: 'NOSQLI', severity: 'HIGH', pattern: '(?i)(?:\\$(?:gt|gte|lt|lte|ne|in|nin|regex|exists|where)\\b)', description: 'MongoDB operator injection' },
    { name: 'OWASP-NOSQL-002', category: 'NOSQLI', severity: 'HIGH', pattern: '(?i)(?:\\{\\s*"\\$(?:or|and|not|nor)"\\s*:)', description: 'MongoDB logical operator injection' },
];

export default owaspRules;
