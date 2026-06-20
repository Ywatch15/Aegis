// ============================================================
// AegisAPI — WAF Threat Signature Dictionary
// Regex patterns for detecting common attack vectors
// ============================================================

/**
 * Threat signatures organized by attack category.
 * Each regex is case-insensitive and designed to catch common variants.
 *
 * IMPORTANT: These are inspected against JSON.stringify(input),
 * so JSON structural characters won't trigger false positives
 * as long as we test body/query/params separately.
 */
export const threatSignatures = {
    SQLI: new RegExp([
        'UNION\\s+SELECT',
        'UNION\\s+ALL\\s+SELECT',
        "'\\s*OR\\s+'1'\\s*=\\s*'1",
        "'\\s*OR\\s+1\\s*=\\s*1",
        '--\\s',
        'SELECT\\s+.*\\s+FROM\\s',
        ';\\s*DROP\\s+TABLE',
        ';\\s*DELETE\\s+FROM',
        ';\\s*INSERT\\s+INTO',
        ';\\s*UPDATE\\s+.*\\s+SET',
        'EXEC\\s*\\(',
        'EXECUTE\\s*\\(',
        'xp_cmdshell',
        'WAITFOR\\s+DELAY',
        'BENCHMARK\\s*\\(',
        'LOAD_FILE\\s*\\(',
        'INTO\\s+OUTFILE',
        'INTO\\s+DUMPFILE',
        'INFORMATION_SCHEMA',
        'CHAR\\s*\\(\\s*\\d+',
    ].join('|'), 'i'),

    XSS: new RegExp([
        '<script[\\s>]',
        '</script>',
        'javascript\\s*:',
        'vbscript\\s*:',
        'onerror\\s*=',
        'onload\\s*=',
        'onclick\\s*=',
        'onmouseover\\s*=',
        'onfocus\\s*=',
        'onblur\\s*=',
        '<iframe',
        '<embed',
        '<object',
        '<img[^>]+onerror',
        '<svg[^>]+onload',
        '<body[^>]+onload',
        'expression\\s*\\(',
        'eval\\s*\\(',
        'document\\.cookie',
        'document\\.write',
        'window\\.location',
        'String\\.fromCharCode',
    ].join('|'), 'i'),

    PATH_TRAVERSAL: new RegExp([
        '\\.\\.\\/(?!\\s)',
        '\\.\\.\\\\',
        '%2e%2e%2f',
        '%2e%2e\\\\',
        '%2e%2e/',
        '\\.\\.%2f',
        '%252e%252e',
        '\\/etc\\/passwd',
        '\\/etc\\/shadow',
        '\\/proc\\/self',
        '\\\\windows\\\\',
        '\\\\system32\\\\',
        '\\.\\.\\.\\.\\/\\/',
    ].join('|'), 'i'),

    CMD_INJECTION: new RegExp([
        ';\\s*ls\\b',
        ';\\s*cat\\b',
        ';\\s*rm\\b',
        ';\\s*wget\\b',
        ';\\s*curl\\b',
        '\\|\\s*cat\\b',
        '\\|\\s*ls\\b',
        '\\|\\s*grep\\b',
        '`[^`]+`',
        '\\$\\([^)]+\\)',
        '\\$\\{[^}]+\\}',
        '&&\\s*(ls|cat|rm|wget|curl|bash|sh|python|node)\\b',
        '\\|\\|\\s*(ls|cat|rm|wget|curl|bash|sh|python|node)\\b',
    ].join('|'), 'i'),
};

/**
 * Inspect a string against all threat signatures.
 * @param {string} input - The stringified input to check
 * @returns {string|null} - The violation type ('SQLI', 'XSS', etc.) or null if clean
 */
export function detectThreat(input) {
    if (!input || typeof input !== 'string') return null;

    for (const [type, pattern] of Object.entries(threatSignatures)) {
        if (pattern.test(input)) {
            return type;
        }
    }
    return null;
}
