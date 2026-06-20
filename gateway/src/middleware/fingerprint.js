// ============================================================
// AegisAPI — Request Fingerprinting
// Hashes request headers to create a unique client fingerprint
// Detects distributed bot attacks that rotate IPs
// ============================================================

import crypto from 'node:crypto';

/**
 * Generate a fingerprint from request headers.
 * Combines User-Agent, Accept-Language, Accept-Encoding, Accept
 * into a SHA-256 hash truncated to 8 hex chars.
 *
 * @param {import('express').Request} req
 * @returns {string} 8-char hex fingerprint
 */
export function generateFingerprint(req) {
    const components = [
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.headers['accept-encoding'] || '',
        req.headers['accept'] || '',
        req.headers['sec-ch-ua'] || '',
    ].join('|');

    return crypto
        .createHash('sha256')
        .update(components)
        .digest('hex')
        .substring(0, 16);
}

/**
 * Express middleware — attaches req.fingerprint
 */
export default function fingerprintMiddleware(req, res, next) {
    req.fingerprint = generateFingerprint(req);
    next();
}
