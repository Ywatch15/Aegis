// ============================================================
// AegisAPI — IP Geolocation Service
// Uses geoip-lite (free MaxMind GeoLite2 data bundled in npm)
// Zero network calls — entire DB loaded in memory (~60MB)
// ============================================================

import geoip from 'geoip-lite';

/**
 * Look up geolocation data for an IP address.
 * @param {string} ip - IPv4 or IPv6 address
 * @returns {{ country: string, city: string, lat: number|null, lon: number|null }}
 */
export function lookupIP(ip) {
    // Strip IPv6 prefix for IPv4-mapped addresses (::ffff:127.0.0.1)
    const cleanIP = ip?.replace(/^::ffff:/, '') || '';

    // Private/localhost IPs return null from geoip-lite
    const privateRanges = [
        /^127\./,
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./,
        /^::1$/,
        /^localhost$/,
    ];

    if (!cleanIP || privateRanges.some((r) => r.test(cleanIP))) {
        return { country: 'LCL', city: 'Private', lat: null, lon: null };
    }

    const geo = geoip.lookup(cleanIP);

    if (!geo) {
        return { country: '---', city: 'Unknown', lat: null, lon: null };
    }

    return {
        country: geo.country || '---',
        city: geo.city || 'Unknown',
        lat: geo.ll?.[0] || null,
        lon: geo.ll?.[1] || null,
    };
}
