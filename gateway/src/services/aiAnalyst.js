// ============================================================
// AegisAPI — Multi-Provider AI Threat Analyzer
// Works with any OpenAI-compatible API (NVIDIA NIM, OpenAI, Groq, Mistral, Ollama)
// Batch mode: collects incidents for 3s, processes up to 5 per API call
// Runs asynchronously — never blocks HTTP request lifecycle
// ============================================================

import { telemetryEmitter } from '../middleware/telemetryPipes.js';
import db from '../config/database.js';

// ── Configuration ───────────────────────────────────────────
const AI_CONFIG = {
    baseUrl: process.env.AI_PROVIDER_BASE_URL || '',
    apiKey: process.env.AI_PROVIDER_API_KEY || '',
    model: process.env.AI_PROVIDER_MODEL || 'meta/llama-3.1-70b-instruct',
};

const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1000;
const BATCH_WINDOW_MS = 3000;  // Wait 3s before processing batch
const MAX_BATCH_SIZE = 5;       // Max incidents per API call

// ── Batch queue ─────────────────────────────────────────────
let batchQueue = [];
let batchTimer = null;

// ── System prompt for cybersecurity analysis ────────────────
const SYSTEM_PROMPT = `You are an expert cybersecurity analyst working in a Security Operations Center (SOC).
You analyze intercepted malicious HTTP payloads caught by a Web Application Firewall (WAF).

For each incident, assess:
1. The severity of the attack attempt (HIGH, MEDIUM, or LOW)
2. A concise technical summary of what the attacker was attempting

Severity guidelines:
- HIGH: SQL injection targeting data exfiltration, command injection, path traversal to sensitive files, sophisticated multi-vector attacks
- MEDIUM: XSS attempts, basic SQL injection probes, encoded evasion attempts
- LOW: Simple scanner noise, automated bot probes, rate limit violations, obvious payload testing

Always respond with ONLY a valid JSON object. No markdown, no extra text.`;

const BATCH_SYSTEM_PROMPT = `You are an expert cybersecurity analyst working in a Security Operations Center (SOC).
You analyze multiple intercepted malicious HTTP payloads caught by a Web Application Firewall (WAF).

For EACH incident in the batch, assess:
1. The severity of the attack attempt (HIGH, MEDIUM, or LOW)
2. A concise technical summary of what the attacker was attempting

Severity guidelines:
- HIGH: SQL injection targeting data exfiltration, command injection, path traversal to sensitive files, sophisticated multi-vector attacks
- MEDIUM: XSS attempts, basic SQL injection probes, encoded evasion attempts
- LOW: Simple scanner noise, automated bot probes, rate limit violations, obvious payload testing

Always respond with ONLY a valid JSON object. No markdown, no extra text.`;

/**
 * Analyze a single incident.
 */
async function analyzeWithAI(incident) {
    const userPrompt = `Analyze this intercepted malicious HTTP request:

IP Address: ${incident.ip_address}
Method: ${incident.request_method}
Path: ${incident.request_path}
Violation Type: ${incident.violation_type}
Origin: ${incident.country || '?'}/${incident.city || '?'}
Captured Payload Fragment: ${incident.payload_snapshot || 'N/A'}

Respond with ONLY this JSON structure:
{ "severity": "HIGH" | "MEDIUM" | "LOW", "summary": "<technical analysis in 1-2 sentences>" }`;

    return await callAI(SYSTEM_PROMPT, userPrompt, incident.id);
}

/**
 * Analyze a batch of incidents in a single API call (Optimization #5).
 */
async function analyzeBatchWithAI(incidents) {
    const incidentList = incidents.map((inc, i) =>
        `--- Incident ${i + 1} (ID: ${inc.id}) ---
IP: ${inc.ip_address} | Method: ${inc.request_method} | Path: ${inc.request_path}
Type: ${inc.violation_type} | Origin: ${inc.country || '?'}/${inc.city || '?'}
Payload: ${(inc.payload_snapshot || 'N/A').substring(0, 300)}`
    ).join('\n\n');

    const userPrompt = `Analyze these ${incidents.length} intercepted malicious HTTP requests:

${incidentList}

Respond with ONLY this JSON structure (an array with one entry per incident, in the same order):
{ "results": [ { "id": "<incident_id>", "severity": "HIGH" | "MEDIUM" | "LOW", "summary": "<technical analysis in 1-2 sentences>" } ] }`;

    return await callAI(BATCH_SYSTEM_PROMPT, userPrompt, 'batch');
}

/**
 * Call the AI API with retries and exponential backoff.
 */
async function callAI(systemPrompt, userPrompt, debugLabel) {
    const requestBody = {
        model: AI_CONFIG.model,
        messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
        ],
        temperature: 0.2,
        max_tokens: 512,
        response_format: { type: 'json_object' },
    };

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
            const response = await fetch(`${AI_CONFIG.baseUrl}/chat/completions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${AI_CONFIG.apiKey}`,
                },
                body: JSON.stringify(requestBody),
                signal: AbortSignal.timeout(30000), // 30s for batch
            });

            if (!response.ok) {
                const errorText = await response.text().catch(() => 'Unknown error');
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            const data = await response.json();
            const content = data.choices?.[0]?.message?.content;

            if (!content) {
                throw new Error('Empty response from AI provider');
            }

            return JSON.parse(content);
        } catch (err) {
            console.error(
                `[AEGIS:AI] Attempt ${attempt}/${MAX_RETRIES} failed for ${debugLabel}:`,
                err.message
            );

            if (attempt < MAX_RETRIES) {
                const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }

    return null;
}

/**
 * Process the batch queue.
 */
async function processBatch() {
    if (batchQueue.length === 0) return;

    const batch = batchQueue.splice(0, MAX_BATCH_SIZE);
    batchTimer = null;

    // If remaining items in queue, schedule next batch
    if (batchQueue.length > 0) {
        batchTimer = setTimeout(processBatch, BATCH_WINDOW_MS);
    }

    // Try batch mode first
    if (batch.length > 1) {
        try {
            console.log(`[AEGIS:AI] Batch analyzing ${batch.length} incidents`);
            const batchResult = await analyzeBatchWithAI(batch);

            if (batchResult?.results && Array.isArray(batchResult.results)) {
                for (const result of batchResult.results) {
                    const severity = ['HIGH', 'MEDIUM', 'LOW'].includes(result.severity) ? result.severity : 'MEDIUM';
                    const summary = typeof result.summary === 'string' ? result.summary.substring(0, 500) : 'Analysis completed.';

                    await db.updateIncident(result.id, {
                        severity_score: severity,
                        threat_summary: summary,
                    });
                    console.log(`[AEGIS:AI] Incident ${result.id} → ${severity}: ${summary.substring(0, 80)}...`);
                }
                return; // Batch succeeded
            }
        } catch (err) {
            console.error('[AEGIS:AI] Batch analysis failed, falling back to single mode:', err.message);
        }
    }

    // Fallback: process individually
    for (const incident of batch) {
        try {
            console.log(`[AEGIS:AI] Analyzing incident ${incident.id} [${incident.violation_type}]`);
            const parsed = await analyzeWithAI(incident);

            if (parsed) {
                const severity = ['HIGH', 'MEDIUM', 'LOW'].includes(parsed.severity) ? parsed.severity : 'MEDIUM';
                const summary = typeof parsed.summary === 'string' ? parsed.summary.substring(0, 500) : 'Analysis completed.';

                await db.updateIncident(incident.id, {
                    severity_score: severity,
                    threat_summary: summary,
                });
                console.log(`[AEGIS:AI] Incident ${incident.id} → ${severity}: ${summary.substring(0, 80)}...`);
            } else {
                await db.updateIncident(incident.id, {
                    severity_score: 'ERROR',
                    threat_summary: 'AI analysis failed after maximum retry attempts.',
                });
            }
        } catch (err) {
            console.error(`[AEGIS:AI] Error processing incident ${incident.id}:`, err.message);
            try {
                await db.updateIncident(incident.id, {
                    severity_score: 'ERROR',
                    threat_summary: `Analysis error: ${err.message}`,
                });
            } catch (_) { /* Silently fail */ }
        }
    }
}

/**
 * Initialize the AI analyzer — listens for incident events.
 * Uses batch mode with 3s debounce window (Optimization #5).
 */
export function initAIAnalyst() {
    if (!AI_CONFIG.baseUrl || !AI_CONFIG.apiKey) {
        console.log('[AEGIS:AI] No AI provider configured (AI_PROVIDER_BASE_URL / AI_PROVIDER_API_KEY empty)');
        console.log('[AEGIS:AI] Incidents will remain in PENDING state — gateway fully operational');
        return;
    }

    console.log(`[AEGIS:AI] Initialized with provider: ${AI_CONFIG.baseUrl}`);
    console.log(`[AEGIS:AI] Model: ${AI_CONFIG.model} | Batch: up to ${MAX_BATCH_SIZE} per call`);

    telemetryEmitter.on('incident:created', (incident) => {
        batchQueue.push(incident);

        // Start or reset the batch timer
        if (!batchTimer) {
            batchTimer = setTimeout(processBatch, BATCH_WINDOW_MS);
        }
    });
}
