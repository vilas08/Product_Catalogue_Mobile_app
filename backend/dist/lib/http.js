"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildCorsHeaders = buildCorsHeaders;
exports.jsonResponse = jsonResponse;
exports.parseJsonBody = parseJsonBody;
exports.logSafe = logSafe;
const env_1 = require("../config/env");
function buildCorsHeaders() {
    const { corsOrigin } = (0, env_1.getEnvConfig)();
    return {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': corsOrigin,
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
    };
}
function jsonResponse(statusCode, body) {
    return {
        statusCode,
        headers: buildCorsHeaders(),
        body: JSON.stringify(body),
    };
}
function parseJsonBody(event) {
    if (!event.body) {
        return null;
    }
    try {
        const raw = event.isBase64Encoded
            ? Buffer.from(event.body, 'base64').toString('utf8')
            : event.body;
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
function logSafe(level, message, meta) {
    const entry = {
        level,
        message,
        timestamp: new Date().toISOString(),
        ...(meta ? { meta } : {}),
    };
    if (level === 'error') {
        console.error(JSON.stringify(entry));
    }
    else if (level === 'warn') {
        console.warn(JSON.stringify(entry));
    }
    else {
        console.log(JSON.stringify(entry));
    }
}
