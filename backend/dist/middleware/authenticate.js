"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateRequest = authenticateRequest;
const env_1 = require("../config/env");
const dynamo_1 = require("../lib/dynamo");
const http_1 = require("../lib/http");
const jwt_1 = require("../lib/jwt");
function extractBearerToken(event) {
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    if (!authHeader) {
        return null;
    }
    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    return match ? match[1].trim() : null;
}
async function authenticateRequest(event) {
    const token = extractBearerToken(event);
    if (!token) {
        return {
            ok: false,
            response: (0, http_1.jsonResponse)(401, { error: 'Authentication required' }),
        };
    }
    const env = (0, env_1.getEnvConfig)();
    let claims;
    try {
        claims = (0, jwt_1.verifyAccessToken)(token, {
            publicKey: env.jwtPublicKey,
            issuer: env.jwtIssuer,
        });
    }
    catch {
        return {
            ok: false,
            response: (0, http_1.jsonResponse)(401, { error: 'Invalid or expired access token' }),
        };
    }
    const user = await (0, dynamo_1.getUserByEmail)(claims.sub);
    if (!user || user.status !== 'ACTIVE') {
        return {
            ok: false,
            response: (0, http_1.jsonResponse)(401, { error: 'Session is not active' }),
        };
    }
    if (user.sessionStatus !== 'ACTIVE' ||
        !user.activeSessionId ||
        user.activeSessionId !== claims.sid ||
        user.activeDeviceId !== claims.deviceId) {
        return {
            ok: false,
            response: (0, http_1.jsonResponse)(401, {
                error: 'Session revoked or replaced on another device',
                code: 'SESSION_REVOKED',
            }),
        };
    }
    const nowMs = Date.now();
    const lastActivityMs = user.lastActivityAt ? Date.parse(user.lastActivityAt) : 0;
    if (!lastActivityMs || nowMs - lastActivityMs > env.inactivityLimitMs) {
        return {
            ok: false,
            response: (0, http_1.jsonResponse)(401, {
                error: 'Session expired due to inactivity',
                code: 'INACTIVITY_EXPIRED',
            }),
        };
    }
    const nowIso = new Date(nowMs).toISOString();
    const inactivityCutoffIso = new Date(nowMs - env.inactivityLimitMs).toISOString();
    try {
        const updatedUser = await (0, dynamo_1.updateLastActivity)({
            email: user.email,
            sessionId: claims.sid,
            nowIso,
            inactivityCutoffIso,
        });
        return {
            ok: true,
            context: {
                user: updatedUser,
                claims,
            },
        };
    }
    catch (err) {
        (0, http_1.logSafe)('warn', 'Failed conditional activity update during auth', {
            email: user.email,
            errorName: err instanceof Error ? err.name : 'UnknownError',
        });
        return {
            ok: false,
            response: (0, http_1.jsonResponse)(401, {
                error: 'Session is no longer active',
                code: 'SESSION_REVOKED',
            }),
        };
    }
}
