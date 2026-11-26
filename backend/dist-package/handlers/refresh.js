"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleRefresh = handleRefresh;
const env_1 = require("../config/env");
const crypto_1 = require("../lib/crypto");
const dynamo_1 = require("../lib/dynamo");
const http_1 = require("../lib/http");
const jwt_1 = require("../lib/jwt");
const secrets_1 = require("../lib/secrets");
async function handleRefresh(event) {
    const body = (0, http_1.parseJsonBody)(event);
    if (!body) {
        return (0, http_1.jsonResponse)(400, { error: 'Invalid request body' });
    }
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const refreshToken = typeof body.refreshToken === 'string' ? body.refreshToken.trim() : '';
    const sessionId = typeof body.sessionId === 'string' ? body.sessionId.trim() : '';
    if (!email || !refreshToken || !sessionId) {
        return (0, http_1.jsonResponse)(400, { error: 'email, refreshToken, and sessionId are required' });
    }
    const incomingHash = (0, crypto_1.hashRefreshToken)(refreshToken);
    const user = await (0, dynamo_1.getUserByEmail)(email);
    if (!user || user.status !== 'ACTIVE') {
        return (0, http_1.jsonResponse)(401, { error: 'Invalid session or credentials', code: 'SESSION_REVOKED' });
    }
    if (user.sessionStatus !== 'ACTIVE' ||
        !user.activeSessionId ||
        user.activeSessionId !== sessionId ||
        !user.activeDeviceId) {
        return (0, http_1.jsonResponse)(401, { error: 'Session is no longer active', code: 'SESSION_REVOKED' });
    }
    if (!user.refreshTokenHash || user.refreshTokenHash !== incomingHash) {
        return (0, http_1.jsonResponse)(401, { error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
    }
    const nowMs = Date.now();
    const refreshExpiresMs = user.refreshExpiresAt ? Date.parse(user.refreshExpiresAt) : 0;
    if (!refreshExpiresMs || refreshExpiresMs <= nowMs) {
        return (0, http_1.jsonResponse)(401, { error: 'Refresh token expired', code: 'REFRESH_EXPIRED' });
    }
    const env = (0, env_1.getEnvConfig)();
    const lastActivityMs = user.lastActivityAt ? Date.parse(user.lastActivityAt) : 0;
    if (!lastActivityMs || nowMs - lastActivityMs > env.inactivityLimitMs) {
        return (0, http_1.jsonResponse)(401, {
            error: 'Session expired due to inactivity',
            code: 'INACTIVITY_EXPIRED',
        });
    }
    const newRefreshToken = (0, crypto_1.generateRefreshToken)();
    const newRefreshHash = (0, crypto_1.hashRefreshToken)(newRefreshToken);
    const nowIso = new Date(nowMs).toISOString();
    const newRefreshExpiresAt = new Date(nowMs + env.refreshTokenExpiryMs).toISOString();
    const inactivityCutoffIso = new Date(nowMs - env.inactivityLimitMs).toISOString();
    try {
        await (0, dynamo_1.rotateRefreshToken)({
            email: user.email,
            expectedSessionId: sessionId,
            expectedRefreshHash: incomingHash,
            newRefreshHash,
            newRefreshExpiresAt,
            nowIso,
            inactivityCutoffIso,
        });
    }
    catch (err) {
        (0, http_1.logSafe)('warn', 'Atomic refresh rotation rejected (concurrent refresh or replay)', {
            email: user.email,
            sessionId,
            errorName: err instanceof Error ? err.name : 'UnknownError',
        });
        return (0, http_1.jsonResponse)(401, {
            error: 'Refresh token invalid or already used',
            code: 'SESSION_REVOKED',
        });
    }
    const privateKey = await (0, secrets_1.getJwtPrivateKey)();
    const accessToken = (0, jwt_1.signAccessToken)({
        email: user.email,
        sessionId,
        deviceId: user.activeDeviceId,
        privateKey,
        issuer: env.jwtIssuer,
        expiresIn: env.jwtAccessExpiry,
    });
    (0, http_1.logSafe)('info', 'Refresh token rotated', { email: user.email, sessionId });
    return (0, http_1.jsonResponse)(200, {
        accessToken,
        refreshToken: newRefreshToken,
        sessionId,
    });
}
