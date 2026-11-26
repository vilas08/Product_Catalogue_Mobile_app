"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleLogin = handleLogin;
const env_1 = require("../config/env");
const crypto_1 = require("../lib/crypto");
const dynamo_1 = require("../lib/dynamo");
const http_1 = require("../lib/http");
const jwt_1 = require("../lib/jwt");
const secrets_1 = require("../lib/secrets");
const GENERIC_LOGIN_ERROR = 'Invalid email or password';
async function handleLogin(event) {
    const body = (0, http_1.parseJsonBody)(event);
    if (!body) {
        return (0, http_1.jsonResponse)(400, { error: 'Invalid request body' });
    }
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
    if (!email || !password || !deviceId || deviceId.length > 128) {
        return (0, http_1.jsonResponse)(400, { error: 'Email, password, and deviceId are required' });
    }
    const user = await (0, dynamo_1.getUserByEmail)(email);
    if (!user) {
        return (0, http_1.jsonResponse)(401, { error: GENERIC_LOGIN_ERROR });
    }
    const passwordValid = await (0, crypto_1.verifyPassword)(password, user.passwordHash);
    if (!passwordValid) {
        return (0, http_1.jsonResponse)(401, { error: GENERIC_LOGIN_ERROR });
    }
    if (user.status !== 'ACTIVE') {
        return (0, http_1.jsonResponse)(401, { error: GENERIC_LOGIN_ERROR });
    }
    const env = (0, env_1.getEnvConfig)();
    const privateKey = await (0, secrets_1.getJwtPrivateKey)();
    const sessionId = (0, crypto_1.generateSessionId)();
    const refreshToken = (0, crypto_1.generateRefreshToken)();
    const refreshTokenHash = (0, crypto_1.hashRefreshToken)(refreshToken);
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const refreshExpiresAt = new Date(nowMs + env.refreshTokenExpiryMs).toISOString();
    try {
        await (0, dynamo_1.replaceSessionOnLogin)({
            email: user.email,
            sessionId,
            deviceId,
            refreshTokenHash,
            refreshExpiresAt,
            nowIso,
        });
    }
    catch (err) {
        (0, http_1.logSafe)('warn', 'Login conditional update failed', {
            email: user.email,
            errorName: err instanceof Error ? err.name : 'UnknownError',
        });
        return (0, http_1.jsonResponse)(401, { error: GENERIC_LOGIN_ERROR });
    }
    const accessToken = (0, jwt_1.signAccessToken)({
        email: user.email,
        sessionId,
        deviceId,
        privateKey,
        issuer: env.jwtIssuer,
        expiresIn: env.jwtAccessExpiry,
    });
    const offlineToken = (0, jwt_1.signOfflineToken)({
        email: user.email,
        sessionId,
        deviceId,
        privateKey,
        issuer: env.jwtIssuer,
        expiresIn: env.jwtOfflineExpiry,
    });
    (0, http_1.logSafe)('info', 'User logged in', { email: user.email, deviceId, sessionId });
    return (0, http_1.jsonResponse)(200, {
        accessToken,
        refreshToken,
        offlineToken,
        sessionId,
        deviceId,
        user: {
            email: user.email,
            name: user.name,
            role: user.role,
            status: user.status,
        },
    });
}
