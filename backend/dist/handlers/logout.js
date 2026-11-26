"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleLogout = handleLogout;
const dynamo_1 = require("../lib/dynamo");
const http_1 = require("../lib/http");
const authenticate_1 = require("../middleware/authenticate");
async function handleLogout(event) {
    const auth = await (0, authenticate_1.authenticateRequest)(event);
    if (!auth.ok) {
        return auth.response;
    }
    const body = (0, http_1.parseJsonBody)(event);
    const requestedSid = body && typeof body.sessionId === 'string' ? body.sessionId.trim() : auth.context.claims.sid;
    if (!requestedSid || requestedSid !== auth.context.claims.sid) {
        return (0, http_1.jsonResponse)(400, { error: 'Invalid sessionId' });
    }
    try {
        await (0, dynamo_1.revokeSession)({
            email: auth.context.user.email,
            sessionId: requestedSid,
        });
    }
    catch (err) {
        (0, http_1.logSafe)('warn', 'Logout conditional update failed', {
            email: auth.context.user.email,
            sessionId: requestedSid,
            errorName: err instanceof Error ? err.name : 'UnknownError',
        });
        return (0, http_1.jsonResponse)(401, { error: 'Session already revoked' });
    }
    (0, http_1.logSafe)('info', 'User logged out', {
        email: auth.context.user.email,
        sessionId: requestedSid,
    });
    return (0, http_1.jsonResponse)(200, {
        success: true,
        message: 'Logged out successfully',
    });
}
