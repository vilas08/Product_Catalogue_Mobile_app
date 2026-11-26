"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleActivity = handleActivity;
const http_1 = require("../lib/http");
const authenticate_1 = require("../middleware/authenticate");
async function handleActivity(event) {
    // authenticateRequest validates the active session, checks 7-day inactivity,
    // and updates lastActivityAt using server time (never client-supplied timestamps).
    const auth = await (0, authenticate_1.authenticateRequest)(event);
    if (!auth.ok) {
        return auth.response;
    }
    const body = (0, http_1.parseJsonBody)(event);
    const eventCount = Array.isArray(body?.events) ? body.events.length : 0;
    (0, http_1.logSafe)('info', 'Activity synchronized', {
        email: auth.context.user.email,
        sessionId: auth.context.claims.sid,
        syncedOfflineEvents: eventCount,
    });
    return (0, http_1.jsonResponse)(200, {
        success: true,
        lastActivityAt: auth.context.user.lastActivityAt,
        syncedEvents: eventCount,
    });
}
