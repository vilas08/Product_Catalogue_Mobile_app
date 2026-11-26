"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleMe = handleMe;
const http_1 = require("../lib/http");
const authenticate_1 = require("../middleware/authenticate");
async function handleMe(event) {
    const auth = await (0, authenticate_1.authenticateRequest)(event);
    if (!auth.ok) {
        return auth.response;
    }
    const { user } = auth.context;
    return (0, http_1.jsonResponse)(200, {
        user: {
            email: user.email,
            name: user.name,
            role: user.role,
            status: user.status,
            activeSessionId: user.activeSessionId,
            activeDeviceId: user.activeDeviceId,
            lastActivityAt: user.lastActivityAt,
            lastLogin: user.lastLogin,
        },
    });
}
