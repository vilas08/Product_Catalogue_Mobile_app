"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = handler;
const activity_1 = require("./handlers/activity");
const login_1 = require("./handlers/login");
const logout_1 = require("./handlers/logout");
const me_1 = require("./handlers/me");
const refresh_1 = require("./handlers/refresh");
const http_1 = require("./lib/http");
async function handler(event) {
    const method = event.httpMethod?.toUpperCase() || '';
    const path = event.path || '';
    if (method === 'OPTIONS') {
        return {
            statusCode: 204,
            headers: (0, http_1.buildCorsHeaders)(),
            body: '',
        };
    }
    try {
        if (method === 'POST' && path.endsWith('/auth/login')) {
            return await (0, login_1.handleLogin)(event);
        }
        if (method === 'POST' && path.endsWith('/auth/refresh')) {
            return await (0, refresh_1.handleRefresh)(event);
        }
        if (method === 'POST' && path.endsWith('/auth/logout')) {
            return await (0, logout_1.handleLogout)(event);
        }
        if (method === 'GET' && path.endsWith('/auth/me')) {
            return await (0, me_1.handleMe)(event);
        }
        if (method === 'POST' && path.endsWith('/auth/activity')) {
            return await (0, activity_1.handleActivity)(event);
        }
        return (0, http_1.jsonResponse)(404, { error: 'Route not found' });
    }
    catch (err) {
        (0, http_1.logSafe)('error', 'Unhandled error in auth router', {
            method,
            path,
            errorName: err instanceof Error ? err.name : 'UnknownError',
        });
        return (0, http_1.jsonResponse)(500, { error: 'Internal server error' });
    }
}
