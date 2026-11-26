"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyPassword = verifyPassword;
exports.hashRefreshToken = hashRefreshToken;
exports.generateRefreshToken = generateRefreshToken;
exports.generateSessionId = generateSessionId;
const node_crypto_1 = require("node:crypto");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
async function verifyPassword(password, passwordHash) {
    if (!password || !passwordHash) {
        return false;
    }
    return bcryptjs_1.default.compare(password, passwordHash);
}
function hashRefreshToken(rawToken) {
    return (0, node_crypto_1.createHash)('sha256').update(rawToken, 'utf8').digest('hex');
}
function generateRefreshToken() {
    return (0, node_crypto_1.randomBytes)(48).toString('base64url');
}
function generateSessionId() {
    return (0, node_crypto_1.randomUUID)();
}
