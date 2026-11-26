"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.signAccessToken = signAccessToken;
exports.signOfflineToken = signOfflineToken;
exports.verifyAccessToken = verifyAccessToken;
exports.verifyOfflineTokenServerSide = verifyOfflineTokenServerSide;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function signAccessToken(input) {
    return jsonwebtoken_1.default.sign({
        sid: input.sessionId,
        deviceId: input.deviceId,
        tokenType: 'access',
    }, input.privateKey, {
        algorithm: 'RS256',
        subject: input.email,
        audience: 'mobile-api',
        issuer: input.issuer,
        expiresIn: input.expiresIn,
    });
}
function signOfflineToken(input) {
    return jsonwebtoken_1.default.sign({
        sid: input.sessionId,
        deviceId: input.deviceId,
        tokenType: 'offline',
    }, input.privateKey, {
        algorithm: 'RS256',
        subject: input.email,
        audience: 'mobile-offline',
        issuer: input.issuer,
        expiresIn: input.expiresIn,
    });
}
function verifyAccessToken(token, options) {
    const decoded = jsonwebtoken_1.default.verify(token, options.publicKey, {
        algorithms: ['RS256'],
        audience: 'mobile-api',
        issuer: options.issuer,
    });
    if (typeof decoded === 'string' || !decoded) {
        throw new Error('Invalid token payload');
    }
    const claims = decoded;
    if (claims.tokenType !== 'access' ||
        typeof claims.sub !== 'string' ||
        typeof claims.sid !== 'string' ||
        typeof claims.deviceId !== 'string') {
        throw new Error('Invalid access token claims');
    }
    return claims;
}
function verifyOfflineTokenServerSide(token, options) {
    const decoded = jsonwebtoken_1.default.verify(token, options.publicKey, {
        algorithms: ['RS256'],
        audience: 'mobile-offline',
        issuer: options.issuer,
    });
    if (typeof decoded === 'string' || !decoded) {
        throw new Error('Invalid offline token payload');
    }
    const claims = decoded;
    if (claims.tokenType !== 'offline' ||
        typeof claims.sub !== 'string' ||
        typeof claims.sid !== 'string' ||
        typeof claims.deviceId !== 'string') {
        throw new Error('Invalid offline token claims');
    }
    return claims;
}
