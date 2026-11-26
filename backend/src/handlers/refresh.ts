import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getEnvConfig } from '../config/env';
import { generateRefreshToken, hashRefreshToken } from '../lib/crypto';
import { getUserByEmail, rotateRefreshToken } from '../lib/dynamo';
import { jsonResponse, logSafe, parseJsonBody } from '../lib/http';
import { signAccessToken } from '../lib/jwt';
import { getJwtPrivateKey } from '../lib/secrets';

interface RefreshBody {
  email?: unknown;
  refreshToken?: unknown;
  sessionId?: unknown;
}

export async function handleRefresh(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const body = parseJsonBody<RefreshBody>(event);
  if (!body) {
    return jsonResponse(400, { error: 'Invalid request body' });
  }

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const refreshToken = typeof body.refreshToken === 'string' ? body.refreshToken.trim() : '';
  const sessionId = typeof body.sessionId === 'string' ? body.sessionId.trim() : '';

  if (!email || !refreshToken || !sessionId) {
    return jsonResponse(400, { error: 'email, refreshToken, and sessionId are required' });
  }

  const incomingHash = hashRefreshToken(refreshToken);
  const user = await getUserByEmail(email);

  if (!user || user.status !== 'ACTIVE') {
    return jsonResponse(401, { error: 'Invalid session or credentials', code: 'SESSION_REVOKED' });
  }

  if (
    user.sessionStatus !== 'ACTIVE' ||
    !user.activeSessionId ||
    user.activeSessionId !== sessionId ||
    !user.activeDeviceId
  ) {
    return jsonResponse(401, { error: 'Session is no longer active', code: 'SESSION_REVOKED' });
  }

  if (!user.refreshTokenHash || user.refreshTokenHash !== incomingHash) {
    return jsonResponse(401, { error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
  }

  const nowMs = Date.now();
  const refreshExpiresMs = user.refreshExpiresAt ? Date.parse(user.refreshExpiresAt) : 0;
  if (!refreshExpiresMs || refreshExpiresMs <= nowMs) {
    return jsonResponse(401, { error: 'Refresh token expired', code: 'REFRESH_EXPIRED' });
  }

  const env = getEnvConfig();
  const lastActivityMs = user.lastActivityAt ? Date.parse(user.lastActivityAt) : 0;
  if (!lastActivityMs || nowMs - lastActivityMs > env.inactivityLimitMs) {
    return jsonResponse(401, {
      error: 'Session expired due to inactivity',
      code: 'INACTIVITY_EXPIRED',
    });
  }

  const newRefreshToken = generateRefreshToken();
  const newRefreshHash = hashRefreshToken(newRefreshToken);
  const nowIso = new Date(nowMs).toISOString();
  const newRefreshExpiresAt = new Date(nowMs + env.refreshTokenExpiryMs).toISOString();
  const inactivityCutoffIso = new Date(nowMs - env.inactivityLimitMs).toISOString();

  try {
    await rotateRefreshToken({
      email: user.email,
      expectedSessionId: sessionId,
      expectedRefreshHash: incomingHash,
      newRefreshHash,
      newRefreshExpiresAt,
      nowIso,
      inactivityCutoffIso,
    });
  } catch (err) {
    logSafe('warn', 'Atomic refresh rotation rejected (concurrent refresh or replay)', {
      email: user.email,
      sessionId,
      errorName: err instanceof Error ? err.name : 'UnknownError',
    });
    return jsonResponse(401, {
      error: 'Refresh token invalid or already used',
      code: 'SESSION_REVOKED',
    });
  }

  const privateKey = await getJwtPrivateKey();
  const accessToken = signAccessToken({
    email: user.email,
    sessionId,
    deviceId: user.activeDeviceId,
    privateKey,
    issuer: env.jwtIssuer,
    expiresIn: env.jwtAccessExpiry,
  });

  logSafe('info', 'Refresh token rotated', { email: user.email, sessionId });

  return jsonResponse(200, {
    accessToken,
    refreshToken: newRefreshToken,
    sessionId,
  });
}
