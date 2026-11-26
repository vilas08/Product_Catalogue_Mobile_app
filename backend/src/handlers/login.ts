import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getEnvConfig } from '../config/env';
import {
  generateRefreshToken,
  generateSessionId,
  hashRefreshToken,
  verifyPassword,
} from '../lib/crypto';
import { getUserByEmail, replaceSessionOnLogin } from '../lib/dynamo';
import { jsonResponse, logSafe, parseJsonBody } from '../lib/http';
import { signAccessToken, signOfflineToken } from '../lib/jwt';
import { getJwtPrivateKey } from '../lib/secrets';

interface LoginBody {
  email?: unknown;
  password?: unknown;
  deviceId?: unknown;
}

const GENERIC_LOGIN_ERROR = 'Invalid email or password';

export async function handleLogin(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const body = parseJsonBody<LoginBody>(event);
  if (!body) {
    return jsonResponse(400, { error: 'Invalid request body' });
  }

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';

  if (!email || !password || !deviceId || deviceId.length > 128) {
    return jsonResponse(400, { error: 'Email, password, and deviceId are required' });
  }

  const user = await getUserByEmail(email);
  if (!user) {
    return jsonResponse(401, { error: GENERIC_LOGIN_ERROR });
  }

  const passwordValid = await verifyPassword(password, user.passwordHash);
  if (!passwordValid) {
    return jsonResponse(401, { error: GENERIC_LOGIN_ERROR });
  }

  if (user.status !== 'ACTIVE') {
    return jsonResponse(401, { error: GENERIC_LOGIN_ERROR });
  }

  const env = getEnvConfig();
  const privateKey = await getJwtPrivateKey();

  const sessionId = generateSessionId();
  const refreshToken = generateRefreshToken();
  const refreshTokenHash = hashRefreshToken(refreshToken);

  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const refreshExpiresAt = new Date(nowMs + env.refreshTokenExpiryMs).toISOString();

  try {
    await replaceSessionOnLogin({
      email: user.email,
      sessionId,
      deviceId,
      refreshTokenHash,
      refreshExpiresAt,
      nowIso,
    });
  } catch (err) {
    logSafe('warn', 'Login conditional update failed', {
      email: user.email,
      errorName: err instanceof Error ? err.name : 'UnknownError',
    });
    return jsonResponse(401, { error: GENERIC_LOGIN_ERROR });
  }

  const accessToken = signAccessToken({
    email: user.email,
    sessionId,
    deviceId,
    privateKey,
    issuer: env.jwtIssuer,
    expiresIn: env.jwtAccessExpiry,
  });

  const offlineToken = signOfflineToken({
    email: user.email,
    sessionId,
    deviceId,
    privateKey,
    issuer: env.jwtIssuer,
    expiresIn: env.jwtOfflineExpiry,
  });

  logSafe('info', 'User logged in', { email: user.email, deviceId, sessionId });

  return jsonResponse(200, {
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
