import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getEnvConfig } from '../config/env';
import { getUserByEmail, updateLastActivity } from '../lib/dynamo';
import { jsonResponse, logSafe } from '../lib/http';
import { verifyAccessToken } from '../lib/jwt';
import { AuthenticatedContext } from '../types/auth';

export type AuthResult =
  | { ok: true; context: AuthenticatedContext }
  | { ok: false; response: APIGatewayProxyResult };

function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader) {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  return match ? match[1].trim() : null;
}

export async function authenticateRequest(event: APIGatewayProxyEvent): Promise<AuthResult> {
  const token = extractBearerToken(event);
  if (!token) {
    return {
      ok: false,
      response: jsonResponse(401, { error: 'Authentication required' }),
    };
  }

  const env = getEnvConfig();
  let claims;
  try {
    claims = verifyAccessToken(token, {
      publicKey: env.jwtPublicKey,
      issuer: env.jwtIssuer,
    });
  } catch {
    return {
      ok: false,
      response: jsonResponse(401, { error: 'Invalid or expired access token' }),
    };
  }

  const user = await getUserByEmail(claims.sub);
  if (!user || user.status !== 'ACTIVE') {
    return {
      ok: false,
      response: jsonResponse(401, { error: 'Session is not active' }),
    };
  }

  if (
    user.sessionStatus !== 'ACTIVE' ||
    !user.activeSessionId ||
    user.activeSessionId !== claims.sid ||
    user.activeDeviceId !== claims.deviceId
  ) {
    return {
      ok: false,
      response: jsonResponse(401, {
        error: 'Session revoked or replaced on another device',
        code: 'SESSION_REVOKED',
      }),
    };
  }

  const nowMs = Date.now();
  const lastActivityMs = user.lastActivityAt ? Date.parse(user.lastActivityAt) : 0;
  if (!lastActivityMs || nowMs - lastActivityMs > env.inactivityLimitMs) {
    return {
      ok: false,
      response: jsonResponse(401, {
        error: 'Session expired due to inactivity',
        code: 'INACTIVITY_EXPIRED',
      }),
    };
  }

  const nowIso = new Date(nowMs).toISOString();
  const inactivityCutoffIso = new Date(nowMs - env.inactivityLimitMs).toISOString();

  try {
    const updatedUser = await updateLastActivity({
      email: user.email,
      sessionId: claims.sid,
      nowIso,
      inactivityCutoffIso,
    });

    return {
      ok: true,
      context: {
        user: updatedUser,
        claims,
      },
    };
  } catch (err) {
    logSafe('warn', 'Failed conditional activity update during auth', {
      email: user.email,
      errorName: err instanceof Error ? err.name : 'UnknownError',
    });
    return {
      ok: false,
      response: jsonResponse(401, {
        error: 'Session is no longer active',
        code: 'SESSION_REVOKED',
      }),
    };
  }
}
