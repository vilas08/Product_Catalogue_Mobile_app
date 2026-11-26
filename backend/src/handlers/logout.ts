import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { revokeSession } from '../lib/dynamo';
import { jsonResponse, logSafe, parseJsonBody } from '../lib/http';
import { authenticateRequest } from '../middleware/authenticate';

interface LogoutBody {
  sessionId?: unknown;
}

export async function handleLogout(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const auth = await authenticateRequest(event);
  if (!auth.ok) {
    return auth.response;
  }

  const body = parseJsonBody<LogoutBody>(event);
  const requestedSid =
    body && typeof body.sessionId === 'string' ? body.sessionId.trim() : auth.context.claims.sid;

  if (!requestedSid || requestedSid !== auth.context.claims.sid) {
    return jsonResponse(400, { error: 'Invalid sessionId' });
  }

  try {
    await revokeSession({
      email: auth.context.user.email,
      sessionId: requestedSid,
    });
  } catch (err) {
    logSafe('warn', 'Logout conditional update failed', {
      email: auth.context.user.email,
      sessionId: requestedSid,
      errorName: err instanceof Error ? err.name : 'UnknownError',
    });
    return jsonResponse(401, { error: 'Session already revoked' });
  }

  logSafe('info', 'User logged out', {
    email: auth.context.user.email,
    sessionId: requestedSid,
  });

  return jsonResponse(200, {
    success: true,
    message: 'Logged out successfully',
  });
}
