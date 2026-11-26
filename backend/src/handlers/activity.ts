import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { jsonResponse, logSafe, parseJsonBody } from '../lib/http';
import { authenticateRequest } from '../middleware/authenticate';

interface ActivityEvent {
  action?: unknown;
  timestamp?: unknown;
}

interface ActivityBody {
  events?: ActivityEvent[];
}

export async function handleActivity(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  // authenticateRequest validates the active session, checks 7-day inactivity,
  // and updates lastActivityAt using server time (never client-supplied timestamps).
  const auth = await authenticateRequest(event);
  if (!auth.ok) {
    return auth.response;
  }

  const body = parseJsonBody<ActivityBody>(event);
  const eventCount = Array.isArray(body?.events) ? body.events.length : 0;

  logSafe('info', 'Activity synchronized', {
    email: auth.context.user.email,
    sessionId: auth.context.claims.sid,
    syncedOfflineEvents: eventCount,
  });

  return jsonResponse(200, {
    success: true,
    lastActivityAt: auth.context.user.lastActivityAt,
    syncedEvents: eventCount,
  });
}
