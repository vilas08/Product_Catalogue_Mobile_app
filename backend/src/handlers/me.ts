import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { jsonResponse } from '../lib/http';
import { authenticateRequest } from '../middleware/authenticate';

export async function handleMe(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const auth = await authenticateRequest(event);
  if (!auth.ok) {
    return auth.response;
  }

  const { user } = auth.context;
  return jsonResponse(200, {
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
