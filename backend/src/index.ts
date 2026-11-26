import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { handleActivity } from './handlers/activity';
import { handleLogin } from './handlers/login';
import { handleLogout } from './handlers/logout';
import { handleMe } from './handlers/me';
import { handleRefresh } from './handlers/refresh';
import { buildCorsHeaders, jsonResponse, logSafe } from './lib/http';

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const method = event.httpMethod?.toUpperCase() || '';
  const path = event.path || '';

  if (method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: buildCorsHeaders(),
      body: '',
    };
  }

  try {
    if (method === 'POST' && path.endsWith('/auth/login')) {
      return await handleLogin(event);
    }
    if (method === 'POST' && path.endsWith('/auth/refresh')) {
      return await handleRefresh(event);
    }
    if (method === 'POST' && path.endsWith('/auth/logout')) {
      return await handleLogout(event);
    }
    if (method === 'GET' && path.endsWith('/auth/me')) {
      return await handleMe(event);
    }
    if (method === 'POST' && path.endsWith('/auth/activity')) {
      return await handleActivity(event);
    }

    return jsonResponse(404, { error: 'Route not found' });
  } catch (err) {
    logSafe('error', 'Unhandled error in auth router', {
      method,
      path,
      errorName: err instanceof Error ? err.name : 'UnknownError',
    });
    return jsonResponse(500, { error: 'Internal server error' });
  }
}
