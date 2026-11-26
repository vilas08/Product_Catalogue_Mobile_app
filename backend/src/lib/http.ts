import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getEnvConfig } from '../config/env';

export function buildCorsHeaders(): Record<string, string> {
  const { corsOrigin } = getEnvConfig();
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  };
}

export function jsonResponse(statusCode: number, body: Record<string, unknown>): APIGatewayProxyResult {
  return {
    statusCode,
    headers: buildCorsHeaders(),
    body: JSON.stringify(body),
  };
}

export function parseJsonBody<T>(event: APIGatewayProxyEvent): T | null {
  if (!event.body) {
    return null;
  }
  try {
    const raw = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf8')
      : event.body;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function logSafe(level: 'info' | 'warn' | 'error', message: string, meta?: Record<string, unknown>): void {
  const entry = {
    level,
    message,
    timestamp: new Date().toISOString(),
    ...(meta ? { meta } : {}),
  };
  if (level === 'error') {
    console.error(JSON.stringify(entry));
  } else if (level === 'warn') {
    console.warn(JSON.stringify(entry));
  } else {
    console.log(JSON.stringify(entry));
  }
}
