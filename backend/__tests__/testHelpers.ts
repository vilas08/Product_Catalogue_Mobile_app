import { generateKeyPairSync } from 'node:crypto';
import { APIGatewayProxyEvent } from 'aws-lambda';
import bcrypt from 'bcryptjs';
import { GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { setDynamoClientForTesting } from '../src/lib/dynamo';
import { setSecretsClientForTesting } from '../src/lib/secrets';
import { UserRecord } from '../src/types/auth';

export const TEST_KEYS = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

export class ConditionalCheckFailedError extends Error {
  constructor(message = 'The conditional request failed') {
    super(message);
    this.name = 'ConditionalCheckFailedException';
  }
}

export class InMemoryUsersTable {
  private items = new Map<string, UserRecord>();

  seed(user: UserRecord): void {
    this.items.set(user.email, { ...user });
  }

  get(email: string): UserRecord | undefined {
    const item = this.items.get(email);
    return item ? { ...item } : undefined;
  }

  createMockDocClient(): DynamoDBDocumentClient {
    return {
      send: async (command: unknown) => {
        if (command instanceof GetCommand) {
          const email = command.input.Key?.email as string;
          const item = this.items.get(email);
          return { Item: item ? { ...item } : undefined };
        }

        if (command instanceof UpdateCommand) {
          const email = command.input.Key?.email as string;
          const existing = this.items.get(email);
          const vals = command.input.ExpressionAttributeValues || {};
          const cond = command.input.ConditionExpression || '';

          if (cond.includes('attribute_exists(email)') && !existing) {
            throw new ConditionalCheckFailedError();
          }
          if (!existing) {
            throw new ConditionalCheckFailedError();
          }

          if (cond.includes('#status = :activeStatus') && existing.status !== vals[':activeStatus']) {
            throw new ConditionalCheckFailedError();
          }
          if (
            cond.includes('sessionStatus = :activeSessionStatus') &&
            existing.sessionStatus !== vals[':activeSessionStatus']
          ) {
            throw new ConditionalCheckFailedError();
          }
          if (
            cond.includes('activeSessionId = :expectedSid') &&
            existing.activeSessionId !== vals[':expectedSid']
          ) {
            throw new ConditionalCheckFailedError();
          }
          if (
            cond.includes('activeSessionId = :sid') &&
            existing.activeSessionId !== vals[':sid']
          ) {
            throw new ConditionalCheckFailedError();
          }
          if (
            cond.includes('refreshTokenHash = :expectedHash') &&
            existing.refreshTokenHash !== vals[':expectedHash']
          ) {
            throw new ConditionalCheckFailedError();
          }
          if (
            cond.includes('refreshExpiresAt > :nowIso') &&
            (!existing.refreshExpiresAt || existing.refreshExpiresAt <= String(vals[':nowIso']))
          ) {
            throw new ConditionalCheckFailedError();
          }
          if (
            cond.includes('lastActivityAt >= :inactivityCutoffIso') &&
            (!existing.lastActivityAt ||
              existing.lastActivityAt < String(vals[':inactivityCutoffIso']))
          ) {
            throw new ConditionalCheckFailedError();
          }

          const updated: UserRecord = { ...existing };
          const expr = command.input.UpdateExpression || '';
          const assignments = expr.replace(/^SET\s+/i, '').split(',');
          for (const part of assignments) {
            const [attr, valKey] = part.split('=').map((s) => s.trim());
            if (attr && valKey && valKey in vals) {
              (updated as unknown as Record<string, unknown>)[attr] = vals[valKey];
            }
          }

          this.items.set(email, updated);
          return { Attributes: { ...updated } };
        }

        throw new Error('Unsupported DynamoDB command in test mock');
      },
    } as unknown as DynamoDBDocumentClient;
  }
}

export function setupTestEnvironment(): InMemoryUsersTable {
  process.env.USERS_TABLE = 'Users';
  process.env.JWT_ISSUER = 'https://auth.test.local';
  process.env.JWT_ACCESS_EXPIRY = '15m';
  process.env.JWT_OFFLINE_EXPIRY = '7d';
  process.env.REFRESH_TOKEN_EXPIRY = '7d';
  process.env.INACTIVITY_LIMIT_DAYS = '7';
  process.env.JWT_PRIVATE_KEY_SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:123:secret:jwt-key';
  process.env.JWT_PUBLIC_KEY = TEST_KEYS.publicKey;
  process.env.AWS_REGION = 'us-east-1';

  const table = new InMemoryUsersTable();
  setDynamoClientForTesting(table.createMockDocClient());

  const mockSecrets = {
    send: async () => ({ SecretString: TEST_KEYS.privateKey }),
  } as unknown as SecretsManagerClient;
  setSecretsClientForTesting(mockSecrets);

  return table;
}

export async function createSeedUser(
  overrides: Partial<UserRecord> = {}
): Promise<UserRecord> {
  const passwordHash = await bcrypt.hash('StrongPass123!', 4);
  return {
    email: 'sales1@example.com',
    passwordHash,
    name: 'Alex Sales',
    role: 'SALESPERSON',
    status: 'ACTIVE',
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

export function makeEvent(
  method: string,
  path: string,
  body?: Record<string, unknown>,
  headers: Record<string, string> = {}
): APIGatewayProxyEvent {
  return {
    httpMethod: method,
    path,
    headers,
    body: body ? JSON.stringify(body) : null,
    isBase64Encoded: false,
    multiValueHeaders: {},
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {} as APIGatewayProxyEvent['requestContext'],
    resource: '',
  };
}
