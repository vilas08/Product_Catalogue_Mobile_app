import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { getEnvConfig } from '../config/env';
import { UserRecord } from '../types/auth';

let docClient: DynamoDBDocumentClient | null = null;

export function setDynamoClientForTesting(client: DynamoDBDocumentClient | null): void {
  docClient = client;
}

function getDocClient(): DynamoDBDocumentClient {
  if (!docClient) {
    const { awsRegion } = getEnvConfig();
    const client = new DynamoDBClient({ region: awsRegion });
    docClient = DynamoDBDocumentClient.from(client, {
      marshallOptions: { removeUndefinedValues: true },
    });
  }
  return docClient;
}

export async function getUserByEmail(email: string): Promise<UserRecord | null> {
  const { usersTable } = getEnvConfig();
  const result = await getDocClient().send(
    new GetCommand({
      TableName: usersTable,
      Key: { email },
    })
  );
  return (result.Item as UserRecord | undefined) ?? null;
}

export interface ReplaceSessionParams {
  email: string;
  sessionId: string;
  deviceId: string;
  refreshTokenHash: string;
  refreshExpiresAt: string;
  nowIso: string;
}

export async function replaceSessionOnLogin(params: ReplaceSessionParams): Promise<UserRecord> {
  const { usersTable } = getEnvConfig();
  const result = await getDocClient().send(
    new UpdateCommand({
      TableName: usersTable,
      Key: { email: params.email },
      UpdateExpression: [
        'SET activeSessionId = :sid',
        'activeDeviceId = :deviceId',
        'refreshTokenHash = :refreshHash',
        'refreshExpiresAt = :refreshExpiresAt',
        'sessionCreatedAt = :nowIso',
        'lastActivityAt = :nowIso',
        'sessionStatus = :activeSessionStatus',
        'lastLogin = :nowIso',
      ].join(', '),
      ConditionExpression: 'attribute_exists(email) AND #status = :activeStatus',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: {
        ':sid': params.sessionId,
        ':deviceId': params.deviceId,
        ':refreshHash': params.refreshTokenHash,
        ':refreshExpiresAt': params.refreshExpiresAt,
        ':nowIso': params.nowIso,
        ':activeSessionStatus': 'ACTIVE',
        ':activeStatus': 'ACTIVE',
      },
      ReturnValues: 'ALL_NEW',
    })
  );

  return result.Attributes as UserRecord;
}

export interface RotateRefreshTokenParams {
  email: string;
  expectedSessionId: string;
  expectedRefreshHash: string;
  newRefreshHash: string;
  newRefreshExpiresAt: string;
  nowIso: string;
  inactivityCutoffIso: string;
}

export async function rotateRefreshToken(params: RotateRefreshTokenParams): Promise<UserRecord> {
  const { usersTable } = getEnvConfig();
  const result = await getDocClient().send(
    new UpdateCommand({
      TableName: usersTable,
      Key: { email: params.email },
      UpdateExpression: [
        'SET refreshTokenHash = :newHash',
        'refreshExpiresAt = :newExpiresAt',
        'lastActivityAt = :nowIso',
      ].join(', '),
      ConditionExpression: [
        'attribute_exists(email)',
        '#status = :activeStatus',
        'sessionStatus = :activeSessionStatus',
        'activeSessionId = :expectedSid',
        'refreshTokenHash = :expectedHash',
        'refreshExpiresAt > :nowIso',
        'lastActivityAt >= :inactivityCutoffIso',
      ].join(' AND '),
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: {
        ':newHash': params.newRefreshHash,
        ':newExpiresAt': params.newRefreshExpiresAt,
        ':nowIso': params.nowIso,
        ':activeStatus': 'ACTIVE',
        ':activeSessionStatus': 'ACTIVE',
        ':expectedSid': params.expectedSessionId,
        ':expectedHash': params.expectedRefreshHash,
        ':inactivityCutoffIso': params.inactivityCutoffIso,
      },
      ReturnValues: 'ALL_NEW',
    })
  );

  return result.Attributes as UserRecord;
}

export async function updateLastActivity(params: {
  email: string;
  sessionId: string;
  nowIso: string;
  inactivityCutoffIso: string;
}): Promise<UserRecord> {
  const { usersTable } = getEnvConfig();
  const result = await getDocClient().send(
    new UpdateCommand({
      TableName: usersTable,
      Key: { email: params.email },
      UpdateExpression: 'SET lastActivityAt = :nowIso',
      ConditionExpression: [
        'attribute_exists(email)',
        '#status = :activeStatus',
        'sessionStatus = :activeSessionStatus',
        'activeSessionId = :sid',
        'lastActivityAt >= :inactivityCutoffIso',
      ].join(' AND '),
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: {
        ':nowIso': params.nowIso,
        ':activeStatus': 'ACTIVE',
        ':activeSessionStatus': 'ACTIVE',
        ':sid': params.sessionId,
        ':inactivityCutoffIso': params.inactivityCutoffIso,
      },
      ReturnValues: 'ALL_NEW',
    })
  );

  return result.Attributes as UserRecord;
}

export async function revokeSession(params: {
  email: string;
  sessionId: string;
}): Promise<void> {
  const { usersTable } = getEnvConfig();
  await getDocClient().send(
    new UpdateCommand({
      TableName: usersTable,
      Key: { email: params.email },
      UpdateExpression:
        'SET sessionStatus = :revokedStatus, refreshTokenHash = :nullVal, refreshExpiresAt = :nullVal',
      ConditionExpression: 'attribute_exists(email) AND activeSessionId = :sid',
      ExpressionAttributeValues: {
        ':revokedStatus': 'REVOKED',
        ':nullVal': null,
        ':sid': params.sessionId,
      },
    })
  );
}
