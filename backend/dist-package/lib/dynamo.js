"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setDynamoClientForTesting = setDynamoClientForTesting;
exports.getUserByEmail = getUserByEmail;
exports.replaceSessionOnLogin = replaceSessionOnLogin;
exports.rotateRefreshToken = rotateRefreshToken;
exports.updateLastActivity = updateLastActivity;
exports.revokeSession = revokeSession;
const client_dynamodb_1 = require("@aws-sdk/client-dynamodb");
const lib_dynamodb_1 = require("@aws-sdk/lib-dynamodb");
const env_1 = require("../config/env");
let docClient = null;
function setDynamoClientForTesting(client) {
    docClient = client;
}
function getDocClient() {
    if (!docClient) {
        const { awsRegion } = (0, env_1.getEnvConfig)();
        const client = new client_dynamodb_1.DynamoDBClient({ region: awsRegion });
        docClient = lib_dynamodb_1.DynamoDBDocumentClient.from(client, {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}
async function getUserByEmail(email) {
    const { usersTable } = (0, env_1.getEnvConfig)();
    const result = await getDocClient().send(new lib_dynamodb_1.GetCommand({
        TableName: usersTable,
        Key: { email },
    }));
    return result.Item ?? null;
}
async function replaceSessionOnLogin(params) {
    const { usersTable } = (0, env_1.getEnvConfig)();
    const result = await getDocClient().send(new lib_dynamodb_1.UpdateCommand({
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
    }));
    return result.Attributes;
}
async function rotateRefreshToken(params) {
    const { usersTable } = (0, env_1.getEnvConfig)();
    const result = await getDocClient().send(new lib_dynamodb_1.UpdateCommand({
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
    }));
    return result.Attributes;
}
async function updateLastActivity(params) {
    const { usersTable } = (0, env_1.getEnvConfig)();
    const result = await getDocClient().send(new lib_dynamodb_1.UpdateCommand({
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
    }));
    return result.Attributes;
}
async function revokeSession(params) {
    const { usersTable } = (0, env_1.getEnvConfig)();
    await getDocClient().send(new lib_dynamodb_1.UpdateCommand({
        TableName: usersTable,
        Key: { email: params.email },
        UpdateExpression: 'SET sessionStatus = :revokedStatus, refreshTokenHash = :nullVal, refreshExpiresAt = :nullVal',
        ConditionExpression: 'attribute_exists(email) AND activeSessionId = :sid',
        ExpressionAttributeValues: {
            ':revokedStatus': 'REVOKED',
            ':nullVal': null,
            ':sid': params.sessionId,
        },
    }));
}
