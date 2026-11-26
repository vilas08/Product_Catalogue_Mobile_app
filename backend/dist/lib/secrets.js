"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setSecretsClientForTesting = setSecretsClientForTesting;
exports.getJwtPrivateKey = getJwtPrivateKey;
const client_secrets_manager_1 = require("@aws-sdk/client-secrets-manager");
const env_1 = require("../config/env");
let cachedPrivateKey = null;
let cachedSecretArn = null;
let secretsClient = null;
function setSecretsClientForTesting(client) {
    secretsClient = client;
    cachedPrivateKey = null;
    cachedSecretArn = null;
}
function getSecretsClient(region) {
    if (!secretsClient) {
        secretsClient = new client_secrets_manager_1.SecretsManagerClient({ region });
    }
    return secretsClient;
}
async function getJwtPrivateKey() {
    const { jwtPrivateKeySecretArn, awsRegion } = (0, env_1.getEnvConfig)();
    if (!jwtPrivateKeySecretArn) {
        throw new Error('JWT_PRIVATE_KEY_SECRET_ARN is not configured');
    }
    if (cachedPrivateKey && cachedSecretArn === jwtPrivateKeySecretArn) {
        return cachedPrivateKey;
    }
    const client = getSecretsClient(awsRegion);
    const response = await client.send(new client_secrets_manager_1.GetSecretValueCommand({ SecretId: jwtPrivateKeySecretArn }));
    if (!response.SecretString) {
        throw new Error('JWT private key secret is empty');
    }
    let key = response.SecretString.trim();
    if (key.startsWith('{')) {
        const parsed = JSON.parse(key);
        if (!parsed.privateKey) {
            throw new Error('JWT private key JSON secret missing privateKey field');
        }
        key = parsed.privateKey;
    }
    cachedPrivateKey = key.replace(/\\n/g, '\n').trim();
    cachedSecretArn = jwtPrivateKeySecretArn;
    return cachedPrivateKey;
}
