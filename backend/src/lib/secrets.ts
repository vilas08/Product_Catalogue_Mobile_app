import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { getEnvConfig } from '../config/env';

let cachedPrivateKey: string | null = null;
let cachedSecretArn: string | null = null;
let secretsClient: SecretsManagerClient | null = null;

export function setSecretsClientForTesting(client: SecretsManagerClient | null): void {
  secretsClient = client;
  cachedPrivateKey = null;
  cachedSecretArn = null;
}

function getSecretsClient(region: string): SecretsManagerClient {
  if (!secretsClient) {
    secretsClient = new SecretsManagerClient({ region });
  }
  return secretsClient;
}

export async function getJwtPrivateKey(): Promise<string> {
  const { jwtPrivateKeySecretArn, awsRegion } = getEnvConfig();
  if (!jwtPrivateKeySecretArn) {
    throw new Error('JWT_PRIVATE_KEY_SECRET_ARN is not configured');
  }

  if (cachedPrivateKey && cachedSecretArn === jwtPrivateKeySecretArn) {
    return cachedPrivateKey;
  }

  const client = getSecretsClient(awsRegion);
  const response = await client.send(
    new GetSecretValueCommand({ SecretId: jwtPrivateKeySecretArn })
  );

  if (!response.SecretString) {
    throw new Error('JWT private key secret is empty');
  }

  let key = response.SecretString.trim();
  if (key.startsWith('{')) {
    const parsed = JSON.parse(key) as { privateKey?: string };
    if (!parsed.privateKey) {
      throw new Error('JWT private key JSON secret missing privateKey field');
    }
    key = parsed.privateKey;
  }

  cachedPrivateKey = key.replace(/\\n/g, '\n').trim();
  cachedSecretArn = jwtPrivateKeySecretArn;
  return cachedPrivateKey;
}
