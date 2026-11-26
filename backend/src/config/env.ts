export interface EnvConfig {
  usersTable: string;
  jwtIssuer: string;
  jwtAccessExpiry: string;
  jwtOfflineExpiry: string;
  refreshTokenExpiryMs: number;
  inactivityLimitDays: number;
  inactivityLimitMs: number;
  jwtPrivateKeySecretArn: string;
  jwtPublicKey: string;
  awsRegion: string;
  corsOrigin: string;
}

export function parseDurationMs(value: string): number {
  const trimmed = value.trim();
  const match = /^(\d+)\s*(ms|s|m|h|d)$/i.exec(trimmed);
  if (!match) {
    throw new Error(`Invalid duration format: ${value}`);
  }
  const amount = Number(match[1]);
  const unit = match[2].toLowerCase();
  const multipliers: Record<string, number> = {
    ms: 1,
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };
  return amount * multipliers[unit];
}

function normalizePem(pem: string): string {
  return pem.replace(/\\n/g, '\n').trim();
}

export function getEnvConfig(): EnvConfig {
  const usersTable = process.env.USERS_TABLE || 'Users';
  const jwtIssuer = process.env.JWT_ISSUER || 'https://auth.example.com';
  const jwtAccessExpiry = process.env.JWT_ACCESS_EXPIRY || '15m';
  const jwtOfflineExpiry = process.env.JWT_OFFLINE_EXPIRY || '7d';
  const refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '7d';
  const inactivityLimitDays = Number(process.env.INACTIVITY_LIMIT_DAYS || '7');
  const jwtPrivateKeySecretArn = process.env.JWT_PRIVATE_KEY_SECRET_ARN || '';
  const jwtPublicKey = normalizePem(process.env.JWT_PUBLIC_KEY || '');
  const awsRegion = process.env.AWS_REGION || 'us-east-1';
  const corsOrigin = process.env.CORS_ALLOW_ORIGIN || '*';

  if (!Number.isFinite(inactivityLimitDays) || inactivityLimitDays <= 0) {
    throw new Error('INACTIVITY_LIMIT_DAYS must be a positive number');
  }

  return {
    usersTable,
    jwtIssuer,
    jwtAccessExpiry,
    jwtOfflineExpiry,
    refreshTokenExpiryMs: parseDurationMs(refreshTokenExpiry),
    inactivityLimitDays,
    inactivityLimitMs: inactivityLimitDays * 24 * 60 * 60 * 1000,
    jwtPrivateKeySecretArn,
    jwtPublicKey,
    awsRegion,
    corsOrigin,
  };
}
