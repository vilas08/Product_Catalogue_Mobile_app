import jwt from 'jsonwebtoken';
import { AccessTokenClaims, OfflineTokenClaims } from '../types/auth';

export interface SignTokenInput {
  email: string;
  sessionId: string;
  deviceId: string;
  privateKey: string;
  issuer: string;
  expiresIn: string;
}

export function signAccessToken(input: SignTokenInput): string {
  return jwt.sign(
    {
      sid: input.sessionId,
      deviceId: input.deviceId,
      tokenType: 'access',
    },
    input.privateKey,
    {
      algorithm: 'RS256',
      subject: input.email,
      audience: 'mobile-api',
      issuer: input.issuer,
      expiresIn: input.expiresIn as jwt.SignOptions['expiresIn'],
    }
  );
}

export function signOfflineToken(input: SignTokenInput): string {
  return jwt.sign(
    {
      sid: input.sessionId,
      deviceId: input.deviceId,
      tokenType: 'offline',
    },
    input.privateKey,
    {
      algorithm: 'RS256',
      subject: input.email,
      audience: 'mobile-offline',
      issuer: input.issuer,
      expiresIn: input.expiresIn as jwt.SignOptions['expiresIn'],
    }
  );
}

export function verifyAccessToken(
  token: string,
  options: { publicKey: string; issuer: string }
): AccessTokenClaims {
  const decoded = jwt.verify(token, options.publicKey, {
    algorithms: ['RS256'],
    audience: 'mobile-api',
    issuer: options.issuer,
  });

  if (typeof decoded === 'string' || !decoded) {
    throw new Error('Invalid token payload');
  }

  const claims = decoded as Partial<AccessTokenClaims>;
  if (
    claims.tokenType !== 'access' ||
    typeof claims.sub !== 'string' ||
    typeof claims.sid !== 'string' ||
    typeof claims.deviceId !== 'string'
  ) {
    throw new Error('Invalid access token claims');
  }

  return claims as AccessTokenClaims;
}

export function verifyOfflineTokenServerSide(
  token: string,
  options: { publicKey: string; issuer: string }
): OfflineTokenClaims {
  const decoded = jwt.verify(token, options.publicKey, {
    algorithms: ['RS256'],
    audience: 'mobile-offline',
    issuer: options.issuer,
  });

  if (typeof decoded === 'string' || !decoded) {
    throw new Error('Invalid offline token payload');
  }

  const claims = decoded as Partial<OfflineTokenClaims>;
  if (
    claims.tokenType !== 'offline' ||
    typeof claims.sub !== 'string' ||
    typeof claims.sid !== 'string' ||
    typeof claims.deviceId !== 'string'
  ) {
    throw new Error('Invalid offline token claims');
  }

  return claims as OfflineTokenClaims;
}
