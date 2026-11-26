import { KEYUTIL, KJUR, RSAKey } from 'jsrsasign';
import { AUTH_CONFIG } from '../config/authConfig';
import { OfflineTokenClaims } from '../types/auth';

export interface VerifyOfflineOptions {
  publicKeyPem?: string;
  expectedIssuer?: string;
  expectedSessionId: string;
  expectedSubject?: string;
  nowSeconds?: number;
}

export type OfflineVerificationResult =
  | { valid: true; claims: OfflineTokenClaims }
  | { valid: false; reason: string };

/**
 * Cryptographically verifies an Offline Session JWT using RS256 and a bundled RSA public key.
 * Never relies on base64 JWT decoding alone.
 */
export function verifyOfflineJwt(
  token: string,
  options: VerifyOfflineOptions
): OfflineVerificationResult {
  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'Missing offline token' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, reason: 'Malformed JWT' };
  }

  let header: { alg?: string };
  let payload: Partial<OfflineTokenClaims>;
  try {
    const parsed = KJUR.jws.JWS.parse(token);
    header = parsed.headerObj as { alg?: string };
    payload = parsed.payloadObj as Partial<OfflineTokenClaims>;
  } catch {
    return { valid: false, reason: 'Failed to parse JWT' };
  }

  // 1. Verify algorithm explicitly
  if (header?.alg !== 'RS256') {
    return { valid: false, reason: 'Invalid JWT algorithm' };
  }

  // 2. Cryptographically verify RS256 signature using RSA public key
  const pem = (options.publicKeyPem || AUTH_CONFIG.jwtPublicKey).trim();
  let publicKey: RSAKey;
  try {
    const keyObj = KEYUTIL.getKey(pem);
    if (!(keyObj instanceof RSAKey)) {
      return { valid: false, reason: 'Public key is not an RSA key' };
    }
    publicKey = keyObj;
  } catch {
    return { valid: false, reason: 'Invalid RSA public key configuration' };
  }

  const nowSec = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const expectedIssuer = options.expectedIssuer || AUTH_CONFIG.jwtIssuer;

  let signatureAndClaimsValid = false;
  try {
    signatureAndClaimsValid = KJUR.jws.JWS.verifyJWT(token, publicKey, {
      alg: ['RS256'],
      iss: [expectedIssuer],
      aud: ['mobile-offline'],
      verifyAt: nowSec,
      gracePeriod: 0,
    });
  } catch {
    return { valid: false, reason: 'Signature verification failed' };
  }

  if (!signatureAndClaimsValid) {
    return { valid: false, reason: 'Signature or standard claims verification failed' };
  }

  // 3. Verify expiry explicitly
  if (typeof payload.exp !== 'number' || payload.exp <= nowSec) {
    return { valid: false, reason: 'Offline token expired' };
  }

  // 4. Verify tokenType, subject, and sessionId
  if (payload.tokenType !== 'offline') {
    return { valid: false, reason: 'Invalid token type' };
  }

  if (typeof payload.sub !== 'string' || !payload.sub) {
    return { valid: false, reason: 'Missing subject' };
  }

  if (options.expectedSubject && payload.sub !== options.expectedSubject) {
    return { valid: false, reason: 'Subject mismatch' };
  }

  if (typeof payload.sid !== 'string' || payload.sid !== options.expectedSessionId) {
    return { valid: false, reason: 'Session ID mismatch' };
  }

  return {
    valid: true,
    claims: payload as OfflineTokenClaims,
  };
}
