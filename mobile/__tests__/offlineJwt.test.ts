import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { verifyOfflineJwt } from '../src/auth/offlineJwt';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const otherKeys = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function createSignedJwt(
  payload: Record<string, unknown>,
  signingPrivateKey = privateKey,
  alg = 'RS256'
): string {
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${header}.${body}`;
  const signature = cryptoSign('RSA-SHA256', Buffer.from(signingInput), signingPrivateKey).toString(
    'base64url'
  );
  return `${signingInput}.${signature}`;
}

describe('Offline JWT Cryptographic Verification', () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const basePayload = {
    sub: 'sales1@example.com',
    sid: 'session-123',
    deviceId: 'device-a',
    tokenType: 'offline',
    iss: 'https://auth.example.com',
    aud: 'mobile-offline',
    iat: nowSec - 60,
    exp: nowSec + 7 * 24 * 60 * 60,
  };

  it('verifies a valid RS256 offline JWT', () => {
    const token = createSignedJwt(basePayload);
    const result = verifyOfflineJwt(token, {
      publicKeyPem: publicKey,
      expectedIssuer: 'https://auth.example.com',
      expectedSessionId: 'session-123',
      expectedSubject: 'sales1@example.com',
      nowSeconds: nowSec,
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.claims.sub).toBe('sales1@example.com');
      expect(result.claims.sid).toBe('session-123');
    }
  });

  it('rejects an invalid signature', () => {
    const token = createSignedJwt(basePayload, otherKeys.privateKey);
    const result = verifyOfflineJwt(token, {
      publicKeyPem: publicKey,
      expectedIssuer: 'https://auth.example.com',
      expectedSessionId: 'session-123',
      nowSeconds: nowSec,
    });
    expect(result.valid).toBe(false);
  });

  it('rejects wrong audience', () => {
    const token = createSignedJwt({ ...basePayload, aud: 'mobile-api' });
    const result = verifyOfflineJwt(token, {
      publicKeyPem: publicKey,
      expectedIssuer: 'https://auth.example.com',
      expectedSessionId: 'session-123',
      nowSeconds: nowSec,
    });
    expect(result.valid).toBe(false);
  });

  it('rejects wrong issuer', () => {
    const token = createSignedJwt({ ...basePayload, iss: 'https://evil.example.com' });
    const result = verifyOfflineJwt(token, {
      publicKeyPem: publicKey,
      expectedIssuer: 'https://auth.example.com',
      expectedSessionId: 'session-123',
      nowSeconds: nowSec,
    });
    expect(result.valid).toBe(false);
  });

  it('rejects expired offline JWT', () => {
    const token = createSignedJwt({ ...basePayload, exp: nowSec - 10 });
    const result = verifyOfflineJwt(token, {
      publicKeyPem: publicKey,
      expectedIssuer: 'https://auth.example.com',
      expectedSessionId: 'session-123',
      nowSeconds: nowSec,
    });
    expect(result.valid).toBe(false);
  });

  it('rejects incorrect session ID', () => {
    const token = createSignedJwt({ ...basePayload, sid: 'other-session' });
    const result = verifyOfflineJwt(token, {
      publicKeyPem: publicKey,
      expectedIssuer: 'https://auth.example.com',
      expectedSessionId: 'session-123',
      nowSeconds: nowSec,
    });
    expect(result.valid).toBe(false);
  });
});
