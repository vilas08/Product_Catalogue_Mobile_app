import { handler } from '../src/index';
import { hashRefreshToken } from '../src/lib/crypto';
import { verifyAccessToken, verifyOfflineTokenServerSide } from '../src/lib/jwt';
import { createSeedUser, makeEvent, setupTestEnvironment, TEST_KEYS } from './testHelpers';

describe('Login', () => {
  it('logs in a valid active salesperson and creates a session', async () => {
    const table = setupTestEnvironment();
    const user = await createSeedUser();
    table.seed(user);

    const res = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.accessToken).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();
    expect(body.offlineToken).toBeTruthy();
    expect(body.sessionId).toBeTruthy();
    expect(body.deviceId).toBe('device-a');
    expect(body.user.email).toBe('sales1@example.com');

    const accessClaims = verifyAccessToken(body.accessToken, {
      publicKey: TEST_KEYS.publicKey,
      issuer: 'https://auth.test.local',
    });
    expect(accessClaims.sub).toBe('sales1@example.com');
    expect(accessClaims.sid).toBe(body.sessionId);
    expect(accessClaims.deviceId).toBe('device-a');

    const offlineClaims = verifyOfflineTokenServerSide(body.offlineToken, {
      publicKey: TEST_KEYS.publicKey,
      issuer: 'https://auth.test.local',
    });
    expect(offlineClaims.sub).toBe('sales1@example.com');
    expect(offlineClaims.sid).toBe(body.sessionId);

    const stored = table.get('sales1@example.com')!;
    expect(stored.activeSessionId).toBe(body.sessionId);
    expect(stored.activeDeviceId).toBe('device-a');
    expect(stored.sessionStatus).toBe('ACTIVE');
    expect(stored.refreshTokenHash).toBe(hashRefreshToken(body.refreshToken));
    expect(stored.refreshTokenHash).not.toBe(body.refreshToken);
  });

  it('returns generic error for invalid email', async () => {
    setupTestEnvironment();
    const res = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'unknown@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).error).toBe('Invalid email or password');
  });

  it('returns generic error for invalid password', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const res = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'WrongPassword!',
        deviceId: 'device-a',
      })
    );
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).error).toBe('Invalid email or password');
  });

  it('rejects inactive user with generic error', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser({ status: 'INACTIVE' }));

    const res = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).error).toBe('Invalid email or password');
  });

  it('rejects missing credentials', async () => {
    setupTestEnvironment();
    const res = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
      })
    );
    expect(res.statusCode).toBe(400);
  });
});
