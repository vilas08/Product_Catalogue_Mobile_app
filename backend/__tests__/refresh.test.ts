import { handler } from '../src/index';
import { createSeedUser, makeEvent, setupTestEnvironment } from './testHelpers';

describe('Refresh Token Rotation & Replay', () => {
  it('rotates refresh token and issues new access token', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const loginRes = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    const loginBody = JSON.parse(loginRes.body);

    const refreshRes = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: loginBody.refreshToken,
        sessionId: loginBody.sessionId,
      })
    );
    expect(refreshRes.statusCode).toBe(200);
    const refreshBody = JSON.parse(refreshRes.body);
    expect(refreshBody.accessToken).toBeTruthy();
    expect(refreshBody.refreshToken).toBeTruthy();
    expect(refreshBody.refreshToken).not.toBe(loginBody.refreshToken);

    // Replay of old refresh token must be rejected
    const replayRes = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: loginBody.refreshToken,
        sessionId: loginBody.sessionId,
      })
    );
    expect(replayRes.statusCode).toBe(401);
  });

  it('rejects expired refresh token', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const loginRes = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    const loginBody = JSON.parse(loginRes.body);

    const user = table.get('sales1@example.com')!;
    table.seed({
      ...user,
      refreshExpiresAt: new Date(Date.now() - 1000).toISOString(),
    });

    const refreshRes = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: loginBody.refreshToken,
        sessionId: loginBody.sessionId,
      })
    );
    expect(refreshRes.statusCode).toBe(401);
    expect(JSON.parse(refreshRes.body).code).toBe('REFRESH_EXPIRED');
  });

  it('rejects invalid refresh token', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const loginRes = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    const loginBody = JSON.parse(loginRes.body);

    const refreshRes = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: 'tampered-refresh-token',
        sessionId: loginBody.sessionId,
      })
    );
    expect(refreshRes.statusCode).toBe(401);
  });

  it('allows only one concurrent refresh to succeed', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const loginRes = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    const loginBody = JSON.parse(loginRes.body);

    const [r1, r2] = await Promise.all([
      handler(
        makeEvent('POST', '/auth/refresh', {
          email: 'sales1@example.com',
          refreshToken: loginBody.refreshToken,
          sessionId: loginBody.sessionId,
        })
      ),
      handler(
        makeEvent('POST', '/auth/refresh', {
          email: 'sales1@example.com',
          refreshToken: loginBody.refreshToken,
          sessionId: loginBody.sessionId,
        })
      ),
    ]);

    const codes = [r1.statusCode, r2.statusCode].sort();
    expect(codes).toEqual([200, 401]);
  });

  it('rejects refresh for revoked session', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const loginRes = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    const loginBody = JSON.parse(loginRes.body);

    const user = table.get('sales1@example.com')!;
    table.seed({ ...user, sessionStatus: 'REVOKED' });

    const refreshRes = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: loginBody.refreshToken,
        sessionId: loginBody.sessionId,
      })
    );
    expect(refreshRes.statusCode).toBe(401);
    expect(JSON.parse(refreshRes.body).code).toBe('SESSION_REVOKED');
  });
});
