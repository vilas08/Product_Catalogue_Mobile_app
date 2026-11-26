import { handler } from '../src/index';
import { createSeedUser, makeEvent, setupTestEnvironment } from './testHelpers';

describe('Logout', () => {
  it('revokes session, clears refresh token hash, and rejects subsequent requests', async () => {
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

    const logoutRes = await handler(
      makeEvent(
        'POST',
        '/auth/logout',
        { sessionId: loginBody.sessionId },
        { Authorization: `Bearer ${loginBody.accessToken}` }
      )
    );
    expect(logoutRes.statusCode).toBe(200);

    const stored = table.get('sales1@example.com')!;
    expect(stored.sessionStatus).toBe('REVOKED');
    expect(stored.refreshTokenHash).toBeNull();

    const meRes = await handler(
      makeEvent('GET', '/auth/me', undefined, {
        Authorization: `Bearer ${loginBody.accessToken}`,
      })
    );
    expect(meRes.statusCode).toBe(401);

    const refreshRes = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: loginBody.refreshToken,
        sessionId: loginBody.sessionId,
      })
    );
    expect(refreshRes.statusCode).toBe(401);
  });
});
