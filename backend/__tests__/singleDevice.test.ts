import { handler } from '../src/index';
import { createSeedUser, makeEvent, setupTestEnvironment } from './testHelpers';

describe('Single-Device Login', () => {
  it('invalidates Device A session and refresh token when Device B logs in', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const loginA = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-a',
      })
    );
    const bodyA = JSON.parse(loginA.body);
    expect(loginA.statusCode).toBe(200);

    const loginB = await handler(
      makeEvent('POST', '/auth/login', {
        email: 'sales1@example.com',
        password: 'StrongPass123!',
        deviceId: 'device-b',
      })
    );
    const bodyB = JSON.parse(loginB.body);
    expect(loginB.statusCode).toBe(200);
    expect(bodyB.sessionId).not.toBe(bodyA.sessionId);

    // Device A online validation must fail
    const meA = await handler(
      makeEvent('GET', '/auth/me', undefined, {
        Authorization: `Bearer ${bodyA.accessToken}`,
      })
    );
    expect(meA.statusCode).toBe(401);
    expect(JSON.parse(meA.body).code).toBe('SESSION_REVOKED');

    // Device A old refresh token must be rejected
    const refreshA = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: bodyA.refreshToken,
        sessionId: bodyA.sessionId,
      })
    );
    expect(refreshA.statusCode).toBe(401);

    // Device B online validation succeeds
    const meB = await handler(
      makeEvent('GET', '/auth/me', undefined, {
        Authorization: `Bearer ${bodyB.accessToken}`,
      })
    );
    expect(meB.statusCode).toBe(200);
    expect(JSON.parse(meB.body).user.activeDeviceId).toBe('device-b');
  });

  it('handles concurrent login attempts consistently with one winning active session', async () => {
    const table = setupTestEnvironment();
    table.seed(await createSeedUser());

    const [res1, res2] = await Promise.all([
      handler(
        makeEvent('POST', '/auth/login', {
          email: 'sales1@example.com',
          password: 'StrongPass123!',
          deviceId: 'device-1',
        })
      ),
      handler(
        makeEvent('POST', '/auth/login', {
          email: 'sales1@example.com',
          password: 'StrongPass123!',
          deviceId: 'device-2',
        })
      ),
    ]);

    expect(res1.statusCode).toBe(200);
    expect(res2.statusCode).toBe(200);

    const b1 = JSON.parse(res1.body);
    const b2 = JSON.parse(res2.body);
    const stored = table.get('sales1@example.com')!;

    // Only one session is active in DynamoDB
    const me1 = await handler(
      makeEvent('GET', '/auth/me', undefined, { Authorization: `Bearer ${b1.accessToken}` })
    );
    const me2 = await handler(
      makeEvent('GET', '/auth/me', undefined, { Authorization: `Bearer ${b2.accessToken}` })
    );

    const statuses = [me1.statusCode, me2.statusCode].sort();
    expect(statuses).toEqual([200, 401]);
    expect([b1.sessionId, b2.sessionId]).toContain(stored.activeSessionId);
  });
});
