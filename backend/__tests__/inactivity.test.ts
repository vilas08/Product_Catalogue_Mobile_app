import { handler } from '../src/index';
import { createSeedUser, makeEvent, setupTestEnvironment } from './testHelpers';

describe('Seven-Day Inactivity Policy', () => {
  it('rejects session after 7 days of inactivity on /auth/me and /auth/refresh', async () => {
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

    // Simulate 8 days of inactivity in DynamoDB
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    const user = table.get('sales1@example.com')!;
    table.seed({ ...user, lastActivityAt: eightDaysAgo });

    const meRes = await handler(
      makeEvent('GET', '/auth/me', undefined, {
        Authorization: `Bearer ${loginBody.accessToken}`,
      })
    );
    expect(meRes.statusCode).toBe(401);
    expect(JSON.parse(meRes.body).code).toBe('INACTIVITY_EXPIRED');

    const refreshRes = await handler(
      makeEvent('POST', '/auth/refresh', {
        email: 'sales1@example.com',
        refreshToken: loginBody.refreshToken,
        sessionId: loginBody.sessionId,
      })
    );
    expect(refreshRes.statusCode).toBe(401);
    expect(JSON.parse(refreshRes.body).code).toBe('INACTIVITY_EXPIRED');
  });

  it('updates lastActivityAt on /auth/activity before expiry using server time', async () => {
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

    const sixDaysAgo = new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString();
    const user = table.get('sales1@example.com')!;
    table.seed({ ...user, lastActivityAt: sixDaysAgo });

    const actRes = await handler(
      makeEvent(
        'POST',
        '/auth/activity',
        {
          events: [{ action: 'visit_logged', timestamp: '2099-01-01T00:00:00.000Z' }],
        },
        { Authorization: `Bearer ${loginBody.accessToken}` }
      )
    );
    expect(actRes.statusCode).toBe(200);
    const updated = table.get('sales1@example.com')!;
    expect(updated.lastActivityAt).not.toBe('2099-01-01T00:00:00.000Z');
    expect(Date.parse(updated.lastActivityAt!)).toBeGreaterThan(Date.parse(sixDaysAgo));
  });

  it('does not allow offline activity timestamps to extend an already expired server deadline', async () => {
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

    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    const user = table.get('sales1@example.com')!;
    table.seed({ ...user, lastActivityAt: eightDaysAgo });

    const actRes = await handler(
      makeEvent(
        'POST',
        '/auth/activity',
        {
          events: [{ action: 'offline_sale', timestamp: new Date().toISOString() }],
        },
        { Authorization: `Bearer ${loginBody.accessToken}` }
      )
    );
    expect(actRes.statusCode).toBe(401);
    expect(JSON.parse(actRes.body).code).toBe('INACTIVITY_EXPIRED');
  });
});
