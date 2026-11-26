import { AuthApiClient, SessionRevokedError } from '../src/api/apiClient';
import { getStoredCredentials, saveAuthCredentials } from '../src/storage/secureStorage';
import { resetMockSecureStore } from './jest.setup';

describe('AuthApiClient', () => {
  beforeEach(async () => {
    resetMockSecureStore();
    await saveAuthCredentials({
      accessToken: 'expired-access-token',
      refreshToken: 'refresh-1',
      offlineToken: 'offline-1',
      sessionId: 'session-1',
      deviceId: 'device-1',
      user: {
        email: 'sales1@example.com',
        name: 'Alex',
        role: 'SALESPERSON',
        status: 'ACTIVE',
      },
    });
  });

  it('uses a shared refresh lock for concurrent 401 responses and rotates tokens', async () => {
    let refreshCallCount = 0;
    const fetchMock = jest.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/auth/refresh')) {
        refreshCallCount += 1;
        return {
          ok: true,
          status: 200,
          json: async () => ({
            accessToken: 'new-access-token',
            refreshToken: 'refresh-2',
          }),
        } as Response;
      }

      const authHeader = (init?.headers as Record<string, string>)?.Authorization;
      if (authHeader === 'Bearer expired-access-token') {
        return {
          ok: false,
          status: 401,
          json: async () => ({ error: 'Expired' }),
        } as Response;
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true }),
      } as Response;
    });

    global.fetch = fetchMock as unknown as typeof fetch;
    const onSessionRevoked = jest.fn();
    const client = new AuthApiClient({ onSessionRevoked }, 'https://api.test');

    const [r1, r2] = await Promise.all([
      client.request<{ ok: boolean }>('/auth/me'),
      client.request<{ ok: boolean }>('/auth/me'),
    ]);

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(refreshCallCount).toBe(1);
    expect(onSessionRevoked).not.toHaveBeenCalled();

    const stored = await getStoredCredentials();
    expect(stored.accessToken).toBe('new-access-token');
    expect(stored.refreshToken).toBe('refresh-2');
  });

  it('prevents infinite refresh loops and revokes session if retry returns 401', async () => {
    const fetchMock = jest.fn(async (url: string) => {
      if (url.endsWith('/auth/refresh')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            accessToken: 'still-rejected-token',
            refreshToken: 'refresh-2',
          }),
        } as Response;
      }
      return {
        ok: false,
        status: 401,
        json: async () => ({ error: 'Revoked' }),
      } as Response;
    });

    global.fetch = fetchMock as unknown as typeof fetch;
    const onSessionRevoked = jest.fn();
    const client = new AuthApiClient({ onSessionRevoked }, 'https://api.test');

    await expect(client.request('/auth/me')).rejects.toThrow(SessionRevokedError);
    expect(onSessionRevoked).toHaveBeenCalledTimes(1);

    const stored = await getStoredCredentials();
    expect(stored.accessToken).toBeNull();
    expect(stored.refreshToken).toBeNull();
  });
});
