import { AUTH_CONFIG } from '../config/authConfig';
import {
  clearSessionCredentials,
  getStoredCredentials,
  getStoredUser,
  updateRotatedTokens,
} from '../storage/secureStorage';

export class SessionRevokedError extends Error {
  constructor(message = 'Session has been revoked or expired') {
    super(message);
    this.name = 'SessionRevokedError';
  }
}

export class NetworkUnavailableError extends Error {
  constructor(message = 'Network request failed') {
    super(message);
    this.name = 'NetworkUnavailableError';
  }
}

export interface ApiClientCallbacks {
  onSessionRevoked: () => Promise<void> | void;
}

export class AuthApiClient {
  private refreshPromise: Promise<string> | null = null;
  private callbacks: ApiClientCallbacks;
  private baseUrl: string;

  constructor(callbacks: ApiClientCallbacks, baseUrl = AUTH_CONFIG.apiBaseUrl) {
    this.callbacks = callbacks;
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async safeFetch(path: string, init: RequestInit): Promise<Response> {
    try {
      return await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: {
          'Content-Type': 'application/json',
          ...(init.headers || {}),
        },
      });
    } catch (err) {
      throw new NetworkUnavailableError(
        err instanceof Error ? err.message : 'Network unavailable'
      );
    }
  }

  async refreshAccessToken(): Promise<string> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      const creds = await getStoredCredentials();
      const user = await getStoredUser();

      if (!creds.refreshToken || !creds.sessionId || !user?.email) {
        await clearSessionCredentials();
        await this.callbacks.onSessionRevoked();
        throw new SessionRevokedError('Missing refresh credentials');
      }

      const res = await this.safeFetch('/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({
          email: user.email,
          refreshToken: creds.refreshToken,
          sessionId: creds.sessionId,
        }),
      });

      if (!res.ok) {
        await clearSessionCredentials();
        await this.callbacks.onSessionRevoked();
        throw new SessionRevokedError('Refresh token rejected');
      }

      const data = (await res.json()) as {
        accessToken: string;
        refreshToken: string;
      };

      await updateRotatedTokens({
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
      });

      return data.accessToken;
    })();

    try {
      return await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }

  async request<T>(
    path: string,
    init: RequestInit = {},
    hasRetried = false
  ): Promise<T> {
    const creds = await getStoredCredentials();
    if (!creds.accessToken) {
      throw new SessionRevokedError('No access token');
    }

    const res = await this.safeFetch(path, {
      ...init,
      headers: {
        ...(init.headers || {}),
        Authorization: `Bearer ${creds.accessToken}`,
      },
    });

    if (res.status === 401) {
      if (hasRetried) {
        // Prevent infinite refresh loops
        await clearSessionCredentials();
        await this.callbacks.onSessionRevoked();
        throw new SessionRevokedError('Authentication failed after refresh');
      }

      const newAccessToken = await this.refreshAccessToken();
      const retryRes = await this.safeFetch(path, {
        ...init,
        headers: {
          ...(init.headers || {}),
          Authorization: `Bearer ${newAccessToken}`,
        },
      });

      if (retryRes.status === 401) {
        await clearSessionCredentials();
        await this.callbacks.onSessionRevoked();
        throw new SessionRevokedError('Session revoked');
      }

      if (!retryRes.ok) {
        const errBody = (await retryRes.json().catch(() => ({}))) as { error?: string };
        throw new Error(errBody.error || `Request failed with status ${retryRes.status}`);
      }

      return (await retryRes.json()) as T;
    }

    if (!res.ok) {
      const errBody = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(errBody.error || `Request failed with status ${res.status}`);
    }

    return (await res.json()) as T;
  }

  async postPublic<T>(path: string, body: Record<string, unknown>): Promise<T> {
    const res = await this.safeFetch(path, {
      method: 'POST',
      body: JSON.stringify(body),
    });

    const data = (await res.json().catch(() => ({}))) as T & { error?: string };
    if (!res.ok) {
      throw new Error(data.error || `Request failed with status ${res.status}`);
    }
    return data;
  }
}
