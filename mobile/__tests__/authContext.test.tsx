import React from 'react';
import { Text } from 'react-native';
import NetInfo from '@react-native-community/netinfo';
import { act, render, waitFor } from '@testing-library/react-native';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { AUTH_CONFIG } from '../src/config/authConfig';
import { AuthProvider, useAuth } from '../src/context/AuthContext';
import {
  getOfflineActivityQueue,
  getStoredCredentials,
  saveAuthCredentials,
} from '../src/storage/secureStorage';
import { resetMockSecureStore } from './jest.setup';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function createOfflineJwt(sid: string, expOffsetSec = 3600): string {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(
    JSON.stringify({
      sub: 'sales1@example.com',
      sid,
      deviceId: 'device-1',
      tokenType: 'offline',
      iss: AUTH_CONFIG.jwtIssuer,
      aud: 'mobile-offline',
      iat: nowSec - 60,
      exp: nowSec + expOffsetSec,
    })
  ).toString('base64url');
  const sig = cryptoSign('RSA-SHA256', Buffer.from(`${header}.${body}`), privateKey).toString(
    'base64url'
  );
  return `${header}.${body}.${sig}`;
}

describe('AuthContext Offline, Sync, and Logout', () => {
  beforeEach(() => {
    resetMockSecureStore();
    AUTH_CONFIG.jwtPublicKey = publicKey;
  });

  it('authenticates offline with valid offline JWT and clears credentials on offline logout', async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: false,
      isInternetReachable: false,
    });

    await saveAuthCredentials({
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      offlineToken: createOfflineJwt('session-1'),
      sessionId: 'session-1',
      deviceId: 'device-1',
      user: {
        email: 'sales1@example.com',
        name: 'Alex',
        role: 'SALESPERSON',
        status: 'ACTIVE',
      },
    });

    let capturedAuth: ReturnType<typeof useAuth> | null = null;
    const Probe = () => {
      const auth = useAuth();
      capturedAuth = auth;
      return <Text>{auth.isAuthenticated ? auth.authMode : 'LOGGED_OUT'}</Text>;
    };

    const { getByText } = render(
      <AuthProvider>
        <Probe />
      </AuthProvider>
    );

    await waitFor(() => expect(getByText('OFFLINE')).toBeTruthy());

    await act(async () => {
      await capturedAuth!.recordLocalActivity('offline_order');
    });
    expect(await getOfflineActivityQueue()).toHaveLength(1);

    // Offline logout must clear SecureStore even when network is down
    global.fetch = jest.fn(async () => {
      throw new Error('Network down');
    }) as unknown as typeof fetch;

    await act(async () => {
      await capturedAuth!.logout();
    });

    await waitFor(() => expect(getByText('LOGGED_OUT')).toBeTruthy());
    const creds = await getStoredCredentials();
    expect(creds.accessToken).toBeNull();
    expect(creds.refreshToken).toBeNull();
    expect(creds.offlineToken).toBeNull();
    expect(creds.sessionId).toBeNull();
  });

  it('synchronizes queued offline activity when connectivity returns', async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: true,
      isInternetReachable: true,
    });

    await saveAuthCredentials({
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      offlineToken: createOfflineJwt('session-1'),
      sessionId: 'session-1',
      deviceId: 'device-1',
      user: {
        email: 'sales1@example.com',
        name: 'Alex',
        role: 'SALESPERSON',
        status: 'ACTIVE',
      },
    });

    const syncedBodies: unknown[] = [];
    global.fetch = jest.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/auth/me')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            user: {
              email: 'sales1@example.com',
              name: 'Alex',
              role: 'SALESPERSON',
              status: 'ACTIVE',
            },
          }),
        } as Response;
      }
      if (url.endsWith('/auth/activity')) {
        syncedBodies.push(JSON.parse(String(init?.body || '{}')));
        return {
          ok: true,
          status: 200,
          json: async () => ({ success: true }),
        } as Response;
      }
      return { ok: false, status: 404, json: async () => ({}) } as Response;
    }) as unknown as typeof fetch;

    let capturedAuth: ReturnType<typeof useAuth> | null = null;
    const Probe = () => {
      const auth = useAuth();
      capturedAuth = auth;
      return <Text>{auth.isAuthenticated ? auth.authMode : 'LOGGED_OUT'}</Text>;
    };

    const { getByText } = render(
      <AuthProvider>
        <Probe />
      </AuthProvider>
    );

    await waitFor(() => expect(getByText('ONLINE')).toBeTruthy());

    await act(async () => {
      await capturedAuth!.recordLocalActivity('offline_visit');
      await capturedAuth!.synchronizeActivity();
    });

    expect(await getOfflineActivityQueue()).toHaveLength(0);
    expect(syncedBodies.length).toBeGreaterThanOrEqual(2);
  });
});
