import React from 'react';
import NetInfo from '@react-native-community/netinfo';
import { render, waitFor } from '@testing-library/react-native';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { AUTH_CONFIG } from '../src/config/authConfig';
import { AuthProvider } from '../src/context/AuthContext';
import { AppNavigator } from '../src/navigation/AppNavigator';
import { saveAuthCredentials } from '../src/storage/secureStorage';
import { resetMockSecureStore } from './jest.setup';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function createOfflineJwt(expOffsetSec: number): string {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(
    JSON.stringify({
      sub: 'sales1@example.com',
      sid: 'session-1',
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

describe('Navigation Guard', () => {
  beforeEach(() => {
    resetMockSecureStore();
    AUTH_CONFIG.jwtPublicKey = publicKey;
  });

  it('routes unauthenticated user to Login screen', async () => {
    const { getByText } = render(
      <AuthProvider>
        <AppNavigator />
      </AuthProvider>
    );

    await waitFor(() => expect(getByText('Salesperson Sign In')).toBeTruthy());
  });

  it('routes valid offline session to Dashboard screen', async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: false,
      isInternetReachable: false,
    });

    await saveAuthCredentials({
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      offlineToken: createOfflineJwt(3600),
      sessionId: 'session-1',
      deviceId: 'device-1',
      user: {
        email: 'sales1@example.com',
        name: 'Alex',
        role: 'SALESPERSON',
        status: 'ACTIVE',
      },
    });

    const { getByText } = render(
      <AuthProvider>
        <AppNavigator />
      </AuthProvider>
    );

    await waitFor(() => expect(getByText('Salesperson Dashboard')).toBeTruthy());
    expect(getByText('Auth Mode: OFFLINE')).toBeTruthy();
  });

  it('routes expired offline session to Login screen', async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({
      isConnected: false,
      isInternetReachable: false,
    });

    await saveAuthCredentials({
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      offlineToken: createOfflineJwt(-60),
      sessionId: 'session-1',
      deviceId: 'device-1',
      user: {
        email: 'sales1@example.com',
        name: 'Alex',
        role: 'SALESPERSON',
        status: 'ACTIVE',
      },
    });

    const { getByText } = render(
      <AuthProvider>
        <AppNavigator />
      </AuthProvider>
    );

    await waitFor(() => expect(getByText('Salesperson Sign In')).toBeTruthy());
  });
});
