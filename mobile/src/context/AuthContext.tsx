import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import NetInfo from '@react-native-community/netinfo';
import { AuthApiClient, NetworkUnavailableError, SessionRevokedError } from '../api/apiClient';
import { verifyOfflineJwt } from '../auth/offlineJwt';
import {
  appendOfflineActivity,
  clearOfflineActivityQueue,
  clearSessionCredentials,
  getOfflineActivityQueue,
  getOrCreateDeviceId,
  getStoredCredentials,
  getStoredUser,
  saveAuthCredentials,
} from '../storage/secureStorage';
import { AuthMode, AuthUser } from '../types/auth';

export interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  authMode: AuthMode;
  user: AuthUser | null;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<boolean>;
  verifyOfflineSession: () => Promise<boolean>;
  getCurrentUser: () => Promise<AuthUser | null>;
  synchronizeActivity: () => Promise<void>;
  recordLocalActivity: (action: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  offlineToken: string;
  sessionId: string;
  deviceId: string;
  user: AuthUser;
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [authMode, setAuthMode] = useState<AuthMode>('ONLINE');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSessionRevoked = useCallback(async () => {
    await clearSessionCredentials();
    setUser(null);
    setIsAuthenticated(false);
    setAuthMode('ONLINE');
  }, []);

  const apiClient = useMemo(
    () =>
      new AuthApiClient({
        onSessionRevoked: handleSessionRevoked,
      }),
    [handleSessionRevoked]
  );

  const verifyOfflineSession = useCallback(async (): Promise<boolean> => {
    const creds = await getStoredCredentials();
    const storedUser = await getStoredUser();

    if (!creds.offlineToken || !creds.sessionId || !storedUser) {
      await clearSessionCredentials();
      setUser(null);
      setIsAuthenticated(false);
      return false;
    }

    const result = verifyOfflineJwt(creds.offlineToken, {
      expectedSessionId: creds.sessionId,
      expectedSubject: storedUser.email,
    });

    if (!result.valid) {
      await clearSessionCredentials();
      setUser(null);
      setIsAuthenticated(false);
      return false;
    }

    setUser(storedUser);
    setAuthMode('OFFLINE');
    setIsAuthenticated(true);
    return true;
  }, []);

  const refreshSession = useCallback(async (): Promise<boolean> => {
    try {
      await apiClient.refreshAccessToken();
      setAuthMode('ONLINE');
      setIsAuthenticated(true);
      return true;
    } catch (err) {
      if (err instanceof SessionRevokedError) {
        return false;
      }
      if (err instanceof NetworkUnavailableError) {
        return verifyOfflineSession();
      }
      return false;
    }
  }, [apiClient, verifyOfflineSession]);

  const getCurrentUser = useCallback(async (): Promise<AuthUser | null> => {
    try {
      const data = await apiClient.request<{ user: AuthUser }>('/auth/me', {
        method: 'GET',
      });
      setUser(data.user);
      setAuthMode('ONLINE');
      setIsAuthenticated(true);
      return data.user;
    } catch (err) {
      if (err instanceof NetworkUnavailableError) {
        const offlineOk = await verifyOfflineSession();
        return offlineOk ? await getStoredUser() : null;
      }
      if (err instanceof SessionRevokedError) {
        return null;
      }
      return null;
    }
  }, [apiClient, verifyOfflineSession]);

  const synchronizeActivity = useCallback(async (): Promise<void> => {
    const queue = await getOfflineActivityQueue();
    try {
      await apiClient.request('/auth/activity', {
        method: 'POST',
        body: JSON.stringify({ events: queue }),
      });
      if (queue.length > 0) {
        await clearOfflineActivityQueue();
      }
      setAuthMode('ONLINE');
    } catch (err) {
      if (err instanceof NetworkUnavailableError) {
        setAuthMode('OFFLINE');
        return;
      }
      if (err instanceof SessionRevokedError) {
        return;
      }
    }
  }, [apiClient]);

  const recordLocalActivity = useCallback(async (action: string): Promise<void> => {
    await appendOfflineActivity({
      action,
      timestamp: new Date().toISOString(),
    });
  }, []);

  const login = useCallback(
    async (email: string, password: string): Promise<void> => {
      setError(null);
      setIsLoading(true);
      try {
        const deviceId = await getOrCreateDeviceId();
        const data = await apiClient.postPublic<LoginResponse>('/auth/login', {
          email: email.trim().toLowerCase(),
          password,
          deviceId,
        });

        await saveAuthCredentials({
          accessToken: data.accessToken,
          refreshToken: data.refreshToken,
          offlineToken: data.offlineToken,
          sessionId: data.sessionId,
          deviceId: data.deviceId,
          user: data.user,
        });

        setUser(data.user);
        setAuthMode('ONLINE');
        setIsAuthenticated(true);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Login failed';
        setError(msg);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [apiClient]
  );

  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    try {
      const creds = await getStoredCredentials();
      if (creds.accessToken && creds.sessionId) {
        try {
          await apiClient.request('/auth/logout', {
            method: 'POST',
            body: JSON.stringify({ sessionId: creds.sessionId }),
          });
        } catch {
          // Always clear local SecureStore credentials even if offline or request fails
        }
      }
    } finally {
      await clearSessionCredentials();
      setUser(null);
      setIsAuthenticated(false);
      setAuthMode('ONLINE');
      setError(null);
      setIsLoading(false);
    }
  }, [apiClient]);

  useEffect(() => {
    let mounted = true;

    async function bootstrapAuth() {
      try {
        const creds = await getStoredCredentials();
        if (!creds.sessionId || (!creds.accessToken && !creds.offlineToken)) {
          if (mounted) {
            setIsAuthenticated(false);
          }
          return;
        }

        const netState = await NetInfo.fetch();
        const isOnline = Boolean(netState.isConnected && netState.isInternetReachable !== false);

        if (isOnline) {
          const onlineUser = await getCurrentUser();
          if (onlineUser && mounted) {
            await synchronizeActivity();
          }
        } else {
          await verifyOfflineSession();
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    }

    bootstrapAuth();
    return () => {
      mounted = false;
    };
  }, [getCurrentUser, synchronizeActivity, verifyOfflineSession]);

  const value: AuthContextValue = {
    isAuthenticated,
    isLoading,
    authMode,
    user,
    error,
    login,
    logout,
    refreshSession,
    verifyOfflineSession,
    getCurrentUser,
    synchronizeActivity,
    recordLocalActivity,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
