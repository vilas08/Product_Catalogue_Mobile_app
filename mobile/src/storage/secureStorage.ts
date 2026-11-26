import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import { AuthUser, OfflineActivityRecord, StoredCredentials } from '../types/auth';

const KEYS = {
  ACCESS_TOKEN: 'auth_access_token',
  REFRESH_TOKEN: 'auth_refresh_token',
  OFFLINE_TOKEN: 'auth_offline_token',
  SESSION_ID: 'auth_session_id',
  DEVICE_ID: 'auth_device_id',
  USER_PROFILE: 'auth_user_profile',
  OFFLINE_ACTIVITY_QUEUE: 'auth_offline_activity_queue',
} as const;

export async function getOrCreateDeviceId(): Promise<string> {
  const existing = await SecureStore.getItemAsync(KEYS.DEVICE_ID);
  if (existing) {
    return existing;
  }
  const generated = Crypto.randomUUID();
  await SecureStore.setItemAsync(KEYS.DEVICE_ID, generated);
  return generated;
}

export async function saveAuthCredentials(params: {
  accessToken: string;
  refreshToken: string;
  offlineToken: string;
  sessionId: string;
  deviceId: string;
  user: AuthUser;
}): Promise<void> {
  await Promise.all([
    SecureStore.setItemAsync(KEYS.ACCESS_TOKEN, params.accessToken),
    SecureStore.setItemAsync(KEYS.REFRESH_TOKEN, params.refreshToken),
    SecureStore.setItemAsync(KEYS.OFFLINE_TOKEN, params.offlineToken),
    SecureStore.setItemAsync(KEYS.SESSION_ID, params.sessionId),
    SecureStore.setItemAsync(KEYS.DEVICE_ID, params.deviceId),
    SecureStore.setItemAsync(KEYS.USER_PROFILE, JSON.stringify(params.user)),
  ]);
}

export async function updateRotatedTokens(params: {
  accessToken: string;
  refreshToken: string;
}): Promise<void> {
  await Promise.all([
    SecureStore.setItemAsync(KEYS.ACCESS_TOKEN, params.accessToken),
    SecureStore.setItemAsync(KEYS.REFRESH_TOKEN, params.refreshToken),
  ]);
}

export async function getStoredCredentials(): Promise<StoredCredentials> {
  const [accessToken, refreshToken, offlineToken, sessionId, deviceId] = await Promise.all([
    SecureStore.getItemAsync(KEYS.ACCESS_TOKEN),
    SecureStore.getItemAsync(KEYS.REFRESH_TOKEN),
    SecureStore.getItemAsync(KEYS.OFFLINE_TOKEN),
    SecureStore.getItemAsync(KEYS.SESSION_ID),
    SecureStore.getItemAsync(KEYS.DEVICE_ID),
  ]);

  return {
    accessToken,
    refreshToken,
    offlineToken,
    sessionId,
    deviceId,
  };
}

export async function getStoredUser(): Promise<AuthUser | null> {
  const raw = await SecureStore.getItemAsync(KEYS.USER_PROFILE);
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

export async function appendOfflineActivity(record: OfflineActivityRecord): Promise<void> {
  const existing = await getOfflineActivityQueue();
  existing.push(record);
  await SecureStore.setItemAsync(KEYS.OFFLINE_ACTIVITY_QUEUE, JSON.stringify(existing));
}

export async function getOfflineActivityQueue(): Promise<OfflineActivityRecord[]> {
  const raw = await SecureStore.getItemAsync(KEYS.OFFLINE_ACTIVITY_QUEUE);
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as OfflineActivityRecord[]) : [];
  } catch {
    return [];
  }
}

export async function clearOfflineActivityQueue(): Promise<void> {
  await SecureStore.deleteItemAsync(KEYS.OFFLINE_ACTIVITY_QUEUE);
}

export async function removeSyncedOfflineActivities(syncedCount: number): Promise<void> {
  if (syncedCount <= 0) {
    return;
  }
  const current = await getOfflineActivityQueue();
  const remaining = current.slice(syncedCount);
  if (remaining.length === 0) {
    await clearOfflineActivityQueue();
  } else {
    await SecureStore.setItemAsync(KEYS.OFFLINE_ACTIVITY_QUEUE, JSON.stringify(remaining));
  }
}

/**
 * Clears session credentials while preserving the stable installation deviceId.
 */
export async function clearSessionCredentials(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(KEYS.ACCESS_TOKEN),
    SecureStore.deleteItemAsync(KEYS.REFRESH_TOKEN),
    SecureStore.deleteItemAsync(KEYS.OFFLINE_TOKEN),
    SecureStore.deleteItemAsync(KEYS.SESSION_ID),
    SecureStore.deleteItemAsync(KEYS.USER_PROFILE),
    SecureStore.deleteItemAsync(KEYS.OFFLINE_ACTIVITY_QUEUE),
  ]);
}
