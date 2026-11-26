export type UserRole = 'USER' | 'SALESPERSON';
export type UserStatus = 'ACTIVE' | 'INACTIVE';
export type AuthMode = 'ONLINE' | 'OFFLINE';

export interface AuthUser {
  email: string;
  name: string;
  role: UserRole;
  status: UserStatus;
  activeSessionId?: string;
  activeDeviceId?: string;
  lastActivityAt?: string;
  lastLogin?: string;
}

export interface OfflineTokenClaims {
  sub: string;
  sid: string;
  deviceId: string;
  tokenType: 'offline';
  iss: string;
  aud: string;
  iat: number;
  exp: number;
}

export interface OfflineActivityRecord {
  action: string;
  timestamp: string;
}

export interface StoredCredentials {
  accessToken: string | null;
  refreshToken: string | null;
  offlineToken: string | null;
  sessionId: string | null;
  deviceId: string | null;
}
