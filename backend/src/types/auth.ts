export type UserRole = 'USER' | 'SALESPERSON';
export type UserStatus = 'ACTIVE' | 'INACTIVE';
export type SessionStatus = 'ACTIVE' | 'REVOKED';

export interface UserRecord {
  email: string;
  passwordHash: string;
  name: string;
  role: UserRole;
  status: UserStatus;
  activeSessionId?: string | null;
  activeDeviceId?: string | null;
  refreshTokenHash?: string | null;
  refreshExpiresAt?: string | null;
  sessionCreatedAt?: string | null;
  lastActivityAt?: string | null;
  sessionStatus?: SessionStatus;
  createdAt: string;
  lastLogin?: string | null;
}

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  deviceId: string;
  tokenType: 'access';
  iss: string;
  aud: string;
  iat: number;
  exp: number;
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

export interface AuthenticatedContext {
  user: UserRecord;
  claims: AccessTokenClaims;
}
