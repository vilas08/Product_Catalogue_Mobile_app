export const AUTH_CONFIG = {
  apiBaseUrl: process.env.EXPO_PUBLIC_API_BASE_URL || 'https://api.example.com/prod',
  jwtIssuer: process.env.EXPO_PUBLIC_JWT_ISSUER || 'https://auth.example.com',
  // Public key ONLY. Never bundle private keys or signing secrets in the mobile app.
  jwtPublicKey: (
    process.env.EXPO_PUBLIC_JWT_PUBLIC_KEY ||
    '-----BEGIN PUBLIC KEY-----\nREPLACE_WITH_PRODUCTION_RS256_PUBLIC_KEY\n-----END PUBLIC KEY-----'
  )
    .replace(/\\n/g, '\n')
    .trim(),
};
