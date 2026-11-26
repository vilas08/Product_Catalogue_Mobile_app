import { generateKeyPairSync } from 'node:crypto';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
});

console.log('=== RS256 PRIVATE KEY (Store ONLY in AWS Secrets Manager) ===');
console.log(privateKey);
console.log('=== RS256 PUBLIC KEY (Safe to configure in Lambda & Mobile) ===');
console.log(publicKey);
