/**
 * Fixture: JavaScript file with RSA JWT signing. Scanner must flag RS256 as vulnerable.
 */
const jwt = require('jsonwebtoken');

// RS256 — RSA-based JWT signing algorithm, quantum-vulnerable
const token = jwt.sign({ userId: 123 }, privateKey, { algorithm: 'RS256' });

// Also flag direct RSA import
const crypto = require('crypto');
const { generateKeyPairSync } = crypto;

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
