// ACME Bank — net-banking web API auth module.
// Issues and verifies customer JWTs, and generates the RSA keypair used
// for the partner webhook signature.

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// RSA keypair for signing outbound partner webhooks — quantum-vulnerable.
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

function issueToken(customerId) {
  // RS256 = RSA-signed JWT.
  return jwt.sign({ sub: customerId, scope: 'netbanking' }, privateKey, {
    algorithm: 'RS256',
    expiresIn: '12h',
  });
}

function signWebhook(body) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(body);
  return signer.sign(privateKey, 'base64');
}

module.exports = { issueToken, signWebhook, publicKey };
