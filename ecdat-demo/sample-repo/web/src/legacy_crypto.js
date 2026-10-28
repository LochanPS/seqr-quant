// ACME Bank — legacy document-encryption helper.
// Encrypts statement PDFs before they are emailed to customers.
// Uses node-forge RSA (old module, scheduled for replacement).

const forge = require('node-forge');

function generateStatementKey() {
  // RSA-2048 keypair — quantum-vulnerable.
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  return keypair;
}

function encryptStatement(publicKey, pdfBytes) {
  return publicKey.encrypt(pdfBytes, 'RSA-OAEP');
}

module.exports = { generateStatementKey, encryptStatement };
