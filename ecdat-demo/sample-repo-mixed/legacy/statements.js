// ACME Bank — legacy statement encryption (NOT yet migrated).
const forge = require('node-forge');
function generateStatementKey() {
  return forge.pki.rsa.generateKeyPair({ bits: 2048 }); // TODO: migrate to ML-KEM
}
module.exports = { generateStatementKey };
