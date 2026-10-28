/** A public/secret keypair. Keys are raw `Uint8Array` bytes, as the FIPS schemes define them. */
export class KeyPair {
  /**
   * @param {Uint8Array} publicKey
   * @param {Uint8Array} secretKey
   */
  constructor(publicKey, secretKey) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    Object.freeze(this);
  }
}
