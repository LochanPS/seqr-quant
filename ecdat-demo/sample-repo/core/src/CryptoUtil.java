// ACME Bank — core banking crypto utility.
// Generates the RSA keypair used to sign inter-branch transfer messages.

package com.acmebank.core;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class CryptoUtil {

    /** RSA-2048 keypair for signing inter-branch settlement messages. */
    public static KeyPair generateTransferSigningKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
