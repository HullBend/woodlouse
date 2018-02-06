/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.security.SecureRandom;

import woodlouse.crypto.ECIntegratedEncryption;
import woodlouse.crypto.KeyPair;

/**
 * Default entry point for ECIES based encryption.
 */
public final class ECIntegratedEncryptionProvider extends ECIntegratedEncryption {

   private static final ECIntegratedEncryption instance = new ECIntegratedEncryptionProvider();

   @Override
   public byte[] encryptEphemeral(final byte[] plainBytes, final ECIESPublicKey publicKey) {
      return ECDomain.encryptEphemeral(plainBytes, publicKey);
   }

   @Override
   public byte[] decryptEphemeral(final byte[] cipherBytes, final ECIESPrivateKey privateKey) {
      return ECDomain.decryptEphemeral(cipherBytes, privateKey);
   }

   @Override
   public KeyPair createNewKeyPair(final int keySize, final SecureRandom prng) {
      return ECDomain.createNewKeyPair(keySize, prng);
   }

   @Override
   public KeyPair createNewKeyPair() {
      return ECDomain.createNewKeyPair();
   }

   public static ECIntegratedEncryption create() {
      return instance;
   }
}
