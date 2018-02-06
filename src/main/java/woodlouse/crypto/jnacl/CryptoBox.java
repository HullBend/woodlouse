/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.jnacl;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * An "ephemeral-static mode" key agreement variant of the combination of the <a
 * href=http://cr.yp.to/ecdh/curve25519-20060209.pdf> Curve25519</a>
 * elliptic-curve Diffie-Hellman function, the Salsa20 stream cipher, and the
 * Poly1305 message-authentication code as recommended in <a
 * href=http://cr.yp.to/highspeed/naclcrypto-20090310.pdf> Cryptography in
 * NaCl</a> (which uses static-static mode by default).
 * <p/>
 * See also <a href=http://cr.yp.to/ecdh.html> A state-of-the-art Diffie-Hellman
 * function</a> and the <a href=http://nacl.cr.yp.to/box.html> crypto_box</a>
 * API.
 */
public final class CryptoBox {

   private static final int NONCE_BYTE_COUNT = 24;
   private static final SecureRandom prng = new SecureRandom();

   /**
    * Encrypt the byte array {@code plainBytes} using the key
    * {@code publicKeyBytes}.
    * 
    * @param plainBytes
    *           bytes to encrypt.
    * @param publicKeyBytes
    *           key to use for encryption.
    * @return encrypted bytes.
    */
   public static byte[] encryptEphemeral(byte[] plainBytes, byte[] publicKeyBytes) {

      byte[] nonce = new byte[NONCE_BYTE_COUNT];
      prng.nextBytes(nonce);

      byte[][] ephemeralKeyPair = createNewKeyPair();
      byte[] ephemeralPrivKey = ephemeralKeyPair[0];

      byte[] cipherBytes = NaCl.encrypt(plainBytes, nonce, publicKeyBytes, ephemeralPrivKey);
      Arrays.fill(ephemeralPrivKey, (byte) 0);

      byte[] triple = new byte[NONCE_BYTE_COUNT + NaCl.KEY_BYTE_COUNT + cipherBytes.length];
      byte[] ephemeralPubKey = ephemeralKeyPair[1];

      System.arraycopy(nonce, 0, triple, 0, nonce.length);
      System.arraycopy(ephemeralPubKey, 0, triple, nonce.length, ephemeralPubKey.length);
      System.arraycopy(cipherBytes, 0, triple, nonce.length + ephemeralPubKey.length, cipherBytes.length);

      return triple;
   }

   /**
    * Decrypt the crypted byte array {@code cipherBytes} using the key
    * {@code privateKeyBytes}.
    * 
    * @param cipherBytes
    *           crypted byte array to decrypt.
    * @param privateKeyBytes
    *           key to use for decryption.
    * @return decrypted plain bytes.
    */
   public static byte[] decryptEphemeral(byte[] cipherBytes, byte[] privateKeyBytes) {

      byte[] rawCipherBytes = new byte[cipherBytes.length - NONCE_BYTE_COUNT - NaCl.KEY_BYTE_COUNT];
      byte[] nonce = new byte[NONCE_BYTE_COUNT];
      byte[] pubKey = new byte[NaCl.KEY_BYTE_COUNT];

      System.arraycopy(cipherBytes, 0, nonce, 0, nonce.length);
      System.arraycopy(cipherBytes, nonce.length, pubKey, 0, pubKey.length);
      System.arraycopy(cipherBytes, nonce.length + pubKey.length, rawCipherBytes, 0, rawCipherBytes.length);

      return NaCl.decrypt(rawCipherBytes, nonce, pubKey, privateKeyBytes);
   }

   /**
    * Create a new randomly generated key pair. The keys are byte arrays and are
    * returned in a two-dimensional byte array (the first component is the
    * private key and the second is the public key).
    * 
    * @return new key pair as a two-dimensional byte array where the first
    *         component (at index 0) is the private key and the second component
    *         (at index 1) is the public key.
    */
   public static byte[][] createNewKeyPair() {

      byte[][] keyPair = new byte[2][];
      byte[] privateKey = new byte[NaCl.KEY_BYTE_COUNT];

      prng.nextBytes(privateKey);

      keyPair[0] = privateKey;
      keyPair[1] = NaCl.getPublicKey(privateKey);

      return keyPair;
   }

   private CryptoBox() {
      throw new AssertionError();
   }
}
