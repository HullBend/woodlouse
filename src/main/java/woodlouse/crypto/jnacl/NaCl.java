/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.jnacl;

import woodlouse.crypto.jnacl.impl.Curve25519XSalsa20Poly1305;

/**
 * See <a href=http://cr.yp.to/highspeed/naclcrypto-20090310.pdf> Cryptography
 * in NaCl</a>
 */
final class NaCl {

   private static final int ZEROBYTES_COUNT = 32;
   private static final int BOXZEROBYTES_COUNT = 16;
   private static final int CRYPTO_OVERHEAD_BYTE_COUNT = 16;
   static final int KEY_BYTE_COUNT = 32;

   static byte[] encrypt(byte[] plainText, byte[] nonce, byte[] pubKey, byte[] privKey) {

      byte[] paddedIn = new byte[plainText.length + ZEROBYTES_COUNT];
      byte[] paddedOut = new byte[paddedIn.length];
      byte[] cipherText = new byte[paddedOut.length - BOXZEROBYTES_COUNT];

      System.arraycopy(plainText, 0, paddedIn, ZEROBYTES_COUNT, plainText.length);
      if (Curve25519XSalsa20Poly1305.crypto_box(paddedOut, paddedIn, paddedIn.length, nonce, pubKey, privKey) != 0) {
         throw new RuntimeException("Curve25519XSalsa20Poly1305.crypto_box() != 0");
      }
      System.arraycopy(paddedOut, BOXZEROBYTES_COUNT, cipherText, 0, cipherText.length);

      return cipherText;
   }

   static byte[] decrypt(byte[] cipherText, byte[] nonce, byte[] pubKey, byte[] privKey) {

      byte[] paddedIn = new byte[cipherText.length + BOXZEROBYTES_COUNT];
      byte[] paddedOut = new byte[paddedIn.length];
      byte[] plainText = new byte[cipherText.length - CRYPTO_OVERHEAD_BYTE_COUNT];

      System.arraycopy(cipherText, 0, paddedIn, BOXZEROBYTES_COUNT, cipherText.length);
      if (Curve25519XSalsa20Poly1305.crypto_box_open(paddedOut, paddedIn, paddedIn.length, nonce, pubKey, privKey) != 0) {
         throw new RuntimeException("Curve25519XSalsa20Poly1305.crypto_box_open() != 0");
      }
      System.arraycopy(paddedOut, ZEROBYTES_COUNT, plainText, 0, paddedOut.length - ZEROBYTES_COUNT);

      return plainText;
   }

   static byte[] getPublicKey(byte[] privKey) {

      byte[] publicKey = new byte[KEY_BYTE_COUNT];

      if (Curve25519XSalsa20Poly1305.crypto_box_getpublickey(publicKey, privKey) != 0) {
         throw new RuntimeException("Curve25519XSalsa20Poly1305.crypto_box_getpublickey() != 0");
      }

      return publicKey;
   }

   private NaCl() {
      throw new AssertionError();
   }
}
