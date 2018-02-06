/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.util;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.util.Arrays;

import woodlouse.crypto.InvalidCipherBytesException;

/**
 * Provides Password based encryption along the lines of PKCS#12 v1.0, "Appendix
 * B" (cf.: ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf). More
 * specifically, it uses the Bouncy Castle JCE algorithm named
 * "PBEWithSHA256And256BitAES-CBC-BC", but the implementation here is based on
 * the Bouncy Castle lightweight API. Note that this utilization of the
 * algorithm prefixes the produced cipher text with a 12 byte random salt.
 */
public final class PBE {

   /*
    * Length of randomly produced (first) component of the salt.
    */
   private static final int SALT_PREFIX_LEN = 12;

   /*
    * Default is 4096 (= 2^12) iterations
    */
   private static final int ITERS = 1 << 12;

   /*
    * IV length for AES (in bits)
    */
   private static final int AES_IVLEN = 128;

   /*
    * AES-256 key length (in bits).
    */
   private static final int AES256_KEYLEN = 256;

   /*
    * Fixed (second) component of the salt (52 byte).
    */
   private static final byte[] SALT_52 = { -26, 50, 22, -72, -42, -96, 80, -117, -121, -29, -108, 2, -116, -18, 64, -89, -99, 81, -112, -109, -98, 115, 97,
         -33, -23, 40, 57, 53, 19, 57, -48, -53, 91, -74, 3, -123, 125, 81, 42, 44, 32, 113, -62, -112, 105, 38, -70, 90, 41, 1, 44, 59 };

   /*
    * PRNG used for random salt generation
    */
   private static final SecureRandom rng = new SecureRandom();

   public static byte[] encrypt(final byte[] bytes, final char[] password) {

      final byte[] salt = new byte[SALT_PREFIX_LEN];
      rng.nextBytes(salt);

      final byte[] entireSalt = ByteArrays.joinedArray(salt, SALT_52.clone());

      final byte[] cipherText = process(true, bytes, password, entireSalt);
      return ByteArrays.joinedArray(salt, cipherText);
   }

   public static byte[] decrypt(final byte[] bytes, final char[] password) {

      if (bytes == null || bytes.length < SALT_PREFIX_LEN) {
         throw new IllegalArgumentException("byte[] argument is null or too short");
      }

      final byte[] salt = ByteArrays.subArray(bytes, 0, SALT_PREFIX_LEN);
      final byte[] cipherText = ByteArrays.subArray(bytes, SALT_PREFIX_LEN, bytes.length);
      final byte[] entireSalt = ByteArrays.joinedArray(salt, SALT_52.clone());

      return process(false, cipherText, password, entireSalt);
   }

   private static byte[] process(final boolean forEncryption, final byte[] bytes, final char[] password, final byte[] salt) {
      try {
         final PKCS12ParametersGenerator keyGen = new PKCS12ParametersGenerator(new SHA256Digest());
         keyGen.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, ITERS);
         final CipherParameters keyParams = keyGen.generateDerivedParameters(AES256_KEYLEN, AES_IVLEN);

         final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()), new PKCS7Padding());
         cipher.init(forEncryption, keyParams);

         final byte[] processed = new byte[cipher.getOutputSize(bytes.length)];
         int outputLen = cipher.processBytes(bytes, 0, bytes.length, processed, 0);
         outputLen += cipher.doFinal(processed, outputLen);

         return Arrays.copyOfRange(processed, 0, outputLen);
      } catch (Exception e) {
         throw new InvalidCipherBytesException(e);
      }
   }

   private PBE() {
      throw new AssertionError();
   }
}
