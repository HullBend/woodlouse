/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import bouncycastle.crypto.Digest;
import bouncycastle.crypto.Mac;
import bouncycastle.crypto.digests.SHA256Digest;
import bouncycastle.crypto.digests.SHA3Digest;
import bouncycastle.crypto.digests.SHA512tDigest;
import bouncycastle.crypto.macs.HMac;
import bouncycastle.crypto.params.IESWithCipherParameters;

/**
 * Provides automatic ECIES parametrization as a function of the ECIES key
 * length.
 */
final class ECIESParams {

   /*
    * Size of the (symmetric) cipher's key in bits (256 bit AES in our case)
    */
   private static final int CIPHER_KEY_SIZE = 256;

   /*
    * Random derivation parameter for the KDF function (64 byte).
    */
   private static final byte[] derivation = { 12, -122, -28, -24, -61, -28, 84, 81, -6, 63, 7, -89, -121, 52, -59, 105, -77, 102, -123, 0, 29, 57, -19, 106,
         -63, 32, -85, 35, -33, -52, 87, -84, -79, 127, 45, -52, -32, -32, 10, -119, -72, -29, 116, 95, 64, 42, 7, -11, 77, 63, -81, -8, 93, -105, -76, 46, 96,
         -113, -110, -59, -50, 81, 105, 104 };

   /*
    * Random encoding parameter for the MAC (64 byte).
    */
   private static final byte[] encoding = { -45, -93, -100, 116, 83, -49, -60, 53, -117, 25, 110, -97, -107, -29, -84, 66, -21, -21, -86, 67, -106, -16, 112,
         34, 40, -69, 67, -5, 7, 10, 72, 69, 48, 66, -40, 58, 101, -2, -100, 17, -114, 56, 26, -27, 32, 6, -89, -97, -112, 4, 2, 83, -63, -78, -82, -91, -99,
         -39, -42, 33, -115, -72, -104, 111 };

   static IESWithCipherParameters getParams(final int keySize) {
      return new IESWithCipherParameters(derivation.clone(), encoding.clone(), macKeyLenInBits(keySize), CIPHER_KEY_SIZE);
   }

   static Mac getMACGen(final int keySize) {
      return new HMac(getDigest(hashOutputLenForMAC(keySize)));
   }

   static Digest getKDFDigest(final int keySize) {
      return getDigest(hashOutputLenForKDF(keySize));
   }

   private static Digest getDigest(final int numBits) {
      switch (numBits) {
      case 224:
         // SHA2-512t/224
         return new SHA512tDigest(224);
      case 256:
         // SHA2-256
         return new SHA256Digest();
      case 320:
         // SHA2-512t/320
         return new SHA512tDigest(320);
      case 384:
      case 512:
         // SHA3-x
         return new SHA3Digest(numBits);
      default:
         return new SHA3Digest(512);
      }
   }

   /*
    * Mapping from ECC key length to the hash function output length for the
    * KDF.
    */
   private static int hashOutputLenForKDF(final int keyLen) {
      // always use a 512 bit SHA since that should have a
      // strength of 256 bit which is the appropriate choice
      // for a 256 bit AES
      return 512;
   }

   /*
    * Mapping from ECC key length to the size of the MAC generated which should
    * be equal to the ECC key length. This has a direct effect on the size of
    * the generated cipher output.
    */
   private static int hashOutputLenForMAC(final int keyLen) {
      switch (keyLen) {
      case 224:
      case 256:
      case 320:
      case 384:
      case 512:
         return keyLen;
      default:
         return 512;
      }
   }

   /*
    * Mapping from the ECC key length to the HMAC key length which should be
    * equal to the block size (in bits) of the hash function used for the MAC.
    */
   private static final int macKeyLenInBits(final int keyLen) {
      switch (keyLen) {
      case 224:
         // SHA2-512t/224 , block = 128
         return 128 * 8;
      case 256:
         // SHA2-256 , block = 64
         return 64 * 8;
      case 320:
         // SHA2-512t/320 , block = 128
         return 128 * 8;
      case 384:
         // SHA3-384 , block = 104
         return 104 * 8;
      case 512:
         // SHA3-512 , block = 72
         return 72 * 8;
      default:
         // SHA3-512 , block = 72
         return 72 * 8;
      }
   }

   private ECIESParams() {
      throw new AssertionError();
   }
}
