/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.util;

import bouncycastle.crypto.PBEParametersGenerator;
import bouncycastle.crypto.digests.SHA256Digest;
import bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import bouncycastle.crypto.params.KeyParameter;

/**
 * A simplified wrapper around the password-based key derivation function
 * (PBKDF2) as defined in RSA PKCS#5 v2.0 that employs SHA2-256 as the
 * pseudo-random function.
 * <p/>
 * Cf. also <a href=http://tools.ietf.org/html/rfc2898> IETF RFC 2898</a>
 */
public final class PBKDF {

   private static final String PRIV_1 = "@GSr:p\"[dZR6RU;B:s&;4P<3XHPl@\"|r9*Az w#:";
   private static final String PRIV_2 = ",k~m:@HXE-a%%7 c](8J|Yu{d\"`./DK_f'z }^'S";

   private static final byte[] SALT_64 = { 59, -76, -110, 53, -98, 81, 100, 67, -90, 113, -119, -32, -5, -61, 44, -9, 8, -108, 107, -86, 118, -125, -70, -94,
         59, -106, -121, -18, 15, 12, 12, -77, 108, 70, 125, 23, -79, 66, 18, -51, 67, 55, 53, -28, -35, -92, -54, 37, -101, 57, 100, -128, 41, 24, 107, -25,
         -106, 73, -108, -110, -34, -102, -55, 74 };

   // Default here is 16384 (= 2^14) iterations
   private static final int ITERS = 1 << 14;

   public static byte[] generateKeyBytes(final String password, final int iterations, final int keyBytesLength) {
      String pwd = password;
      if (pwd == null || "".equals(pwd)) {
         pwd = PRIV_1;
      }
      pwd += PRIV_2;
      final byte[] pwdBytes = PBEParametersGenerator.PKCS5PasswordToBytes(pwd.toCharArray());

      PKCS5S2ParametersGenerator pbkdf = new PKCS5S2ParametersGenerator(new SHA256Digest());
      pbkdf.init(pwdBytes, SALT_64.clone(), iterations);

      KeyParameter params = (KeyParameter) pbkdf.generateDerivedParameters(keyBytesLength * 8);
      return params.getKey();
   }

   public static byte[] generateKeyBytes(final String password, final int keyBytesLength) {
      return generateKeyBytes(password, ITERS, keyBytesLength);
   }

   public static char[] generatePasswordChars(final String password, final int passwordLength) {
      final byte[] key = generateKeyBytes(password, passwordLength);
      char[] pwd = new char[key.length];
      for (int i = 0; i < key.length; ++i) {
         pwd[i] = (char) (key[i] & 0xFF);
      }
      return pwd;
   }

   private PBKDF() {
      throw new AssertionError();
   }
}
