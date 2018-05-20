/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A provider-independent implementation of {@link ECIESPrivateKey} that is also
 * a {@link SecretKey}.
 */
public class PrivateKeyImpl extends SecretKeySpec implements ECIESPrivateKey {

   private static final long serialVersionUID = 8439189155178128411L;

   /**
    * @param key
    * @param offset
    * @param len
    * @param algorithm
    */
   public PrivateKeyImpl(final byte[] key, final int offset, final int len, final String algorithm) {
      super(key, offset, len, algorithm);
   }

   /**
    * @param key
    * @param algorithm
    */
   public PrivateKeyImpl(final byte[] key, final String algorithm) {
      super(key, algorithm);
   }

   /**
    * @param d
    * @param algorithm
    */
   public PrivateKeyImpl(final BigInteger d, final String algorithm) {
      super(d.toByteArray(), algorithm);
   }

	/**
	 * @return an encoded BigInteger representation of the {@code D} of this
	 *         {@code PrivateKey}
	 */
   public BigInteger getD() {
      return new BigInteger(getEncoded());
   }

   public String toString() {
      return getAlgorithm() + " : " + Arrays.toString(getEncoded());
   }
}
