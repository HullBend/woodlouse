/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A provider-independent implementation of {@link ECIESPublicKey} that is also
 * a {@link SecretKey}.
 */
public class PublicKeyImpl extends SecretKeySpec implements ECIESPublicKey {

   private static final long serialVersionUID = -6511094886190405986L;

   /**
    * @param key
    * @param offset
    * @param len
    * @param algorithm
    */
   public PublicKeyImpl(final byte[] key, final int offset, final int len, final String algorithm) {
      super(key, offset, len, algorithm);
   }

   /**
    * @param key
    * @param algorithm
    */
   public PublicKeyImpl(final byte[] key, final String algorithm) {
      super(key, algorithm);
   }

   /**
    * @return
    */
   public InputStream getInputStream() {
      return new ByteArrayInputStream(getEncoded());
   }

   public String toString() {
      return getAlgorithm() + " : " + Arrays.toString(getEncoded());
   }
}
