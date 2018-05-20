/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.util;

import java.security.SecureRandom;

import bouncycastle.crypto.prng.FixedSecureRandom;

/**
 * A deterministic {@link SecureRandom} implementation that must be seeded with
 * a string seed.
 */
public class DeterministicSecureRandom extends FixedSecureRandom {

   private static final long serialVersionUID = 6514676172393135833L;

   private static final int ITERS = 1536;

   /**
    * Produces up to 4224 bytes (= 64 x 528 bit) from the seed.
    * 
    * @param seed
    *           the seed to use.
    */
   public DeterministicSecureRandom(final String seed) {
      super(createSeedBytes(seed, 4224));
   }

   /**
    * Produces {@code seedBytesNeeded} bytes from the seed.
    * 
    * @param seed
    *           the seed to use.
    * @param seedBytesNeeded
    *           the number of bytes needed.
    */
   public DeterministicSecureRandom(final String seed, final int seedBytesNeeded) {
      super(createSeedBytes(seed, seedBytesNeeded));
   }

   private static byte[] createSeedBytes(final String seed, final int seedBytesNeeded) {
      return PBKDF.generateKeyBytes(seed, ITERS, seedBytesNeeded);
   }
}
