/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.util;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.ISAACEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A simple byte array obfuscation facility. An obfuscated byte array grows by 6
 * bytes.
 */
public final class Obfuscator {

   private static final int SALT_LEN = 6;
   private static final SecureRandom rng = new SecureRandom();

   private static KeyParameter nextSalt() {
      final byte[] salt = new byte[SALT_LEN];
      rng.nextBytes(salt);
      return new KeyParameter(salt);
   }

   public static byte[] obfuscate(final byte[] plainBytes) {
      final byte[] obfuscated = new byte[plainBytes.length];
      final KeyParameter salt = nextSalt();
      final ISAACEngine obfuscator = new ISAACEngine();
      obfuscator.init(true, salt);
      obfuscator.processBytes(plainBytes, 0, plainBytes.length, obfuscated, 0);
      return ByteArrays.joinedArray(salt.getKey(), obfuscated);
   }

   public static byte[] deobfuscate(final byte[] obfuscatedBytes) {
      final byte[] deobfuscated = new byte[obfuscatedBytes.length - SALT_LEN];
      final byte[] salt = ByteArrays.subArray(obfuscatedBytes, 0, SALT_LEN);
      final ISAACEngine deobfuscator = new ISAACEngine();
      deobfuscator.init(false, new KeyParameter(salt));
      deobfuscator.processBytes(obfuscatedBytes, SALT_LEN, obfuscatedBytes.length - SALT_LEN, deobfuscated, 0);
      return deobfuscated;
   }

   private Obfuscator() {
      throw new AssertionError();
   }
}
