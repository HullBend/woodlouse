/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.keystorage;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import bouncycastle.crypto.util.Pack;
import woodlouse.crypto.util.B64EncDec;
import woodlouse.crypto.util.PBE;

/**
 * A crude key store for {@link SecretKey}s that are persisted in a simple XML
 * format.
 */
public class SecretKeyStore {

   private final HashMap<String, String> aliasKeyPairs = new HashMap<String, String>(4);

   public SecretKey getEntry(final String alias, final char[] password) {
      final String crypted = aliasKeyPairs.get(alias);
      if (crypted == null) {
         return null;
      }
      byte[] plainBytes = PBE.decrypt(B64EncDec.decode(crypted), password);
      return fromBytes(plainBytes);
   }

   public SecretKey getEntryUnencrypted(final String alias) {
      final String base64 = aliasKeyPairs.get(alias);
      if (base64 == null) {
         return null;
      }
      byte[] plainBytes = B64EncDec.decode(base64);
      return fromBytes(plainBytes);
   }

   private static SecretKey fromBytes(final byte[] plainBytes) {
      SecretKey key = null;
      try {
         int algLength = Pack.littleEndianToInt(plainBytes, 0);
         byte[] alg = new byte[algLength];
         System.arraycopy(plainBytes, 4, alg, 0, algLength);
         String algorithm = new String(alg, "UTF-8");

         byte[] encoded = new byte[plainBytes.length - 4 - alg.length];
         System.arraycopy(plainBytes, 4 + algLength, encoded, 0, encoded.length);

         key = new SecretKeySpec(encoded, algorithm);
      } catch (UnsupportedEncodingException wontHappen) {
      }
      return key;
   }

   public void setEntry(final String alias, final SecretKey key, final char[] password) {

      byte[] bytes = toBytes(key);
      String crypted = B64EncDec.encodeToString(PBE.encrypt(bytes, password));
      aliasKeyPairs.put(alias, crypted);
   }

   public void setEntryUnencrypted(final String alias, final SecretKey key) {

      byte[] bytes = toBytes(key);
      String base64 = B64EncDec.encodeToString(bytes);
      aliasKeyPairs.put(alias, base64);
   }

   private static byte[] toBytes(final SecretKey key) {
      byte[] bytes = null;
      try {
         String alg = key.getAlgorithm();

         byte[] algorithm = alg.getBytes("UTF-8");
         byte[] encoded = key.getEncoded();
         bytes = new byte[4 + algorithm.length + encoded.length];

         Pack.intToLittleEndian(algorithm.length, bytes, 0);
         System.arraycopy(algorithm, 0, bytes, 4, algorithm.length);
         System.arraycopy(encoded, 0, bytes, 4 + algorithm.length, encoded.length);
      } catch (UnsupportedEncodingException wontHappen) {
      }
      return bytes;
   }

   public void addTextAnnotation(final String alias, final String value) {
      aliasKeyPairs.put(alias, value);
   }

   public SecretKeyStore load(final File f) throws IOException {
      aliasKeyPairs.clear();
      final XmlStore backingStore = new XmlStore(f);
      loadEntries(backingStore);
      return this;
   }

   public void store(final File f) {
      final XmlStore store = new XmlStore();
      for (Map.Entry<String, String> entry : aliasKeyPairs.entrySet()) {
         store.put(entry.getKey(), entry.getValue());
      }
      store.persistToDisk(f);
   }

   private void loadEntries(final XmlStore store) {
      Set<String> aliases = store.names();
      for (final String alias : aliases) {
         String crypted = store.get(alias);
         aliasKeyPairs.put(alias, crypted);
      }
   }

   public static SecretKeyStore create() {
      return new SecretKeyStore();
   }

   private SecretKeyStore() {
      // no-op
   }
}
