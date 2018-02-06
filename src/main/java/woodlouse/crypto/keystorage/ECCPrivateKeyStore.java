/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.keystorage;

import java.io.File;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import woodlouse.crypto.ec.ECIESPrivateKey;
import woodlouse.crypto.ec.PrivateKeyImpl;

/**
 * A key store for an ECC private key. You can have only one private key per
 * store.
 */
public final class ECCPrivateKeyStore extends ECCKeyStore {

   private static final String ALIAS_PRIV = "private";
   private static final String RECEIVER = "Receiver (Decoder)";

   public ECCPrivateKeyStore(final File f) {
      super(f);
   }

   public void store(final String comments) {
      secKeyStore.addTextAnnotation(ALIAS_PARTY, RECEIVER);
      super.store(comments);
   }

   public ECIESPrivateKey getPrivateKey(final char[] password) {
      SecretKey privKey = secKeyStore.getEntry(ALIAS_PRIV, password);
      if (privKey == null) {
         throw new NoSuchKeyException("Private key not found");
      }
      return new PrivateKeyImpl(privKey.getEncoded(), privKey.getAlgorithm());
   }

   public void setPrivateKey(final ECIESPrivateKey key, final char[] password) {
      if (key == null || password == null) {
         throw new IllegalArgumentException("key and/or password is null");
      }
      if (key instanceof SecretKey) {
         secKeyStore.setEntry(ALIAS_PRIV, (SecretKey) key, password);
      } else {
         secKeyStore.setEntry(ALIAS_PRIV, new SecretKeySpec(key.getEncoded(), key.getAlgorithm()), password);
      }
   }
}
