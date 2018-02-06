/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.keystorage;

import java.io.File;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import woodlouse.crypto.ec.ECIESPublicKey;
import woodlouse.crypto.ec.PublicKeyImpl;

/**
 * A key store for an ECC public key. You can have only one public key per
 * store.
 */
public final class ECCPublicKeyStore extends ECCKeyStore {

   private static final String ALIAS_PUB = "public";
   private static final String SENDER = "Sender (Encoder)";

   public ECCPublicKeyStore(final File f) {
      super(f);
   }

   public void store(final String comments) {
      secKeyStore.addTextAnnotation(ALIAS_PARTY, SENDER);
      super.store(comments);
   }

   public ECIESPublicKey getPublicKey() {
      SecretKey pubKey = secKeyStore.getEntryUnencrypted(ALIAS_PUB);
      if (pubKey == null) {
         throw new NoSuchKeyException("Public key not found");
      }
      return new PublicKeyImpl(pubKey.getEncoded(), pubKey.getAlgorithm());
   }

   public void setPublicKey(final ECIESPublicKey key) {
      if (key == null) {
         throw new IllegalArgumentException("key is null");
      }
      if (key instanceof SecretKey) {
         secKeyStore.setEntryUnencrypted(ALIAS_PUB, (SecretKey) key);
      } else {
         secKeyStore.setEntryUnencrypted(ALIAS_PUB, new SecretKeySpec(key.getEncoded(), key.getAlgorithm()));
      }
   }
}
