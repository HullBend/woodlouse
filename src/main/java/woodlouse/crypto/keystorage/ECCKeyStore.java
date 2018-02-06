/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.keystorage;

import java.io.File;
import java.io.IOException;

/**
 * Base class for ECC key stores.
 */
public abstract class ECCKeyStore {

   protected static final String ALIAS_PARTY = "participant role";
   protected static final String ALIAS_NOTE = "comments";

   private final File file;
   protected final SecretKeyStore secKeyStore;

   public ECCKeyStore(final File f) {
      file = f;
      secKeyStore = SecretKeyStore.create();
   }

   public final void load() throws IOException {
      secKeyStore.load(file);
   }

   public final void store() {
      store(null);
   }

   public void store(final String comments) {
      if (comments != null && !"".equals(comments.trim())) {
         secKeyStore.addTextAnnotation(ALIAS_NOTE, comments.trim());
      } else {
         secKeyStore.addTextAnnotation(ALIAS_NOTE, "");
      }
      secKeyStore.store(file);
   }
}
