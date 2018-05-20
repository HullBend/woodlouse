/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto;

import woodlouse.crypto.ec.ECIntegratedEncryptionProvider;

/**
 * Encryption based on the ECIES scheme as defined in IEEE Std 1363a.
 */
public abstract class ECIntegratedEncryption implements IntegratedEncryption {

   /**
    * Get an instance of {@link IntegratedEncryption}.
    * 
    * @return an IntegratedEncryption instance 
    */
   public static IntegratedEncryption create() {
      return ECIntegratedEncryptionProvider.create();
   }

   protected ECIntegratedEncryption() {
   }
}
