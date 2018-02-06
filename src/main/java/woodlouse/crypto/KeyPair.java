/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto;

import java.io.Serializable;

import woodlouse.crypto.ec.ECIESPrivateKey;
import woodlouse.crypto.ec.ECIESPublicKey;

/**
 * A composite pair of a {@link ECIESPrivateKey} and a {@link ECIESPublicKey}
 * respectively.
 */
public class KeyPair implements Serializable {

   private static final long serialVersionUID = -3302875043843414231L;

   private final ECIESPrivateKey receiverPrivate;
   private final ECIESPublicKey receiverPublic;

   public KeyPair(final ECIESPrivateKey receiverPrivate, final ECIESPublicKey receiverPublic) {
      this.receiverPrivate = receiverPrivate;
      this.receiverPublic = receiverPublic;
      if (!receiverPrivate.getAlgorithm().equals(receiverPublic.getAlgorithm())) {
         throw new IllegalArgumentException(receiverPrivate.getAlgorithm() + " != " + receiverPublic.getAlgorithm());
      }
   }

   /**
    * @return the receiverPrivate
    */
   public ECIESPrivateKey getReceiverPrivate() {
      return receiverPrivate;
   }

   /**
    * @return the receiverPublic
    */
   public ECIESPublicKey getReceiverPublic() {
      return receiverPublic;
   }
}
