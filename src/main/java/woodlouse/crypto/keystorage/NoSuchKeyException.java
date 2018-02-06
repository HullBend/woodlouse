/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.keystorage;

public class NoSuchKeyException extends RuntimeException {

   private static final long serialVersionUID = 6018992463831213474L;

   public NoSuchKeyException() {
   }

   public NoSuchKeyException(final String message) {
      super(message);
   }

   public NoSuchKeyException(final Throwable cause) {
      super(cause);
   }

   public NoSuchKeyException(final String message, final Throwable cause) {
      super(message, cause);
   }
}
