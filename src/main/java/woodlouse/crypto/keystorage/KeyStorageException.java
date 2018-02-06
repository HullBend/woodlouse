/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.keystorage;

public class KeyStorageException extends RuntimeException {

   private static final long serialVersionUID = 3233285758138691191L;

   public KeyStorageException() {
   }

   public KeyStorageException(final String message) {
      super(message);
   }

   public KeyStorageException(final Throwable cause) {
      super(cause);
   }

   public KeyStorageException(final String message, final Throwable cause) {
      super(message, cause);
   }
}
