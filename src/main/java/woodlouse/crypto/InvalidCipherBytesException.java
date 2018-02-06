/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto;

public class InvalidCipherBytesException extends RuntimeException {

   private static final long serialVersionUID = 2928270168811899364L;

   public InvalidCipherBytesException() {
   }

   /**
    * @param message
    * @param cause
    */
   public InvalidCipherBytesException(final String message, final Throwable cause) {
      super(message, cause);
   }

   /**
    * @param message
    */
   public InvalidCipherBytesException(final String message) {
      super(message);
   }

   /**
    * @param cause
    */
   public InvalidCipherBytesException(final Throwable cause) {
      super(cause);
   }
}
