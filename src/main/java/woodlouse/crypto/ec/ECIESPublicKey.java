/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.io.InputStream;
import java.security.Key;

/**
 * A public key for ECC encryption.
 */
// Note: do NOT extend from java.security.PublicKey (this won't work with the
// jceks KeyStores)
public interface ECIESPublicKey extends Key {

   InputStream getInputStream();
}
