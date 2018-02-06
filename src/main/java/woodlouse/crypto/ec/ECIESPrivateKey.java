/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.math.BigInteger;
import java.security.Key;

/**
 * A private key for ECC encryption.
 */
// Note: do NOT extend from java.security.PrivateKey (this won't work with the
// jceks KeyStores)
public interface ECIESPrivateKey extends Key {

   BigInteger getD();
}
