/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto;

import java.io.File;
import java.io.IOException;

import woodlouse.crypto.ec.ECIESPrivateKey;
import woodlouse.crypto.ec.ECIESPublicKey;
import woodlouse.crypto.keystorage.ECCPrivateKeyStore;
import woodlouse.crypto.keystorage.ECCPublicKeyStore;
import woodlouse.crypto.util.PBKDF;

/**
 * A simple reader for the keystores generated by {@link KeyStoreGenerator}.
 */
public final class KeyStoreLoader {

   /**
    * Load a private key from a private keystore file designated by the
    * {@code privateKeyStore} argument that is protected by a fixed default
    * password.
    * 
    * @param privateKeyStore
    * @return
    * @throws IOException
    */
   public static ECIESPrivateKey loadPrivateKeyWithDefaults(final File privateKeyStore) throws IOException {

      return loadPrivateKey(privateKeyStore, null);
   }

   /**
    * Load a private key from a private keystore file designated by the
    * {@code privateKeyStore} argument that is protected by the password passed
    * in the {@code privateKeyStorePassword} argument.
    * 
    * @param privateKeyStore
    * @param privateKeyStorePassword
    * @return
    * @throws IOException
    */
   public static ECIESPrivateKey loadPrivateKey(final File privateKeyStore, final String privateKeyStorePassword) throws IOException {

      char[] decryptKSPwd = PBKDF.generatePasswordChars(privateKeyStorePassword, KeyStoreGenerator.PWD_LENGTH);
      ECCPrivateKeyStore privKeyKS = new ECCPrivateKeyStore(privateKeyStore);
      privKeyKS.load();
      return privKeyKS.getPrivateKey(decryptKSPwd);
   }

   /**
    * Load a public key from a public keystore file designated by the
    * {@code publicKeyStore} argument.
    * 
    * @param publicKeyStore
    * @return
    * @throws IOException
    */
   public static ECIESPublicKey loadPublicKey(final File publicKeyStore) throws IOException {

      ECCPublicKeyStore pubKeyKS = new ECCPublicKeyStore(publicKeyStore);
      pubKeyKS.load();
      return pubKeyKS.getPublicKey();
   }

   private KeyStoreLoader() {
      throw new AssertionError();
   }
}
