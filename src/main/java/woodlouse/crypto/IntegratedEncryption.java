/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto;

import java.security.SecureRandom;

import woodlouse.crypto.ec.ECIESPrivateKey;
import woodlouse.crypto.ec.ECIESPublicKey;

/**
 * API for the integrated encryption scheme (IES) with ephemeral keys.
 */
public interface IntegratedEncryption {

   /**
    * Encrypt the byte array {@code plainBytes} using the key {@code publicKey}
    * .
    * 
    * @param plainBytes
    *           bytes to encrypt.
    * @param publicKey
    *           key to use for encryption.
    * @return encrypted bytes.
    */
   byte[] encryptEphemeral(byte[] plainBytes, ECIESPublicKey publicKey);

   /**
    * Decrypt the crypted byte array {@code cipherBytes} using the key
    * {@code privateKey}.
    * 
    * @param cipherBytes
    *           crypted byte array to decrypt.
    * @param privateKey
    *           key to use for decryption.
    * @return decrypted plain bytes.
    */
   byte[] decryptEphemeral(byte[] cipherBytes, ECIESPrivateKey privateKey);

   /**
    * Create a new KeyPair with a key length of {@code keySize} bits using the
    * supplied random generator {@code prng}. This method can be used to
    * generate deterministic keypairs.
    * 
    * @param keySize
    *           length of the generated keys measured in bits.
    * @param prng
    *           the SecureRandom to use in the key generation process.
    * @return the new {@link KeyPair}.
    */
   KeyPair createNewKeyPair(int keySize, SecureRandom prng);

   /**
    * Create a new randomly generated KeyPair with a default key length
    * (currently 320 bits).
    * 
    * @return new {@link KeyPair}.
    */
   KeyPair createNewKeyPair();
}
