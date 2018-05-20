/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.UUID;

import woodlouse.crypto.keystorage.ECCPrivateKeyStore;
import woodlouse.crypto.keystorage.ECCPublicKeyStore;
import woodlouse.crypto.util.DeterministicSecureRandom;
import woodlouse.crypto.util.PBKDF;

/**
 * A utility class for the creation of a 320 bit ECC encryption KeyStore pair
 * (one KeyStore is used for encryption, the other one for the corresponding
 * decryption).
 * <p/>
 * Which one is which can be seen from the name of the generated KeyStore file
 * and also from its contents under the entry with the name "participant role".
 * It is possible to specify an optional comment that will be embedded in both
 * KeyStore files to further clarify their intended usage.
 * <p/>
 * You can change the names of the generated files or edit its contents as long
 * as you stick to the predefined "name"/"value" XML format. But <b>never
 * ever</b> change the "public"/"private" entries (neither their names nor their
 * content)!
 * <p/>
 * If you want the generated keys to be <b>deterministic</b> (i.e., you want to
 * be able to generate the same keys over and over you must use the
 * {@link #create(String, File, String, String, String)} method and supply a
 * fixed password for the first argument.
 * <p/>
 * Btw, never forget the password(s) you have used, otherwise you are lost! For
 * checking purposes, a third file "passwords.txt" containing the password(s)
 * you supplied is written to the same directory where the KeyStores are
 * created.
 */
public final class KeyStoreGenerator {

   public static final String DECODER_KEYSTORE_NAME = "decoder_keystore.xml";
   public static final String ENCODER_KEYSTORE_NAME = "encoder_keystore.xml";

   // make this accessible to the KeyStoreLoader
   /* package */static final int PWD_LENGTH = 50;

   // 320-bit "brainpoolP320r1" standard curve
   private static final int DEFAULT_KEY_LEN = 320;

   /**
    * Create a new deterministically generated keystore pair where the private
    * key is protected by by a fixed default password and the concrete key pair
    * is determined by the value of the {@code ksGenerationSeed} argument.
    *
    * @param ksGenerationSeed
    *           the seed to use for deterministic (i.e. repeatable) KeyStore
    *           generation (must neither be null nor empty!).
    * @param targetDir
    *           a directory where the KeyStore files should be saved (must be a
    *           directory!).
    * @param ksFilePrefix
    *           optional prefix for the KeyStore file names (may be null or
    *           empty).
    * @param comments
    *           optional comment to embed in the KeyStore (may be null or
    *           empty).
    * @throws IllegalArgumentException in case of wrong arguments.
    * @throws IOException
    *            in case of an IO error.
    */
   public static void createWithDefaults(final String ksGenerationSeed, final File targetDir, final String ksFilePrefix, final String comments)
         throws IOException {

      checkIsDirectory(targetDir);
      checkKeyStoreSeed(ksGenerationSeed);

      SecureRandom rng = new DeterministicSecureRandom(ksGenerationSeed);
      generate(rng, targetDir, ksFilePrefix, null, comments, ksGenerationSeed);
   }

   /**
    * Create a new deterministically generated keystore pair where the private
    * key is protected by the password passed in as {@code decryptKSPassword}
    * argument and the concrete key pair is determined by the value of the
    * {@code ksGenerationSeed} argument.
    *
    * @param ksGenerationSeed
    *           the seed to use for deterministic (i.e. repeatable) KeyStore
    *           generation (must neither be null nor empty!).
    * @param targetDir
    *           a directory where the KeyStore files should be saved (must be a
    *           directory!).
    * @param ksFilePrefix
    *           optional prefix for the KeyStore file names (may be null or
    *           empty).
    * @param decryptKSPassword
    *           the password for the decrypting KeyStore (must neither be null
    *           nor empty!).
    * @param comments
    *           optional comment to embed in the KeyStore (may be null or
    *           empty).
    * @throws IllegalArgumentException in case of wrong arguments.
    * @throws IOException
    *            in case of an IO error.
    */
   public static void create(final String ksGenerationSeed, final File targetDir, final String ksFilePrefix, final String decryptKSPassword,
         final String comments) throws IOException {

      checkPasswordNotEmpty(decryptKSPassword);
      checkIsDirectory(targetDir);
      checkKeyStoreSeed(ksGenerationSeed);

      SecureRandom rng = new DeterministicSecureRandom(ksGenerationSeed);
      generate(rng, targetDir, ksFilePrefix, decryptKSPassword, comments, ksGenerationSeed);
   }

   /**
    * Create a new randomly chosen keystore pair where the private key is
    * protected by a fixed default password.
    *
    * @param targetDir
    *           a directory where the KeyStore files should be saved (must be a
    *           directory!).
    * @param ksFilePrefix
    *           optional prefix for the KeyStore file names (may be null or
    *           empty).
    * @param comments
    *           optional comment to embed in the KeyStore (may be null or
    *           empty).
    * @throws IllegalArgumentException in case of wrong arguments.
    * @throws IOException
    *            in case of an IO error.
    */
   public static void createWithDefaults(final File targetDir, final String ksFilePrefix, final String comments) throws IOException {

      checkIsDirectory(targetDir);

      generate(new SecureRandom(), targetDir, ksFilePrefix, null, comments, null);
   }

   /**
    * Create a new randomly chosen keystore pair where the private key is
    * protected by the password passed in as {@code decryptKSPassword} argument.
    *
    * @param targetDir
    *           a directory where the KeyStore files should be saved (must be a
    *           directory!).
    * @param ksFilePrefix
    *           optional prefix for the KeyStore file names (may be null or
    *           empty).
    * @param decryptKSPassword
    *           the password for the decrypting KeyStore (must neither be null
    *           nor empty!).
    * @param comments
    *           optional comment to embed in the KeyStore (may be null or
    *           empty).
    * @throws IllegalArgumentException in case of wrong arguments.
    * @throws IOException
    *            in case of an IO error.
    */
   public static void create(final File targetDir, final String ksFilePrefix, final String decryptKSPassword, final String comments) throws IOException {

      checkPasswordNotEmpty(decryptKSPassword);
      checkIsDirectory(targetDir);

      generate(new SecureRandom(), targetDir, ksFilePrefix, decryptKSPassword, comments, null);
   }

   private static void generate(final SecureRandom rng, final File targetDir, final String ksFilePrefix, final String decryptKSPassword, final String comments,
         final String seed) throws IOException {

      String commonFilenamePrefix = "";
      if (ksFilePrefix != null && !"".equals(ksFilePrefix.trim())) {
         commonFilenamePrefix = ksFilePrefix.trim() + "_";
      }

      File encryptStore = new File(targetDir, commonFilenamePrefix + ENCODER_KEYSTORE_NAME);
      File decryptStore = new File(targetDir, commonFilenamePrefix + DECODER_KEYSTORE_NAME);
      File passwords = new File(targetDir, commonFilenamePrefix + "passwords.txt");

      // check for existence and rename for backup if it's already there
      UUID uuid = UUID.randomUUID();
      attemptBackup(encryptStore, uuid);
      attemptBackup(decryptStore, uuid);
      attemptBackup(passwords, uuid);

      IntegratedEncryption ecIES = ECIntegratedEncryption.create();
      KeyPair keyPair = ecIES.createNewKeyPair(DEFAULT_KEY_LEN, rng);

      char[] decryptKSPwd = PBKDF.generatePasswordChars(decryptKSPassword, PWD_LENGTH);

      ECCPublicKeyStore encryptKS = new ECCPublicKeyStore(encryptStore);
      ECCPrivateKeyStore decryptKS = new ECCPrivateKeyStore(decryptStore);

      encryptKS.setPublicKey(keyPair.getReceiverPublic());
      decryptKS.setPrivateKey(keyPair.getReceiverPrivate(), decryptKSPwd);

      encryptKS.store(comments);
      decryptKS.store(comments);
      writePasswordsFile(passwords, decryptKSPassword, seed);
   }

   private static void writePasswordsFile(final File passwords, final String decryptKSPassword, final String seed) throws IOException {

      String decKSPwd = "Decryption Keystore password: [" + decryptKSPassword + "]";
      String seedPwd = (seed == null) ? "No Seed." : ("Seed password: [" + seed + "]");

      PrintWriter pw = null;
      try {
         pw = new PrintWriter(passwords);
         pw.println(decKSPwd);
         pw.println(seedPwd);
      } finally {
         if (pw != null) {
            pw.flush();
            pw.close();
         }
      }
   }

   private static void checkPasswordNotEmpty(final String decryptKSPassword) {
      if (decryptKSPassword == null || "".equals(decryptKSPassword)) {
         throw new IllegalArgumentException("Decryption Keystore password is null or empty");
      }
   }

   private static void checkIsDirectory(final File targetDir) throws IOException {
      if (targetDir == null) {
         throw new IllegalArgumentException("Target directory is null");
      }
      if (!targetDir.isDirectory()) {
         throw new IllegalArgumentException(targetDir.getCanonicalPath() + " is not a directory");
      }
   }

   private static void checkKeyStoreSeed(final String ksGenerationSeed) {
      if (ksGenerationSeed == null || "".equals(ksGenerationSeed)) {
         throw new IllegalArgumentException("Seed for Keystore generation is null or empty");
      }
   }

   /*
    * Check for existence and try to rename for backup purposes.
    */
   private static void attemptBackup(final File store, final UUID uuid) throws IOException {
      if (store.exists()) {
         if (!store.renameTo(new File(store.getCanonicalPath() + "." + uuid.toString()))) {
            throw new IOException("Could not rename existing Keystore " + store.getCanonicalPath());
         }
      }
   }

   private KeyStoreGenerator() {
      throw new AssertionError();
   }
}
