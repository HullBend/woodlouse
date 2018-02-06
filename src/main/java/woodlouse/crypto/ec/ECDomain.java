/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
import org.bouncycastle.math.ec.ECPoint;

import woodlouse.crypto.InvalidCipherBytesException;
import woodlouse.crypto.KeyPair;

/**
 * Represents an ECC domain and the essential operations needed to make use of
 * it.
 */
abstract class ECDomain {

   // 320-bit "brainpoolP320r1" standard curve
   private static final int DEFAULT_KEY_LEN = 320;

   // 320-bit "brainpoolP320r1" standard curve
   protected static final String DEFAULT_CURVE = "1.3.36.3.3.2.8.1.1.9 (320 bit)";

   private final ECDomainParameters model;

   protected ECDomain() {
      model = initializeDomain();
   }

   @SuppressWarnings("unused")
   private static AsymmetricCipherKeyPair getCipherKeyPair(final String oid, final BigInteger d) {
      if (oid == null) {
         throw new IllegalArgumentException("oid == null");
      }
      if (d == null) {
         throw new IllegalArgumentException("d == null");
      }
      final ECDomain domain = getModel(oid);
      return new AsymmetricCipherKeyPair(domain.computePublicKeyParams(d), domain.getPrivateKeyParams(d));
   }

   private static ECDomain getModel(final String oid) {
      if (oid == null) {
         throw new IllegalArgumentException("oid == null");
      }
      final ECDomain domain = NamedCurves.getByOid(oid);
      if (domain == null) {
         throw new IllegalArgumentException("unknown OID : " + oid);
      }
      return domain;
   }

   private static ECDomain getModel(final int keySize) {
      final ECDomain domain = NamedCurves.getByKeySize(keySize);
      if (domain == null) {
         throw new IllegalArgumentException("unsupported key size : " + keySize);
      }
      return domain;
   }

   private ECPrivateKeyParameters getPrivateKeyParams(final BigInteger d) {
      if (d == null) {
         throw new IllegalArgumentException("d == null");
      }
      return new ECPrivateKeyParameters(d, model);
   }

   private ECPublicKeyParameters computePublicKeyParams(final BigInteger d) {
      if (d == null) {
         throw new IllegalArgumentException("d == null");
      }
      final ECPoint Q = model.getG().multiply(d);
      return new ECPublicKeyParameters(Q, model);
   }

   protected abstract ECDomainParameters initializeDomain();

   protected abstract String getOid();

   protected abstract int getKeyLength();

   static byte[] encryptEphemeral(final byte[] plainBytes, final ECIESPublicKey receiverPublicKey) {
      ECDomain domain = getModel(receiverPublicKey.getAlgorithm());
      ECIESEngine encryptor = new ECIESEngine(domain.getKeyLength());
      encryptor.initForEphemeralEncryption(domain.model, getReceiverPubKey(receiverPublicKey, domain.model));
      return encryptor.encrypt(plainBytes, 0, plainBytes.length);
   }

   static byte[] decryptEphemeral(final byte[] cipherBytes, final ECIESPrivateKey receiverPrivateKey) {
      ECDomain domain = getModel(receiverPrivateKey.getAlgorithm());
      ECIESEngine decryptor = new ECIESEngine(domain.getKeyLength());
      decryptor.initForEphemeralDecryption(domain.model, getReceiverPrivKey(receiverPrivateKey, domain));
      return decryptor.decrypt(cipherBytes, 0, cipherBytes.length);
   }

   static KeyPair createNewKeyPair(final int keySize, final SecureRandom prng) {
      ECDomain domain = getModel(keySize);
      KeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domain.model, prng);
      ECKeyPairGenerator keyPairGen = new ECKeyPairGenerator();

      keyPairGen.init(keyGenParams);
      AsymmetricCipherKeyPair receiver = keyPairGen.generateKeyPair();

      BigInteger privReceiverD = ((ECPrivateKeyParameters) receiver.getPrivate()).getD();
      byte[] pubReceiverBytes = ((ECPublicKeyParameters) receiver.getPublic()).getQ().getEncoded(false);

      KeyPair keyPair = new KeyPair(new PrivateKeyImpl(privReceiverD, domain.getOid()), new PublicKeyImpl(pubReceiverBytes, domain.getOid()));

      return keyPair;
   }

   static KeyPair createNewKeyPair() {
      return createNewKeyPair(DEFAULT_KEY_LEN, new SecureRandom());
   }

   private static AsymmetricKeyParameter getReceiverPubKey(final ECIESPublicKey publicKey, final ECDomainParameters model) {
      try {
         ECIESPublicKeyParser recvPubKeyParser = new ECIESPublicKeyParser(model);
         return recvPubKeyParser.readKey(publicKey.getInputStream());
      } catch (Exception e) {
         throw new InvalidCipherBytesException(e);
      }
   }

   private static AsymmetricKeyParameter getReceiverPrivKey(final ECIESPrivateKey privateKey, final ECDomain domain) {
      return domain.getPrivateKeyParams(privateKey.getD());
   }
}
