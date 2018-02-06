/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.ec;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;

import woodlouse.crypto.InvalidCipherBytesException;

/**
 * Encapsulates the whole setup for the Bouncy Castle IESEngine.
 */
final class ECIESEngine {

   private final IESEngine engine;
   private final int keySize;

   ECIESEngine(final int keySize) {
      this.keySize = keySize;
      // always 256-bit AES in CFB-8 mode
      final BufferedBlockCipher c = new BufferedBlockCipher(new CFBBlockCipher(new AESFastEngine(), 8));
      // setup the IESEngine
      engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(ECIESParams.getKDFDigest(this.keySize)), ECIESParams.getMACGen(this.keySize), c);
   }

   void initForEncryption(final AsymmetricKeyParameter senderPrivateKey, final AsymmetricKeyParameter receiverPublicKey) {
      if (senderPrivateKey == null) {
         throw new IllegalArgumentException("senderPrivateKey == null");
      }
      if (receiverPublicKey == null) {
         throw new IllegalArgumentException("receiverPublicKey == null");
      }
      engine.init(true, senderPrivateKey, receiverPublicKey, ECIESParams.getParams(keySize));
   }

   void initForEphemeralEncryption(final ECDomainParameters model, final AsymmetricKeyParameter receiverPublicKey) {
      if (model == null) {
         throw new IllegalArgumentException("model == null");
      }
      if (receiverPublicKey == null) {
         throw new IllegalArgumentException("receiverPublicKey == null");
      }
      // create the KeyPairGenerator for ephemeral keys
      ECKeyPairGenerator gen = new ECKeyPairGenerator();
      gen.init(new ECKeyGenerationParameters(model, new SecureRandom()));
      EphemeralKeyPairGenerator ephemeralKeyGen = new EphemeralKeyPairGenerator(gen, new KeyEncoder() {
         public byte[] getEncoded(AsymmetricKeyParameter publicKey) {
            // use compressed format for the public key
            return ((ECPublicKeyParameters) publicKey).getQ().getEncoded(true);
         }
      });
      engine.init(receiverPublicKey, ECIESParams.getParams(keySize), ephemeralKeyGen);
   }

   void initForDecryption(final AsymmetricKeyParameter receiverPrivateKey, final AsymmetricKeyParameter senderPublicKey) {
      if (receiverPrivateKey == null) {
         throw new IllegalArgumentException("receiverPrivateKey == null");
      }
      if (senderPublicKey == null) {
         throw new IllegalArgumentException("senderPublicKey == null");
      }
      engine.init(false, receiverPrivateKey, senderPublicKey, ECIESParams.getParams(keySize));
   }

   void initForEphemeralDecryption(final ECDomainParameters model, final AsymmetricKeyParameter receiverPrivateKey) {
      if (model == null) {
         throw new IllegalArgumentException("model == null");
      }
      if (receiverPrivateKey == null) {
         throw new IllegalArgumentException("receiverPrivateKey == null");
      }
      engine.init(receiverPrivateKey, ECIESParams.getParams(keySize), new ECIESPublicKeyParser(model));
   }

   byte[] encrypt(final byte[] in, final int inOffset, final int inLength) {
      try {
         return engine.processBlock(in, inOffset, inLength);
      } catch (Exception e) {
         throw new InvalidCipherBytesException(e);
      }
   }

   byte[] decrypt(final byte[] in, final int inOffset, final int inLength) {
      try {
         return engine.processBlock(in, inOffset, inLength);
      } catch (Exception e) {
         throw new InvalidCipherBytesException(e);
      }
   }
}
