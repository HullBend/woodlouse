//
//  Copyright (c) 2011, Neil Alexander T.
//  All rights reserved.
// 
//  Redistribution and use in source and binary forms, with
//  or without modification, are permitted provided that the following
//  conditions are met:
// 
//  - Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  - Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//

package woodlouse.crypto.jnacl.impl;

public final class Curve25519XSalsa20Poly1305 {
   private static final int crypto_secretbox_BEFORENMBYTES = 32;

   public static int crypto_box_getpublickey(byte[] pubKeyOut, byte[] privKey) {
      return Curve25519.crypto_scalarmult_base(pubKeyOut, privKey);
   }

   public static int crypto_box_afternm(byte[] cipherOut, byte[] messageIn, long msgLen, byte[] nonce, byte[] sharedSecret) {
      return XSalsa20Poly1305.crypto_secretbox(cipherOut, messageIn, msgLen, nonce, sharedSecret);
   }

   public static int crypto_box_beforenm(byte[] sharedSecretOut, byte[] pubKey, byte[] privKey) {
      byte[] raw = new byte[32];
      Curve25519.crypto_scalarmult(raw, privKey, pubKey);
      return HSalsa20.crypto_core(sharedSecretOut, null, raw, XSalsa20.sigma);
   }

   public static int crypto_box(byte[] cipherOut, byte[] messageIn, long msgLen, byte[] nonce, byte[] pubKey, byte[] privKey) {
      byte[] precomp = new byte[crypto_secretbox_BEFORENMBYTES];

      crypto_box_beforenm(precomp, pubKey, privKey);
      return crypto_box_afternm(cipherOut, messageIn, msgLen, nonce, precomp);
   }

   public static int crypto_box_open(byte[] messageOut, byte[] cipherIn, long cipherLen, byte[] nonce, byte[] pubKey, byte[] privKey) {
      byte[] precomp = new byte[crypto_secretbox_BEFORENMBYTES];

      crypto_box_beforenm(precomp, pubKey, privKey);
      return crypto_box_open_afternm(messageOut, cipherIn, cipherLen, nonce, precomp);
   }

   public static int crypto_box_open_afternm(byte[] messageOut, byte[] cipherIn, long cipherLen, byte[] nonce, byte[] sharedSecret) {
      return XSalsa20Poly1305.crypto_secretbox_open(messageOut, cipherIn, cipherLen, nonce, sharedSecret);
   }

   public static int crypto_box_afternm(byte[] cipherOut, byte[] messageIn, byte[] nonce, byte[] sharedSecret) {
      return crypto_box_afternm(cipherOut, messageIn, (long) messageIn.length, nonce, sharedSecret);
   }

   public static int crypto_box_open_afternm(byte[] messageOut, byte[] cipherIn, byte[] nonce, byte[] sharedSecret) {
      return crypto_box_open_afternm(messageOut, cipherIn, (long) cipherIn.length, nonce, sharedSecret);
   }

   public static int crypto_box(byte[] cipherOut, byte[] messageIn, byte[] nonce, byte[] pubKey, byte[] privKey) {
      return crypto_box(cipherOut, messageIn, (long) messageIn.length, nonce, pubKey, privKey);
   }

   public static int crypto_box_open(byte[] messageOut, byte[] cipherIn, byte[] nonce, byte[] pubKey, byte[] privKey) {
      return crypto_box_open(messageOut, cipherIn, (long) cipherIn.length, nonce, pubKey, privKey);
   }

   private Curve25519XSalsa20Poly1305() {
      throw new AssertionError();
   }
}
