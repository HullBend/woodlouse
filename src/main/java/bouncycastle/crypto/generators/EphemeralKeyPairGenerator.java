package bouncycastle.crypto.generators;

import bouncycastle.crypto.AsymmetricCipherKeyPair;
import bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import bouncycastle.crypto.EphemeralKeyPair;
import bouncycastle.crypto.KeyEncoder;

public class EphemeralKeyPairGenerator
{
    private AsymmetricCipherKeyPairGenerator gen;
    private KeyEncoder keyEncoder;

    public EphemeralKeyPairGenerator(AsymmetricCipherKeyPairGenerator gen, KeyEncoder keyEncoder)
    {
        this.gen = gen;
        this.keyEncoder = keyEncoder;
    }

    public EphemeralKeyPair generate()
    {
        AsymmetricCipherKeyPair eph = gen.generateKeyPair();

        // Encode the ephemeral public key
        return new EphemeralKeyPair(eph, keyEncoder);
    }
}
