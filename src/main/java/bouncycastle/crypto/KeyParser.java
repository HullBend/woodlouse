package bouncycastle.crypto;

import java.io.IOException;
import java.io.InputStream;

import bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface KeyParser
{
    AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException;
}
