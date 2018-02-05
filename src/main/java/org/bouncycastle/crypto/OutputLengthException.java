package org.bouncycastle.crypto;

public class OutputLengthException
    extends DataLengthException
{
	private static final long serialVersionUID = -2514856573478091437L;

	public OutputLengthException(String msg)
    {
        super(msg);
    }
}
