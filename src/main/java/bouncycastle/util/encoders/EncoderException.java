package bouncycastle.util.encoders;

public class EncoderException
    extends IllegalStateException
{
	private static final long serialVersionUID = -201942987450889072L;

	private Throwable cause;

    EncoderException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
