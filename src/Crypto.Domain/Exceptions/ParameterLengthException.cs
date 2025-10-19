namespace Crypto.Domain.Exceptions;

public class ParameterLengthException : ParameterException
{
    public ParameterLengthException(string message) : base(message)
    {
    }
}