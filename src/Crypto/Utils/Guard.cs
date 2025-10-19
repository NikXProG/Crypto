
using Crypto.Domain.Exceptions;

namespace Crypto.Utils;

public static class Guard   
{
    
    internal static void ValidLength(bool condition, string message)
    {
        if (condition)
        {
            ThrowParameterLengthException(message);
        }
          
    }

    internal static void ValidLength(
        byte[] buf, int off, int len, string message)
    {
        if (off > (buf.Length - len))
        {
            ThrowParameterLengthException(message);
        }
    }
    
    internal static void ValidLength<T>(ReadOnlySpan<T> input, int len, string message)
    {
        if (input.Length < len)
        {
            ThrowParameterLengthException(message);
        }
    }
    
    internal static void ValidLength<T>(Span<T> output, int len, string message)
    {
        if (output.Length < len)
        {
            ThrowParameterLengthException(message);
        }
       
    }
    
    private static void ThrowParameterKeyException(string message) => throw new ParameterKeyException(message);
    
    private static void ThrowParameterLengthException(string message) => throw new ParameterLengthException(message);
}