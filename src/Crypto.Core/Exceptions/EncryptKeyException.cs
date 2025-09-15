namespace Crypto.Core.Exceptions;

public class EncryptKeyException : ParameterException
{
    
    public EncryptKeyException(string message, string key) : base(message, key)
    {
        
    }
    
}