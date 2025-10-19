namespace Crypto.Domain.Exceptions
{
    
    
    public class InitializationException : CryptoException
    {
        public InitializationException(string message) 
            : base(message) { }
    }

    
}