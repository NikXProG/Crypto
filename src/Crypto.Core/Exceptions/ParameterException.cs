namespace Crypto.Core.Exceptions
{
    public class ParameterException : CryptoException
    {
        public string ParameterName { get; }

        public ParameterException(string message, string parameterName) 
            : base(message)
        {
            ParameterName = parameterName;
        }

      
    }
}
