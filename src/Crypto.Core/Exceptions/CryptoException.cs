using System.Text;

namespace Crypto.Core.Exceptions
{
    
    public class CryptoException : Exception
    {

        public string Algorithm { get; }
        
        public CryptoException(string? msg) : base(msg)
        {
        
        }

        public CryptoException(string? msg, Exception? innerException) : base(msg, innerException)
        {
            
        }

        public CryptoException(string? msg, string? algorithm) : base(msg, null)
        {
            algorithm = algorithm;
        }

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"CryptoException: {Message}");
            if (!string.IsNullOrEmpty(Algorithm))
                sb.AppendLine($"Algorithm: {Algorithm}");
            if (InnerException != null)
                sb.AppendLine($"Inner Exception: {InnerException}");
        
            return sb.ToString();
        }
    }
    
}
