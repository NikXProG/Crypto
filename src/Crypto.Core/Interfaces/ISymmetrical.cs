namespace Crypto.Core.Interfaces
{
    
    public interface ISymmetrical : ICryptable
    {
    
        string AlgorithmName { get; }
    
        IEncryptor GetEncryptor();
        
        IDecryptor GetDecryptor();
        
        
    }
    
}



