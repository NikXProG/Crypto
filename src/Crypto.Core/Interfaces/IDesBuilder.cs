
namespace Crypto.Core.Interfaces
{
    
    
    public interface IDesBuilder
    {
        
        IDesBuilder WithKey(byte[] key);
        
        IDesBuilder WithIV(byte[] iv);
        
        IDesBuilder WithPadding(PaddingMode padding);
        
        IDesBuilder WithCipherMode(CipherMode cipherMode);
        
        IDesBuilder UseGenerateIV();
    
        IDesBuilder UseGenerateKey();
        
        ISymmetrical Build();
    
    }
    
}
