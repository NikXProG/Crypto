namespace Crypto.Domain.Interfaces;

public interface IBlockCipherMode : IBlockCipher
{
    
    IBlockCipher CipherEngine { get; }
    
    bool IsPartialBlockOkay { get; }
    
    void Reset();
    
}