namespace Crypto.Domain.Interfaces;

public interface IAsymmetricalCipher : IEncryptParamSetup
{
    
    int InputBlockSize { get; }
    
    int OutputBlockSize { get; }
    
    byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen);
    
}