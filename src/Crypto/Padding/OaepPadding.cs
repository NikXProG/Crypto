using Crypto.Domain.Interfaces;

namespace Crypto.Padding;

public class OaepPadding : IAsymmetricalCipher
{
    public int InputBlockSize { get; }
    
    public int OutputBlockSize { get; }

    public OaepPadding(IAsymmetricalCipher engine)
    {
        
    }
    
    public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
    {
        throw new NotImplementedException();
    }

    public void Setup(bool encrypting, ICryptoParams cryptoParams)
    {
        throw new NotImplementedException();
    }
}