using Crypto.Core;
using Crypto.Core.Interfaces;

namespace Crypto.Symmetrical;

public class PaddedBlockDecryptor : IDecryptor
{

    public PaddedBlockDecryptor(PaddingMode paddingMode, IBlockCipher engine)
    {
        
    }
    
    public bool CanReuseTransform { get; }

    public bool CanTransformMultipleBlocks { get; }

    public int DecryptBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        throw new NotImplementedException();
    }

    public byte[] DecryptFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        throw new NotImplementedException();
    }

    public int InputBlockSize { get; }

    public int OutputBlockSize { get; }
    
    
}