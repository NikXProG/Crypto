
namespace Crypto.Domain.Interfaces
{
    
    public interface IBlockCipher : IEncryptParamSetup
    {
        public int BlockSizeInBytes { get; }
    
        int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff);
    
        int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output);
        
    }
}
