using Crypto.Core.Interfaces;

namespace Crypto.Cipher.Symmetrical
{
    
    public class AesEngine : IBlockCipher
    {
        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            throw new NotImplementedException();
        }

        public int ProcessBlockFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            throw new NotImplementedException();
        }
    }
}
