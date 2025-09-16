using Crypto.Core;
using Crypto.Core.Interfaces;

namespace Crypto.Cipher.Symmetrical
{
    
    public class DesEngine : IBlockCipher
    {

        public DesEngine(
            CipherMode cipherMode,
            byte[] key,
            int blockSize,
            byte[]? iv,
            int feedbackSize,
            int paddingSize,
            bool encrypting)
        {
        
        }

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
