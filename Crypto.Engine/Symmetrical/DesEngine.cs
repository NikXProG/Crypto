using Crypto.Core;
using Crypto.Engine.Core.Interfaces;

namespace Crypto.Engine.Symmetrical
{
    
    public class DesEngine : ISymmetricalEngine
    {

        public DesEngine(
            CipherMode cipherMode,
            int blockSize,
            byte[] key,
            byte[]? iv,
            bool encrypting,
            int feedbackSize,
            int paddingSize)
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
