using Crypto.Engine.Core.Interfaces;

namespace Crypto.Engine.Symmetrical
{
    
    public class AesEngine : ISymmetricalEngine
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
