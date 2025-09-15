namespace Crypto.Engine.Core.Interfaces
{
    
    public interface ISymmetricalEngine
    {
    
        public int ProcessBlock(
            ReadOnlySpan<byte> input,
            Span<byte> output);

        public int ProcessBlockFinal(
            ReadOnlySpan<byte> input,
            Span<byte> output);
    
    }
}
