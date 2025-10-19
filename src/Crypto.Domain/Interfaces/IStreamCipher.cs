namespace Crypto.Domain.Interfaces;

public interface IStreamCipher : IEncryptParamSetup
{
    byte ReturnByte(byte input);
    
    void ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff);
    
    void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output);
    
    void Reset();
    
    
}