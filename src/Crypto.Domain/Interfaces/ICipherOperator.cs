namespace Crypto.Domain.Interfaces;

public interface ICipherOperator : IEncryptParamSetup
{
    int BlockSize { get; }
    
    // Processing one byte 
    
    byte[] ProcessByte(byte input);

    int ProcessByte(byte input, byte[] output, int outOff);
    
    int ProcessByte(byte input, Span<byte> output);
    
    // Front blocks after padding block processing;

    byte[] ProcessBlocks(byte[] input, int inOff, int length);

    int ProcessBlocks(byte[] input, int inOff, int length, byte[] output, int outOff);

    int ProcessBlocks(ReadOnlySpan<byte> input, Span<byte> output);
    
    // Block final processing

    int ProcessBlockFinal(byte[] output, int outOff);
        
    int ProcessBlockFinal(Span<byte> output); 
    
    // wrapper for combining methods ProcessBlock and ProcessBlockFinal
    
    byte[] ProcessAll(byte[] input, int inOff, int inLen);
    
    // others methods
    
    int GetOutputSize(
        int inputLen);

    int GetUpdateOutputSize(
        int inputLen);
    
    void Reset();

}