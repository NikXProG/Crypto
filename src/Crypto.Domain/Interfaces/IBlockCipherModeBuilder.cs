using Crypto.Domain.Enums;

namespace Crypto.Domain.Interfaces;

public interface IBlockCipherModeBuilder
{
    
    IBlockCipherModeBuilder UseCfbMode();
    
    IBlockCipherModeBuilder UseCbcMode();
    
    IBlockCipherModeBuilder UseEcbMode();
    
    IBlockCipherModeBuilder UseMode(CipherMode mode);
    
    IBlockCipherModeBuilder WithFeedbackSize(int feedbackSize);
    
    IBlockCipherModeBuilder WithCtrCounterMode(CtrCounterMode mode);
    
    IBlockCipherModeBuilder WithIV(byte[] iv);
    
    IBlockCipherMode Build();
    
}