using System.Text;
using Crypto.Builders;
using Crypto.CipherModes;
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Engines;
using Crypto.Generators;
using Xunit.Abstractions;

namespace Crypto.Tests.CipherModes;

public class CipherModeTest
{


    private const CtrCounterMode DefaultCtrCounterMode = CtrCounterMode.One;

    [Theory]
    [InlineData("password", CipherMode.CBC, false)]
    [InlineData("message1message2message3", CipherMode.ECB, false)]
    [InlineData("message1message2", CipherMode.OFB, true)]
    public void BlockCipherMode_TestMode(string text, CipherMode mode, bool isStreamMode)
    {
    
        // Warning:
        // The data is a multiple of 8!
        // There is no padding applied to it.
        
        var plain = Encoding.ASCII.GetBytes(text);
        
        var gen = CreateDesKeyGenerator();

        IBlockCipher engine = new DesEngine();

        SymmetricKey key = gen.GenerateKey();
        
        byte[] iv = gen.GenerateIV();

        var encrypted = ProcessWithoutPaddingFor(
            engine,
            key,
            plain,
            mode,
            iv,
            encrypting: true);
        
        var decrypted = ProcessWithoutPaddingFor(
            engine,
            key,
            encrypted,
            mode,
            iv,
            encrypting: isStreamMode); // stream mode processing requires true
        
        Assert.Equal(plain, decrypted);
    }
    
   
    private byte[] ProcessWithoutPaddingFor(
        IBlockCipher engine,
        SymmetricKey key,
        byte[] message,
        CipherMode mode,
        byte[] iv,
        bool encrypting)
    { 
        byte[] result = new byte[message.Length];
        
        IBlockCipherMode cipherMode = CreateCipherMode(engine, mode, iv);
        
        cipherMode.Setup(encrypting, key);
        
        for (int i = 0; i <  result.Length; i += engine.BlockSizeInBytes)
        {
            int blockSize = Math.Min(engine.BlockSizeInBytes, message.Length - i);
            ReadOnlySpan<byte> inputBlock = message.AsSpan(i, blockSize);
            Span<byte> outputBlock = result.AsSpan(i, blockSize);
            
            cipherMode.ProcessBlock(inputBlock, outputBlock);
        }
        
        return result;

    }
    
    private ISymmetricKeyGenerator CreateDesKeyGenerator()
    {
        IRandomGenerator random = new CryptoRandom();

        ISymmetricKeyGenerator keyGen = new DesKeyGenerator(random);
        
        return keyGen;
    }
    
    private IBlockCipherMode CreateCipherMode(
        IBlockCipher engine,
        CipherMode mode,
        byte[] iv)
    {
        return new BlockCipherModeModeBuilder(engine)
            .UseMode(mode)
            .WithIV(iv)
            .WithCtrCounterMode(DefaultCtrCounterMode)
            .Build();
    }
    
}