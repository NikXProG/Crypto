using System.Text;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Engines;
using Crypto.Generators;

namespace Crypto.Tests.Engines;

public class DesEngineTests 
{
    
    [Theory]
    [InlineData("12345678", true)]
    [InlineData("123456789", false)]
    [InlineData("Hello world", false)]
    [InlineData("Hello 123", false)]
    [InlineData("Hello123", true)]
    public void EncryptDecrypt_VariousLengths(string text, bool shouldMatch)
    {
        var plain = Encoding.ASCII.GetBytes(text);
        var key = CreateDesKeyGenerator().GenerateKey();

        var enc = EncryptOneBlock(key, plain);
        var dec = DecryptOneBlock(key, enc);

        if (shouldMatch)
            Assert.Equal(plain, dec);
        else
            Assert.NotEqual(plain, dec);
    }
    
    private byte[] EncryptOneBlock(SymmetricKey key, byte[] plain)
    {
        return ProcessBlock(true, key, plain);
    }
    
    private byte[] DecryptOneBlock(SymmetricKey key, byte[] cipher)
    {
        return ProcessBlock(false, key, cipher);
    }

    private byte[] ProcessBlock(bool encrypting, SymmetricKey key, byte[] message)
    { 
        byte[] result = new byte[message.Length];
        
        IBlockCipher engine = new DesEngine();
        
        engine.Setup(encrypting, key);
        
        engine.ProcessBlock(message, result);
        
        return result;
    }
    
    private ISymmetricKeyGenerator CreateDesKeyGenerator()
    {
        IRandomGenerator random = new CryptoRandom();

        ISymmetricKeyGenerator keyGen = new DesKeyGenerator(random);
        
        return keyGen;
    }


}