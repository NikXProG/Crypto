using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;

namespace Crypto.Tests.IO;

public abstract class BlockCipherStreamTests
{
    protected abstract ICipherOperator CreateCipherOperator();
    protected abstract ISymmetricKeyGenerator CreateKeyGenerator();
    
    protected virtual ICryptoParams CreateSymmetricParams(ICryptoParams paramKey, byte[] iv = null)
    {
        return new IVWithParams(paramKey, iv);
    }

    public void TestWithStream(byte[] data)
    {
        var keyGenerator = CreateKeyGenerator();
        var cipher = CreateCipherOperator();
        
        var key = keyGenerator.GenerateKey();
        var iv = keyGenerator.GenerateIV();
        
        // Encryption
        byte[] encrypted;
        using (var ms = new MemoryStream())
        {
            cipher.Setup(true, CreateSymmetricParams(key, iv));
            using (var cryptoStream = new SimpleStream(ms, cipher, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinal();
            }
            encrypted = ms.ToArray();
        }

        // Decryption
        byte[] decrypted;
        using (var ms = new MemoryStream(encrypted))
        {
            cipher.Setup(false, CreateSymmetricParams(key, iv));
            using (var cryptoStream = new SimpleStream(ms, cipher, CryptoStreamMode.Read))
            using (var resultStream = new MemoryStream())
            {
                cryptoStream.CopyTo(resultStream);
                decrypted = resultStream.ToArray();
            }
        }

        Assert.Equal(data, decrypted);
        
        
    }


}