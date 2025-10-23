using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;

namespace Crypto.Tests.Base;

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
        ISymmetricKeyGenerator keyGenerator = CreateKeyGenerator();
        ICipherOperator cipher = CreateCipherOperator();
        
        SymmetricKey key = keyGenerator.GenerateKey();
        byte[] iv = keyGenerator.GenerateIV();
        
        ICryptoParams parameters = CreateSymmetricParams(key, iv);
        
        // Encryption
        byte[] encrypted;
        using (var ms = new MemoryStream())
        {
            cipher.Setup(true, parameters);
            using (var cryptoStream = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
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
            cipher.Setup(false, parameters);
            using (var cryptoStream = new CryptoStream(ms, cipher, CryptoStreamMode.Read))
            using (var resultStream = new MemoryStream())
            {
                cryptoStream.CopyTo(resultStream);
                decrypted = resultStream.ToArray();
            }
        }

        Assert.Equal(data, decrypted);
        
        
    }

    public void TestSimpleCipher(byte[] data)
    {
        ISymmetricKeyGenerator keyGenerator = CreateKeyGenerator();
        ICipherOperator cipher = CreateCipherOperator();
        
        SymmetricKey key = keyGenerator.GenerateKey();
        byte[] iv = keyGenerator.GenerateIV();
        
        ICryptoParams parameters = CreateSymmetricParams(key, iv);
        
        cipher.Setup(true, parameters);

        byte[] encrypted = cipher.ProcessAll(data, 0 , data.Length);

        cipher.Setup(false, parameters);
        
        byte[] decrypted = cipher.ProcessAll(encrypted, 0 , encrypted.Length);
        
        Assert.Equal(data, decrypted);
    }

}