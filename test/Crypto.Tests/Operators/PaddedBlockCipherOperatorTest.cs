using System.Numerics;
using System.Text;
using Crypto.Padding;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit.Abstractions;
using IBlockCipher = Org.BouncyCastle.Crypto.IBlockCipher;

namespace Crypto.Tests.Operators;

public class PaddedBlockCipherOperatorTest
{
    private readonly ITestOutputHelper _testOutputHelper;

    public PaddedBlockCipherOperatorTest(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void TestOperator()
    {
        var desGenerator = new DesKeyGenerator();
        
        desGenerator.Init(new KeyGenerationParameters(
            new SecureRandom(),
            64));

        IBlockCipher engine = new DesEngine();

        IBlockCipher mode = new CbcBlockCipher(engine);

        IBlockCipherPadding padding = new Pkcs7Padding();
        
        IBufferedCipher cipher = new PaddedBufferedBlockCipher(mode, padding);
        
        var key = new KeyParameter(desGenerator.GenerateKey());
        
        cipher.Init(true, key);
            
        byte[] plain = Encoding.ASCII.GetBytes("Hello, Cryptography!");
        byte[] encrypted;
        
        using (MemoryStream ms = new MemoryStream())
        {
            using (var cs = new CipherStream(ms, null, cipher))
            {
                cs.Write(plain, 0, plain.Length);
              
            }
            encrypted = ms.ToArray();
        
        }
        
        _testOutputHelper.WriteLine("=== DIRECT DECRYPTION ===");
        cipher.Init(false,  key);
        byte[] decryptedDirect = cipher.DoFinal(encrypted, 0, encrypted.Length);
        _testOutputHelper.WriteLine("Direct decrypted: " + BitConverter.ToString(decryptedDirect));
        _testOutputHelper.WriteLine("Direct decrypted text: " + Encoding.UTF8.GetString(decryptedDirect));
        _testOutputHelper.WriteLine("Direct decrypted length: " + decryptedDirect.Length);
        
        // ПРОВЕРКА ЧЕРЕЗ CRYPTOSTREAM
        _testOutputHelper.WriteLine("=== STREAM DECRYPTION ===");
        cipher.Init(false, key); // Reset
        
        using (MemoryStream ms2 = new MemoryStream(encrypted))
        using (CipherStream cs2 = new CipherStream(ms2, cipher, null)) 
        {
            using (MemoryStream resultStream = new MemoryStream())
            {
                cs2.CopyTo(resultStream);
             
                byte[] decrypted = resultStream.ToArray();
                _testOutputHelper.WriteLine("Stream decrypted: " + BitConverter.ToString(decrypted));
                _testOutputHelper.WriteLine("Stream decrypted text: " + Encoding.UTF8.GetString(decrypted));
                _testOutputHelper.WriteLine("Stream decrypted length: " + decrypted.Length);
            }
        }
        

    }
}