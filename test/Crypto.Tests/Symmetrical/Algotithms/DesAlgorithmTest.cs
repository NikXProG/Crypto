using Xunit.Abstractions;
using CipherMode = Crypto.Core.CipherMode;
using PaddingMode = Crypto.Core.PaddingMode;

namespace Crypto.Tests.Symmetrical.Algotithms
{
    
    public class DesAlgorithmTest
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public DesAlgorithmTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void Test1()
        {
            
            byte[] weakKey = System.Text.Encoding.ASCII.GetBytes("password");
            
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("message1");
            
            byte[] iv = System.Text.Encoding.ASCII.GetBytes("eterni");

            var des = CryptoBuilder
                .UseDes()
                .WithCipherMode(CipherMode.ECB)
                .WithPadding(PaddingMode.ANSIX923)
                .WithKey(weakKey)
                .Build();
            

            // var defaultDes = 
            //     CryptoFactory.CreateDes(weakKey, iv);
            //
            // defaultDes.Encrypt(msg);
            //
            // _testOutputHelper.WriteLine(des.AlgorithmName);
            //
            // _testOutputHelper.WriteLine(
            //     System.Text.Encoding.ASCII.GetString(des.IV).Trim());
            //     
            // _testOutputHelper.WriteLine(
            //     System.Text.Encoding.ASCII.GetString(des.Key).Trim());
            //
            // var e = DesCipher.Encrypt(msg, weakKey, iv);

            //
            // IBlockCipher engine = new DesEngine(
            //      CipherMode.CBC,
            //      8,
            //      weakKey,
            //      iv, 
            //      true,
            //      8,
            //      8);
            //
            // IEncryptor transform = new PaddedBlockEncryptor(
            //     PaddingMode.PKCS7,
            //     engine);
            //
            // MemoryStream memoryStream = new MemoryStream();
            //
            // CryptoWriteStream stream = new CryptoWriteStream(
            //     memoryStream, transform);


            // if (des.IV != null)
            // {
            //     _testOutputHelper.WriteLine(
            //         System.Text.Encoding.ASCII.GetString(des.IV).Trim());
            // }
            //
            //

            //
            //

            //
            // var ms = new MemoryStream();
            //
            // var stream = new CryptoWriteStream(ms, aes.GetEncryptor());
            //
            // stream.Write(bytes, 0, bytes.Length);
            //
            // stream.FlushFinal();

        }
    }
}

