
using Crypto.Symmetrical.Algorithms;
using Xunit.Abstractions;

using Crypto.Core;
using Crypto.Core.Interfaces;
using Crypto.Symmetrical.Builders;
using Crypto.Symmetrical.Parameters;
using PaddingMode = Crypto.Core.PaddingMode;

namespace Crypto.Tests
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
            
            byte[] iv = System.Text.Encoding.ASCII.GetBytes("eternity");

            var des = CryptoBuilder
                .UseDesAlgorithm()
                .WithFeistelSize(FeistelNetSize.Large)
                .WithRoundsCount(16)
                .WithSymmetricalParams(builder => 
                    builder.WithIV(iv)
                        .WithKey(weakKey)
                        .Build())
                .Build();

            var defaultDes = CryptoFactory.CreateDes(weakKey, iv);

            defaultDes.Encrypt(msg);
            
            _testOutputHelper.WriteLine(des.AlgorithmName);
            
            var e = Des.Encrypt(msg, weakKey, iv);
            
            
            
            //
            // ISymmetricalEngine engine = new DesEngine(
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

