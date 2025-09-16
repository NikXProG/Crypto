using Crypto.Core;

namespace Crypto.Tests
{
    
    public class CryptoBuilderTest
    {

        [Fact]
        public void TestCreateDes()
        {
            
            byte[] weakKey = System.Text.Encoding.ASCII.GetBytes("password");
            
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("message1");
            
            byte[] iv = System.Text.Encoding.ASCII.GetBytes("eternity");

            var des = CryptoBuilder
                .UseDes()
                .WithCipherMode(CipherMode.ECB)
                .WithPadding(PaddingMode.ANSIX923)
                .WithKey(weakKey)
                .WithIV(iv)
                .Build();

            des.Encrypt(msg);
            
            

        }
    }
}
  