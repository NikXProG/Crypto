
namespace Crypto.Tests
{
    
    public class CryptoFactoryTest
    {

        [Fact]
        public void TestCreateDes()
        {
            
            byte[] weakKey = System.Text.Encoding.ASCII.GetBytes("password");
            
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("message1");
            
            byte[] iv = System.Text.Encoding.ASCII.GetBytes("eternity");

            var des = CryptoFactory.CreateDes(weakKey, iv);

            des.Encrypt(msg);
            

        }
    }
}
