
using System.Numerics;
using System.Text;
using Crypto.Builders;
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Engines;
using Crypto.Helpers;
using Crypto.Utils;
using Xunit.Abstractions;


namespace Crypto.Tests.Engines
{
    
    public class RsaEngineTests
    {
      

        private const int DefaultKeySize = 2048;
        private const int DefaultCertainty = 32;
        private static readonly BigInteger DefaultPublicExponent = 65537;
        private const PrimalityTestMode DefaultPrimalityMode = PrimalityTestMode.Miller;
        
        // parameters specifically selected for the winner's attack
        private static readonly BigInteger VulnerableE = BigInteger.Parse("66485515700027508124393462603307250283285433560589922749953846584350319445057850434378385036858864936995624416301155250283854028492295775511806815870240769834283989221116776654053682452967999953321125454046763105962086775969986855276743946578863359050058645755209508360174125889513337651751635233993709763703");
        private static readonly BigInteger VulnerableN =  BigInteger.Parse("106774728126681627939368333568146834748954381924140339429116948705200702583783883904569812973644885904232513676261931492637265097244025465493777677546902927256074232367594502950952251233351032491901485509039965967881313865964941445996219261211676996512756521494649034694180698160424747599765303636899244093939");
        
        [Theory]
        [InlineData("user.name+tag@example.co.uk 🙉")]
        [InlineData("another.invalid.com 🤖")]
        [InlineData("Hello, Cryptography! This is rsa encryption! 👾")]
        [InlineData("Nice! I'm back! 🎉")]
        public void EncryptDecrypt_VariousLengths(string text)
        {
            var plain = Encoding.UTF8.GetBytes(text);
            var key = CreateDefaultRsaGen().GenerateKey();
            
            var enc = Encrypt(key.Public, plain);
            var dec = Decrypt(key.Private, enc);
        
            Assert.Equal(plain, dec);
        }
        
        [Fact]
        public void WienerAttack_Test()
        {
            var plain = Encoding.UTF8.GetBytes("Hello Wiener!");
            
            // parameters specifically selected for the winner's attack
            
            var crackedPrivateKey = WienerAttack.Run(VulnerableE, VulnerableN);
            
            var publicKey = new RsaKey(false, VulnerableN,VulnerableE);
            
            var encrypted = Encrypt(publicKey, plain);
            
            var result = Decrypt(crackedPrivateKey, encrypted);
            
            Assert.Equal(plain, result);
        }
        
        private byte[] Encrypt(AsymmetricKey key, byte[] plain)
        {
            return ProcessBlock(true, key, plain);
        }
    
        private byte[] Decrypt(AsymmetricKey key, byte[] cipher)
        {
            return ProcessBlock(false, key, cipher);
        }

        private byte[] ProcessBlock(bool encrypting, AsymmetricKey key, byte[] message)
        { 
            IAsymmetricalCipher engine = new RsaEngine();
        
            engine.Setup(encrypting, key);
        
            return engine.ProcessBlock(message, 0, message.Length);
        }
        
        
        private IAsymmetricKeyGenerator CreateDefaultRsaGen()
        {
            return new RsaKeyGeneratorBuilder()
                .WithKeySize(DefaultKeySize)
                .WithCertaintyTest(DefaultCertainty)
                .WithPrimalityMode(DefaultPrimalityMode)
                .WithPublicExponent(DefaultPublicExponent)
                .Build();
        }
        
        private IAsymmetricKeyGenerator CreateRsaKeyGenerator(
            int keySize, 
            BigInteger publicExponent,
            int certainty,
            PrimalityTestMode mode)
        {
            return new RsaKeyGeneratorBuilder()
                .WithKeySize(keySize)
                .WithCertaintyTest(certainty)
                .WithPrimalityMode(mode)
                .WithPublicExponent(publicExponent)
                .Build();
        }
        
        

    }
    
    
}
