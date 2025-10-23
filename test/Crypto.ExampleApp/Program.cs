using System.Text;
using Crypto;
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Extensions;
using Crypto.Generators;

namespace Crypto.ExampleApp;

public class Program
{
    public static int Main()
    {

        var plain = Encoding.ASCII.GetBytes("Hello, Cryptography!");

        ISymmetricKeyGenerator keyGen = new AesKeyGenerator(new CryptoRandom(), 256);

        ICipherOperator oper = CryptoBuilder
            .UseAes()
            .WithMode(builder => builder
                .UseMode(CipherMode.CBC)
                .WithIV(keyGen.GenerateIV()))
            .AddPadding(BlockPadding.PKCS7)
            .Build();

        ICryptoParams key = keyGen.GenerateKey();

        //cipher.Setup(true, key);
        //byte[] encrypted = cipher.ProcessAll(data, 0 , data.Length);
        //cipher.Setup(false, key);
        //byte[] decrypted = cipher.ProcessAll(encrypted, 0 , encrypted.Length);

        // или можете воспользоваться Crypto.Extensions

        byte[] encrypted = oper.Encrypt(key, plain);

        byte[] decrypted = oper.Decrypt(key, encrypted);

        string decryptedText = Encoding.UTF8.GetString(decrypted);

        Console.WriteLine(decryptedText);  // Hello, Cryptography!

        return 0;
    }
}