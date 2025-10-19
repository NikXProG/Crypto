using System.Text;
using Crypto.Builders;
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Engines;
using Crypto.Extensions;
using Crypto.Generators;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Processing;
using Xunit.Abstractions;

namespace Crypto.Tests.IO;

public class CryptoStreamTests : BinaryBaseTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public CryptoStreamTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }
    
    [Theory]
    [InlineData("scripts/Trie.cs")]
    public void Des_TextScriptEncryptionTest(string scriptPath)
    {
        var data = GetBinaryData(scriptPath);
        
        var keyGenerator = new DesKeyGenerator(new CryptoRandom());
        var cipher = CryptoBuilder.UseDes()
            .WithMode(builder => builder
                .UseCbcMode()
                .WithIV(keyGenerator.GenerateIV()))
            .AddPadding(BlockPadding.PKCS7)
            .Build();
        
        var key = keyGenerator.GenerateKey();
        
        byte[] encrypted;
        using (var ms = new MemoryStream())
        {
            cipher.Setup(true, key);
            using (var cryptoStream = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinal();
            }
            encrypted = ms.ToArray();
        }
        
        byte[] decrypted;
        using (var ms = new MemoryStream(encrypted))
        {
            cipher.Setup(false, key);
            using (var cryptoStream = new CryptoStream(ms, cipher, CryptoStreamMode.Read))
            using (var resultStream = new MemoryStream())
            {
                cryptoStream.CopyTo(resultStream);
                decrypted = resultStream.ToArray();
            }
        }
        
        Assert.Equal(data, decrypted);
  
    }
    
    [Theory]
    [InlineData("images/test_image_one.jpg")]
    [InlineData("media/mario.mp3")]
    public void Des_TextMediaEncryptionTest(string scriptPath)
    {
        var data = GetBinaryData(scriptPath);
        
        var keyGenerator = new DesKeyGenerator(new CryptoRandom());
        var cipher = CryptoBuilder.UseDes()
            .WithMode(builder => builder
                .UseCbcMode()
                .WithIV(keyGenerator.GenerateIV()))
            .AddPadding(BlockPadding.PKCS7)
            .Build();
        
        var key = keyGenerator.GenerateKey();
        
        byte[] encrypted;
        using (var ms = new MemoryStream())
        {
            cipher.Setup(true, key);
            using (var cryptoStream = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinal();
            }
            encrypted = ms.ToArray();
        }
        
        string encryptedFilePath = Path.Combine(
            Path.GetDirectoryName(scriptPath) ?? Directory.GetCurrentDirectory(),
            "encrypted_" + Path.GetFileName(scriptPath)
        );
    
        File.WriteAllBytes(encryptedFilePath, encrypted);
        
        byte[] decrypted;
        using (var ms = new MemoryStream(encrypted))
        {
            cipher.Setup(false, key);
            using (var cryptoStream = new CryptoStream(ms, cipher, CryptoStreamMode.Read))
            using (var resultStream = new MemoryStream())
            {
                cryptoStream.CopyTo(resultStream);
                decrypted = resultStream.ToArray();
            }
        }
        
        string decryptedFilePath = Path.Combine(
            Path.GetDirectoryName(scriptPath) ?? Directory.GetCurrentDirectory(),
            "decrypted_" + Path.GetFileName(scriptPath)
        );
    
        File.WriteAllBytes(decryptedFilePath, decrypted);
        
        Assert.Equal(data, decrypted);
        
    }
    
    [Fact]
    public void TestBinaryDataSimulation()
    {
        _testOutputHelper.WriteLine("\n=== BINARY DATA SIMULATION (Images/Audio/Video) ===");

        var keyGenerator = new DesKeyGenerator(new CryptoRandom());
        var cipher = CryptoBuilder.UseDes()
            .WithMode(builder => builder.UseCbcMode().WithIV(keyGenerator.GenerateIV()))
            .AddPadding(BlockPadding.PKCS7)
            .Build();

        var key = keyGenerator.GenerateKey();
        
        var binaryFormats = new[]
        {
            new { Name = "PNG Header", Data = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } },
            new { Name = "WAV Header", Data = new byte[] { 0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45 } },
            new { Name = "MP4 Header", Data = new byte[] { 0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32 } },
        };

        foreach (var format in binaryFormats)
        {
            _testOutputHelper.WriteLine($"Testing {format.Name}: {format.Data.Length} bytes");

            // Шифрование
            cipher.Setup(true, key);
            byte[] encrypted = cipher.ProcessAll(format.Data, 0, format.Data.Length);

            // Дешифрование
            cipher.Setup(false, key);
            byte[] decrypted = cipher.ProcessAll(encrypted, 0, encrypted.Length);

            Assert.Equal(format.Data, decrypted);
            _testOutputHelper.WriteLine($"  ✓ {format.Name} encryption/decryption successful");
            _testOutputHelper.WriteLine($"    Original: {BitConverter.ToString(format.Data.Take(8).ToArray())}");
            _testOutputHelper.WriteLine($"    Encrypted: {BitConverter.ToString(encrypted.Take(8).ToArray())}");
        }
    }
    

}