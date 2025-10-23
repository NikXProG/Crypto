using Crypto.Tests.Algorithms;
using Crypto.Tests.Base;
using Crypto.Tests.IO;

namespace Crypto.Tests.Ciphers;

public class CipherTests : CipherBaseTests
{
    
       
    [Theory]
    [MemberData(nameof(TestDataProvider.GetRandomData), MemberType = typeof(TestDataProvider))]
    public void TripleDes_EncryptDecryptBinaryTest(byte[] data)
        => EncryptDecryptWithBlockTests(new TripleDesStreamTests(), data);
    
    [Theory]
    [MemberData(nameof(TestDataProvider.GetTextFiles), MemberType = typeof(TestDataProvider))]
    [MemberData(nameof(TestDataProvider.GetMediaFiles), MemberType = typeof(TestDataProvider))]
    public void TripleDes_EncryptDecryptFileTest(string filePath)
        => EncryptDecryptWithBlockTests(new TripleDesStreamTests(), GetBinaryData(filePath));
    
    [Theory]
    [MemberData(nameof(TestDataProvider.GetRandomData), MemberType = typeof(TestDataProvider))]
    public void Deal_EncryptDecryptBinaryTest(byte[] data)
        => EncryptDecryptWithBlockTests(new DealCipherStreamTests(), data);
    
    [Theory]
    [MemberData(nameof(TestDataProvider.GetTextFiles), MemberType = typeof(TestDataProvider))]
    [MemberData(nameof(TestDataProvider.GetMediaFiles), MemberType = typeof(TestDataProvider))]
    public void Deal_EncryptDecryptFileTest(string filePath)
        => EncryptDecryptWithBlockTests(new DealCipherStreamTests(), GetBinaryData(filePath));
    
    
    [Theory]
    [MemberData(nameof(TestDataProvider.GetRandomData), MemberType = typeof(TestDataProvider))]
    public void Des_EncryptDecryptBinaryTest(byte[] data)
        => EncryptDecryptWithBlockTests(new DesCipherStreamTests(), data);
    
    [Theory]
    [MemberData(nameof(TestDataProvider.GetTextFiles), MemberType = typeof(TestDataProvider))]
    [MemberData(nameof(TestDataProvider.GetMediaFiles), MemberType = typeof(TestDataProvider))]
    public void Des_EncryptDecryptFileTest(string filePath)
        => EncryptDecryptWithBlockTests(new DesCipherStreamTests(), GetBinaryData(filePath));

    [Theory]
    [MemberData(nameof(TestDataProvider.GetRandomData), MemberType = typeof(TestDataProvider))]
    public void Aes_EncryptDecryptBinaryTest(byte[] data)
        => EncryptDecryptWithBlockTests(new AesCipherStreamTests(), data);
    
    [Theory]
    [MemberData(nameof(TestDataProvider.GetTextFiles), MemberType = typeof(TestDataProvider))]
    [MemberData(nameof(TestDataProvider.GetMediaFiles), MemberType = typeof(TestDataProvider))]
    public void Aes_EncryptDecryptFileTest(string filePath)
        => EncryptDecryptWithBlockTests(new AesCipherStreamTests(), GetBinaryData(filePath));

    protected override void EncryptDecryptWithBlockTests(BlockCipherStreamTests tests, byte[] data) =>
        tests.TestSimpleCipher(data);
    
}