using Crypto.Engines;

namespace Crypto.Tests.IO;

public class CipherStreamTests : BinaryBaseTests
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

    private void EncryptDecryptWithBlockTests(BlockCipherStreamTests tests, byte[] data) => 
        tests.TestWithStream(data);
    
}