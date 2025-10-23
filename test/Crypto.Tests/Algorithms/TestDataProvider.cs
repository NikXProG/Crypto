namespace Crypto.Tests.Base;

public static class TestDataProvider
{
    public static IEnumerable<object[]> GetTextFiles()
    {
        return new[]
        {
            new object[] { "scripts/Trie.cs" },
            new object[] { "scripts/Example.cs" },
            new object[] { "markdown/README.md" },
            new object[] { "markdown/random.md" },
        };
    }

    public static IEnumerable<object[]> GetMediaFiles()
    {
        return new[]
        {
            new object[] { "images/test_image_one.jpg" },
            new object[] { "media/mario.mp3" },
        };
    }
    
    public static IEnumerable<object[]> GetRandomData()
    {
        var random = new Random();
        return new[]
        {
            new object[] { GenerateRandomBytes(16) },
            new object[] { GenerateRandomBytes(1024) },
            new object[] { GenerateRandomBytes(64 * 1024) },
            new object[] { GenerateRandomBytes(15) },
            new object[] { GenerateRandomBytes(17) }
        };
    }

    private static byte[] GenerateRandomBytes(int length)
    {
        var bytes = new byte[length];
        new Random().NextBytes(bytes);
        return bytes;
    }
    
}