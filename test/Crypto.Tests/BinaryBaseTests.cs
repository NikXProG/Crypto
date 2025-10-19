using System.Reflection;

namespace Crypto.Tests;

public class BinaryBaseTests
{
    
    
    private static Assembly GetAssembly() => typeof(BinaryBaseTests).Assembly;
    
    private static string GetTestFilePath(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            throw new ArgumentException("File name cannot be null or empty", nameof(fileName));
            
        return Path.Combine(Directory.GetCurrentDirectory(), fileName);
    }
    
    internal static byte[] GetBinaryData(string fileName)
    {
        var filePath = GetTestFilePath(fileName);
        
        return !File.Exists(filePath) ? 
            throw new FileNotFoundException($"Test data file not found: {filePath}") : 
            File.ReadAllBytes(filePath);
    }
    
}