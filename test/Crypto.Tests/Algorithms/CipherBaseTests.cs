using System.Reflection;
using Crypto.Tests.Base;

namespace Crypto.Tests.Algorithms;

public abstract class CipherBaseTests : BinaryBaseTests
{
   
    protected abstract void EncryptDecryptWithBlockTests(
        BlockCipherStreamTests tests,
        byte[] data);
    
    
}