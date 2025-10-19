using Crypto.Domain.Parameters;

namespace Crypto.Domain.Interfaces;

public interface ISymmetricKeyGenerator : IKeyGenerator<SymmetricKey>
{
     
     byte[] GenerateIV();

}