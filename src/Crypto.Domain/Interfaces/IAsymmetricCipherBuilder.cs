using Crypto.Domain.Enums;

namespace Crypto.Domain.Interfaces;

public interface IAsymmetricCipherBuilder
{

    IAsymmetricCipherBuilder AddPadding(AsymmetricPadding paddingMode);

    IAsymmetricalCipher Build();

}