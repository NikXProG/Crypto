using Crypto.Domain.Enums;

namespace Crypto.Domain.Interfaces;

public interface ICipherModeConfigurable<out T> where T : ICipherModeConfigurable<T>
{
    T WithCipherMode(CipherMode cipherMode);
}