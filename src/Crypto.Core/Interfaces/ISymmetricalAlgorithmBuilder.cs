namespace Crypto.Core.Interfaces;
//
// public interface ISymmetricalAlgorithmBuilder
// {
//     /// <summary>
//     /// Some types of algorithms do not support customization of key sizes at all
//     /// </summary>
//     /// <param name="size">encrypt key size in bits</param>
//     /// <returns></returns>
//     ISymmetricalAlgorithmBuilder WithKeySize(int size);
//     
//     /// <summary>
//     /// It is highly recommended to read the standard before using it.
//     /// Weak key and Semi-weak key is bad => runtime error
//     /// </summary>
//     /// <param name="key">bit array block of key</param>
//     /// <returns></returns>
//     ISymmetricalAlgorithmBuilder WithKey(byte[] key);
//     
//     /// <summary>
//     /// Primary vector for encryption modes.
//     /// Serves as encryption and decryption for the first block
//     /// or subsequent ciphertexts.
//     /// It is usually recommended to set the size to the same as the block itself
//     /// </summary>
//     /// <returns></returns>
//     ISymmetricalAlgorithmBuilder WithIV(byte[] iv);
//     ISymmetricalAlgorithmBuilder WithMode(CipherMode mode);
//     ISymmetricalAlgorithmBuilder WithPadding(PaddingMode padding);
//     
//     ISymmetrical Build();
// }