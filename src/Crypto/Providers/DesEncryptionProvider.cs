
// using Crypto.CipherModes;
// using Crypto.Domain;
// using Crypto.Domain.Exceptions;
// using Crypto.Domain.Extensions;
// using Crypto.Domain.Interfaces;
// using Crypto.Domain.Parameters;
// using Crypto.Engines;
// using Crypto.Factories;
// using Crypto.Generators;
// using Crypto.Helpers;
// using Crypto.Operators;
// using Crypto.BlockPadding;
// using Crypto.Parameters;
// using Crypto.Symmetrical;
// using CipherMode = Crypto.Domain.CipherMode;
// using BlockPadding = Crypto.Domain.BlockPadding;
//
// namespace Crypto.Providers
// {
//     [Obsolete]
//     public sealed class DesEncryptionProvider : ISymmetricalProvider
//     {
//
//         #region Fields
//
//         private ISymmetricKeyGenerator _symmetricalGenerator;
//
//         #region Alrgoithm Fields
//
//         private CipherMode _cipherMode;
//         private BlockPadding _paddingMode;
//         private byte[]? _key;
//         private byte[]? _iv;
//
//         private readonly ValidRangeSize[]? _blockValidRanges;
//         private readonly ValidRangeSize[]? _keyValidRanges;
//
//         private int _blockSize = 64;
//         private int _feedbackSize = 64;
//
//         #endregion
//
//         #region Parameter Ranges
//
//         private static readonly ValidRangeSize[] s_validBlockRanges =
//         {
//             new ValidRangeSize(minSize: 64, maxSize: 64, stepSize: 0)
//         };
//
//         private static readonly ValidRangeSize[] s_ValidKeyRanges =
//         {
//             new ValidRangeSize(minSize: 64, maxSize: 64, stepSize: 0)
//         };
//
//         #endregion
//
//         #endregion
//
//         #region Constructors
//
//         public DesEncryptionProvider() : this(CreateDefaultGenerator())
//         {
//         }
//
//         public DesEncryptionProvider(
//             ISymmetricKeyGenerator keyGenerator)
//         {
//             _blockValidRanges = s_validBlockRanges.DeepCopyValidRange();
//             _keyValidRanges = s_ValidKeyRanges.DeepCopyValidRange();
//
//             FeedbackSize = 8;
//
//             // if (!ValidKeySize(keyGenerator.KeySizeInBits))
//             // {
//             //     throw new CryptoException("Invalid key size. DES must be with size key 64 bits");
//             // }
//             //
//             _symmetricalGenerator = keyGenerator;
//
//             _cipherMode = CipherMode.CBC;
//             _paddingMode = BlockPadding.Zeros;
//
//         }
//
//
//         #endregion
//
//         #region Properties
//
//         /// <summary>
//         /// Initialization Vector (IV) for encryption modes.
//         /// Serves as the initial byte sequence
//         /// to randomize the encryption process
//         /// and prevent repeating patterns in encrypted data.
//         /// </summary>
//         /// <remarks>
//         /// With the same keys and different initialization vectors,
//         /// the encryption result will be different. 
//         /// Requires uniqueness for each encryption session with the same key.
//         /// </remarks>
//         public byte[] IV
//         {
//             get
//             {
//                 if (_iv == null)
//                 {
//                     _iv = _symmetricalGenerator.GenerateIV();
//                 }
//
//                 return _iv.CloneByteArray()!;
//             }
//
//             set
//             {
//                 ArgumentNullException.ThrowIfNull(value);
//                 if (value.Length != this.BlockSizeInBytes / 8)
//                     throw new CryptoException("Invalid size for IV");
//                 _iv = value.CloneByteArray();
//             }
//         }
//
//         /// <summary>
//         /// property specifies the key for encryption
//         /// </summary>
//         public byte[] Key
//         {
//             get
//             {
//                 if (_key == null)
//                 {
//                     _key = _symmetricalGenerator.GenerateKey();
//                 }
//
//                 return _key.CloneByteArray()!;
//             }
//             set
//             {
//                 ArgumentNullException.ThrowIfNull(value);
//
//                 long bitLength = value.Length * 8L;
//                 if (bitLength > int.MaxValue || !ValidKeySize((int)bitLength))
//                     throw new CryptoException("Invalid key size");
//
//                 _key = value.CloneByteArray();
//             }
//         }
//
//         /// <summary>
//         /// defines the block text encryption mode
//         /// </summary>
//         public CipherMode Mode
//         {
//             get => _cipherMode;
//             set
//             {
//                 if ((value < CipherMode.CBC) || (value > CipherMode.ECB))
//                     throw new CryptoException("Invalid range for blockPadding mode");
//                 _cipherMode = value;
//             }
//         }
//
//         /// <summary>
//         /// determines the number of bit blocks into which the message is divided
//         /// </summary>
//         public int BlockSizeInBytes
//         {
//             get => _blockSize;
//             set
//             {
//                 bool validatedByZeroSkipSizeKeySizes;
//                 if (!value.IsValidSize(this.KeyValidRanges, out validatedByZeroSkipSizeKeySizes))
//                     throw new CryptoException("Invalid key size");
//
//                 if (_blockSize == value &&
//                     !validatedByZeroSkipSizeKeySizes) // The !validatedByZeroSkipSizeKeySizes check preserves a very obscure back-compat behavior.
//                     return;
//
//                 _blockSize = value;
//                 _iv = null;
//             }
//         }
//
//         public int FeedbackSize
//         {
//             get { return _feedbackSize; }
//             set
//             {
//                 if (value <= 0 || value > _blockSize || (value % 8) != 0)
//                     throw new CryptoException("FeedBack size must be between 0 and 8");
//                 _feedbackSize = value;
//             }
//         }
//
//         /// <summary>
//         /// determines how to align the last block of the bit sequence
//         /// </summary>
//         public BlockPadding BlockPadding
//         {
//             get => _paddingMode;
//             set
//             {
//                 if ((value < BlockPadding.None) || (value > BlockPadding.ISO10126))
//                     throw new CryptoException("Invalid range for blockPadding mode");
//                 _paddingMode = value;
//             }
//         }
//
//         public ValidRangeSize[] KeyValidRanges =>
//             (ValidRangeSize[])_keyValidRanges!.Clone();
//
//         public ValidRangeSize[] BlockValidRanges =>
//             (ValidRangeSize[])_blockValidRanges!.Clone();
//
//         #endregion
//
//         #region Methods
//
//         #region Public Methods
//
//         public ICipherOperator CreateOperator()
//         {
//             // IBlockCipher engine = new DesEngine();
//             //
//             //
//             // ICipherOperator cipherOperator =
//             //     (BlockPadding == BlockPadding.None)
//             //         ? new BlockCipherOperator(cipherMode)
//             //         : new PaddedBlockCipherOperator(cipherMode, BlockPaddingModeFactory.Create(BlockPadding));
//             //
//             // return cipherOperator;
//
//             return null;
//         }
//
//         public byte[] Decrypt(byte[] ciphertext)
//         {
//             var cipherOperator = CreateOperator();
//
//             cipherOperator.Setup(false, new SymmetricKey(Key));
//
//             return cipherOperator.ProcessAll(ciphertext);
//         }
//
//         public byte[] Encrypt(byte[] plaintext)
//         {
//             var cipherOperator = CreateOperator();
//
//             cipherOperator.Setup(true, new SymmetricKey(Key));
//
//             return cipherOperator.ProcessAll(plaintext);
//         }
//
//         #endregion
//
//         #region Private Methods
//
//         public bool ValidKeySize(int bitLength)
//         {
//             ValidRangeSize[] ranges = this.KeyValidRanges;
//             if (ranges == null)
//                 return false;
//             return bitLength.IsValidSize(ranges);
//         }
//
//         private static ISymmetricKeyGenerator CreateDefaultGenerator()
//         {
//
//             return new DesKeyGenerator();
//
//         }
//
//         #endregion
//
//         #endregion
//
//     }
// }
