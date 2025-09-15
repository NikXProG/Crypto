using Crypto.Core;
using Crypto.Core.Interfaces;
using Crypto.Engine;
using Crypto.Engine.Core.Interfaces;
using Crypto.Engine.Symmetrical;
using Crypto.Symmetrical.Parameters;

namespace Crypto.Symmetrical.Algorithms
{
    
    public class Des : ISymmetrical
    {
        
        private readonly SymmetricalParameters _parameters;
        
        private readonly FeistelNetSize _delBlockSize;

        private readonly int _roundCount;
        
        public Des(SymmetricalParameters parameters) : 
            this(parameters, FeistelNetSize.Large, 16)
        {
            
        }
        
        internal Des(SymmetricalParameters parameters, FeistelNetSize delBlockSize, int roundCount)
        {
            _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            _delBlockSize = delBlockSize;
            _roundCount = roundCount;
        }
        
        public string AlgorithmName => "DES";

        public void GenerateIV()
        {
            throw new NotImplementedException();
        }

        public IDecryptor GetDecryptor()
        {
            
            ISymmetricalEngine engine = new DesEngine(
                _parameters.Mode,
                _parameters.BlockSize,
                _parameters.Key,
                _parameters.IV,
                true,
                _parameters.FeedbackSize,
                _parameters.BlockSize);
            
            return new PaddedBlockDecryptor(PaddingMode.Zeros, engine);
        }

        public IEncryptor GetEncryptor()
        {
            ISymmetricalEngine engine = new DesEngine(
                _parameters.Mode,
                _parameters.BlockSize,
                _parameters.Key,
                _parameters.IV,
                true,
                _parameters.FeedbackSize,
                _parameters.BlockSize);
            
            return new PaddedBlockEncryptor(PaddingMode.Zeros, engine);
        }

        public void GenerateKey()
        {
            throw new NotImplementedException();
        }
    
        public byte[] Decrypt(byte[] ciphertext)
        {
            throw new NotImplementedException();
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            
            using (var ms = new MemoryStream())
            {
                using (var stream = new CryptoWriteStream(
                           ms,
                           this.GetEncryptor()))
                {
                    
                    stream.FlushFinal();
                    
                    return ms.ToArray();
                }
            
            }
            
        }


        public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
        {
            var algorithm = CryptoFactory.CreateDes(iv, key);

            return algorithm.Encrypt(plaintext);
        }
        
    }
    //
    // public abstract class Des : SymmetricalAlgorithm, IFeistelNetwork
    // {
    //     
    //     #region Fields
    //     
    //     private FeistelNetSize _feistelNetSize;
    //     
    //     #endregion
    //     
    //     #region Constructors
    //     
    //     protected Des()
    //     {
    //         DataBlockValidRangeSize = [
    //             new ValidRangeSize(64, 64, 0),
    //         ];
    //
    //         EncryptKeyValidRangeSize = [
    //             new ValidRangeSize(64, 64, 0),
    //         ];
    //         
    //         FeistelNetSize = FeistelNetSize.Medium;
    //         EncryptKeySize = 64;
    //         DataBlockSize = 64;
    //         
    //     }
    //     
    //     #endregion
    //
    //     #region Properties
    //
    //     #region Public properties
    //     
    //     /// <summary>
    //     /// determines how much our block will be divided
    //     /// </summary>
    //     public virtual FeistelNetSize FeistelSize
    //     {
    //         get => FeistelNetSize;
    //         set => FeistelNetSize = value;
    //     }
    //     
    //     public override byte[] Key
    //     {
    //         get
    //         {
    //             byte[] key = base.Key;
    //             while (!IsValidKey(key))
    //             {
    //                 GenerateKey();
    //                 key = base.Key;
    //             }
    //             return key;
    //         }
    //         set
    //         {
    //             ArgumentNullException.ThrowIfNull(value);
    //
    //             if (value.Length != 8)
    //             {
    //                 throw new CryptoException("Invalid key length", "DES");
    //             }
    //
    //             if (!IsValidKey(value))
    //             {
    //                 throw new CryptoException("Weak or semi-weak key detected", "DES");
    //             }
    //             
    //             base.Key = value;
    //         }
    //     }
    //     
    //     #endregion
    //     
    //     #region Protected properties
    //     
    //     protected FeistelNetSize FeistelNetSize
    //     {
    //         get => _feistelNetSize; 
    //         set => _feistelNetSize = value;
    //     }
    //     
    //     #endregion
    //     
    //     #endregion
    //     
    //     #region Methods 
    //     
    //     #region Public methods
    //     
    //     public static bool IsValidKey(byte[] key)
    //     {
    //         
    //         if (key == null || key.Length != 8)
    //             return false;
    //
    //         return !DesWeakKeys.AllWeakKeys.Contains(GetNormalizedKey(key));
    //         
    //     }
    //     
    //     #endregion
    //     
    //     #region Private methods
    //     
    //     private static ulong GetNormalizedKey(byte[] key) =>
    //         BinaryPrimitives.ReadUInt64BigEndian(key.EnsureOddParity());
    //     
    //     #endregion
    //     
    //     #endregion
    //     
    //     
    // }
    
}
