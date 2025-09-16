using System.Text;
using Crypto.Core.Interfaces;

namespace Crypto;

public class CryptoWriteStream : Stream, IDisposable
{
    
    #region Constructors
    
    public CryptoWriteStream(Stream stream, IEncryptor encryptor)
        : this(stream, encryptor, true)
    {
        
    }

    public CryptoWriteStream(
        Stream stream, 
        IEncryptor processor, 
        bool disposeStream)
    {
        
    }
    
    #endregion
    
    #region Properties

    public override bool CanRead { get; }

    public override bool CanSeek { get; }

    public override long Length { get; }

    public override long Position { get; set; }

    public override bool CanWrite { get; }

    #endregion
    
    #region Methods

    /// <summary>
    /// flushing final segment block 
    /// </summary>
    public void FlushFinal()
    {
        
    }
    
    public override void Flush()
    {
        throw new NotImplementedException();
    }

  
    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotImplementedException();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotImplementedException();
    }

    public override void SetLength(long value)
    {
        throw new NotImplementedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotImplementedException();
    }
    
    #endregion
    
}