using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Crypto.Domain.Exceptions;
using Crypto.Domain.Interfaces;
using Crypto.Extensions;
using Crypto.Helpers;

namespace Crypto;

public sealed class CryptoStream : Stream
{
    
    #region Fields
    
    private readonly Stream _stream;
    private readonly ICipherOperator _operator;
    private readonly CryptoStreamMode _mode;
    
    private bool _finalized; 
    private readonly object _finalizeLock = new object();

    
    private byte[] m_readBuf;
    private int m_readBufPos;
    private bool m_readEnded;
    private bool _canWrite;
    private bool _canRead;

    #endregion
    
    #region Constructors
    
    public CryptoStream(Stream stream, ICipherOperator cipher, CryptoStreamMode mode)
    {
        _stream = stream;
        _operator = cipher;
        _mode = mode;
        
        _canRead = mode == CryptoStreamMode.Read && stream.CanRead;
        _canWrite = mode == CryptoStreamMode.Write && stream.CanWrite;

        if (mode == CryptoStreamMode.Read && cipher != null)
        {
            m_readBuf = null;
        }
    }
    
    #endregion

    #region Properties
    
    public Stream Stream => _stream;
    public ICipherOperator Operator => _operator;
    public CryptoStreamMode Mode => _mode;

    public override bool CanRead => _canRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _canWrite;
    
    
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
    
    #endregion


    #region Methods
    
    public override void Flush()
    {
        if (_canWrite)
        {
            _stream.Flush();
        }
    }
    
    public void FlushFinal()
    {
        if (!_canWrite || _operator == null)
            return;
        
        if (_finalized)
            return;

        lock (_finalizeLock)
        {
            if (_finalized)
                return;

            try
            {
              
                int outputSize = _operator.GetOutputSize(0);
                if (outputSize <= 0)
                {
                    _finalized = true;
                    return;
                }

                byte[] output = new byte[outputSize];
                try
                {
                    
                    int len = _operator.ProcessBlockFinal(output, 0);
                    if (len > 0)
                    {
                        _stream.Write(output, 0, len);
                        _stream.Flush();
                    }
                }
                finally
                {
                    Array.Clear(output, 0, output.Length);
                }
            }
            finally
            {
                _finalized = true;
            }
        }
    }
    
    public override void CopyTo(Stream destination, int bufferSize)
    {
        int bytesRead;
        Span<byte> buffer = bufferSize <=  4096
            ? stackalloc byte[bufferSize]
            : new byte[bufferSize];
        while ((bytesRead = ReadSource.Read(buffer)) != 0)
        {
            destination.Write(buffer[..bytesRead]);
        }
    }
    

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (!_canRead)
            throw new NotSupportedException("Stream not readable");
        
        if (_operator == null)
            return _stream.Read(buffer, offset, count);

        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        int available = buffer.Length - offset;
        if ((offset | available) < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        int remaining = available - count;
        if ((count | remaining) < 0)
            throw new ArgumentOutOfRangeException(nameof(count));

        int num = 0;
        while (num < count)
        {
            if (m_readBuf == null || m_readBufPos >= m_readBuf.Length)
            {
                if (!FillInBuf())
                    break;
            }

            int numToCopy = System.Math.Min(count - num, m_readBuf.Length - m_readBufPos);
            Array.Copy(m_readBuf, m_readBufPos, buffer, offset + num, numToCopy);
            m_readBufPos += numToCopy;
            num += numToCopy;
        }

        return num;
    }
    
    // public override int Read(Span<byte> buffer)
    // {
    //     if (!_canRead)
    //         throw new NotSupportedException("Stream not readable");
    //
    //     if (_operator == null)
    //         return _stream.Read(buffer);
    //
    //     if (buffer.IsEmpty)
    //         return 0;
    //
    //     int num = 0;
    //     while (num < buffer.Length)
    //     {
    //         if (m_readBuf == null || m_readBufPos >= m_readBuf.Length)
    //         {
    //             if (!FillInBuf())
    //                 break;
    //         }
    //
    //         int numToCopy = System.Math.Min(buffer.Length - num, m_readBuf.Length - m_readBufPos);
    //         m_readBuf.AsSpan(m_readBufPos, numToCopy).CopyTo(buffer[num..]);
    //
    //         m_readBufPos += numToCopy;
    //         num += numToCopy;
    //     }
    //
    //     return num;
    // }
    //
    // public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    // {
    //     if (!_canRead)
    //         throw new NotSupportedException("Stream not readable");
    //     
    //     return ReadSource.ReadAsync(buffer, cancellationToken);
    // }
    
    public override void Write(byte[] buffer, int offset, int count)
    {
        if (!_canWrite)
            throw new NotSupportedException("Stream not writable");

        if (_operator == null)
        {
            _stream.Write(buffer, offset, count);
            return;
        }

        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        int available = buffer.Length - offset;
        if ((offset | available) < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        int remaining = available - count;
        if ((count | remaining) < 0)
            throw new ArgumentOutOfRangeException(nameof(count));

        if (count > 0)
        {
            int outputSize = _operator.GetUpdateOutputSize(count);

            byte[] output = new byte[outputSize];

            int length = _operator.ProcessBlocks(buffer, offset, count, output, 0);
            if (length > 0)
            {
                try
                {
                    _stream.Write(output, 0, length);
                }
                finally
                {
                    Array.Clear(output, 0, output.Length);
                }
            }
        }
    }
    
    // public override int ReadByte()
    // {
    //     if (!_canRead)
    //         throw new NotSupportedException("Stream not readable");
    //
    //     if (_operator == null)
    //     {
    //         return _stream.ReadByte();
    //     }
    //
    //     if (m_readBuf != null && m_readBufPos < m_readBuf.Length)
    //     {
    //         return m_readBuf[m_readBufPos++];
    //     }
    //     
    //     if (!FillInBuf())
    //         return -1;
    //
    //     return m_readBuf[m_readBufPos++];
    // }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long length) => throw new NotSupportedException();
    
        // public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        // {
        //     if (!_canWrite)
        //         throw new NotSupportedException("Stream not writable");
        //
        //     if (_operator == null)
        //     {
        //         await _stream.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        //         return;
        //     }
        //     
        //     if (buffer == null)
        //         throw new ArgumentNullException(nameof(buffer));
        //     int available = buffer.Length - offset;
        //     if ((offset | available) < 0)
        //         throw new ArgumentOutOfRangeException(nameof(offset));
        //     int remaining = available - count;
        //     if ((count | remaining) < 0)
        //         throw new ArgumentOutOfRangeException(nameof(count));
        //
        //     if (count > 0)
        //     {
        //         if (cancellationToken.IsCancellationRequested)
        //             throw new TaskCanceledException();
        //
        //         int outputSize = _operator.GetUpdateOutputSize(count);
        //
        //         byte[] output = new byte[outputSize];
        //
        //         try
        //         {
        //             int length = _operator.ProcessBlocks(buffer, offset, count, output, 0);
        //             if (length > 0)
        //             {
        //                 await _stream.WriteAsync(output, 0, length, cancellationToken).ConfigureAwait(false);
        //             }
        //         }
        //         finally
        //         {
        //             Array.Clear(output, 0, output.Length);
        //         }
        //         
        //     }
        //     
        // }
        //
    // public override void WriteByte(byte value)
    // {
    //     if (!_canWrite)
    //         throw new NotSupportedException("Stream not writable");
    //
    //     if (_operator == null)
    //     {
    //         _stream.WriteByte(value);
    //         return;
    //     }
    //
    //     byte[] output = _operator.ProcessByte(value);
    //     if (output != null)
    //     {
    //         try
    //         {
    //             _stream.Write(output, 0, output.Length);
    //         }
    //         finally
    //         {
    //             Array.Clear(output, 0, output.Length);
    //         }
    //     }
    // }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _stream.Dispose();
        }
        base.Dispose(disposing);
    }
    
    private bool FillInBuf()
    {
        if (m_readEnded)
            return false;

        m_readBufPos = 0;

        do
        {
            m_readBuf = ReadAndProcessBlock();
        }
        while (!m_readEnded && m_readBuf == null);

        return m_readBuf != null;
    }
    
    private byte[] ReadAndProcessBlock()
    {
        int blockSize = _operator.BlockSize;
        int readSize = blockSize == 0 ? 256 : blockSize;

        byte[] block = new byte[readSize];
        int numRead = 0;
        do
        {
            int count = _stream.Read(block, numRead, block.Length - numRead);
            if (count < 1)
            {
                m_readEnded = true;
                break;
            }
            numRead += count;
        } while (numRead < block.Length);
        
        byte[] bytes = m_readEnded
            ? _operator.ProcessAll(block, 0, numRead)
            : _operator.ProcessBlocks(block);

        if (bytes != null && bytes.Length == 0)
        {
            bytes = null;
        }

        return bytes;
    }
    
    private Stream ReadSource => _operator == null ? _stream : this;
    
    #endregion

}
    