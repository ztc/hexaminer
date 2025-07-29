using System;
using System.IO;
using System.Text;

namespace ZTC.Hexaminer.Core
{
    public class HexBinaryReader : IDisposable
    {
        private readonly Stream _stream;
        private readonly bool _leaveOpen;

        public HexBinaryReader(Stream stream, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _leaveOpen = leaveOpen;
        }

        public long Position => _stream.Position;
        public long Length => _stream.Length;

        public byte ReadByte()
        {
            int value = _stream.ReadByte();
            return value == -1 ? throw new EndOfStreamException() : (byte)value;
        }

        public byte[] ReadBytes(int count)
        {
            byte[] buffer = new byte[count];
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = _stream.Read(buffer, totalRead, count - totalRead);
                if (read == 0) throw new EndOfStreamException();
                totalRead += read;
            }
            return buffer;
        }

        public ushort ReadUInt16LE() => (ushort)(ReadByte() | (ReadByte() << 8));
        public ushort ReadUInt16BE() => (ushort)((ReadByte() << 8) | ReadByte());
        public uint ReadUInt32LE() => (uint)(ReadByte() | (ReadByte() << 8) | (ReadByte() << 16) | (ReadByte() << 24));
        public uint ReadUInt32BE() => (uint)((ReadByte() << 24) | (ReadByte() << 16) | (ReadByte() << 8) | ReadByte());
        public ulong ReadUInt64LE() => ReadUInt32LE() | ((ulong)ReadUInt32LE() << 32);
        public ulong ReadUInt64BE() => ((ulong)ReadUInt32BE() << 32) | ReadUInt32BE();

        public string ReadString(int length, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            byte[] bytes = ReadBytes(length);
            return encoding.GetString(bytes).TrimEnd('\0');
        }

        public void Seek(long offset, SeekOrigin origin = SeekOrigin.Begin)
        {
            _stream.Seek(offset, origin);
        }

        public void Dispose()
        {
            if (!_leaveOpen)
                _stream?.Dispose();
        }
    }
}