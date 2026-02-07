using System;
using System.IO;
using System.Globalization;

namespace PECoff
{
    internal static class SevenZipLzmaDecoder
    {
        public static bool TryDecodeLzma(byte[] input, byte[] properties, ulong unpackSize, out byte[] output)
        {
            output = Array.Empty<byte>();
            if (input == null || input.Length == 0 || properties == null || properties.Length < 5)
            {
                return false;
            }

            int lc;
            int lp;
            int pb;
            if (!LzmaDecoder.TryParseProperties(properties, out lc, out lp, out pb))
            {
                return false;
            }

            uint dictSize = BitConverter.ToUInt32(properties, 1);
            if (dictSize == 0)
            {
                dictSize = 1;
            }

            using MemoryStream inputStream = new MemoryStream(input, writable: false);
            using MemoryStream outputStream = new MemoryStream();
            LzmaDecoder decoder = new LzmaDecoder();
            if (!decoder.SetDecoderProperties(lc, lp, pb, dictSize))
            {
                return false;
            }

            long outSize = unpackSize > 0 && unpackSize <= int.MaxValue ? (long)unpackSize : -1;
            if (!decoder.Decode(inputStream, outputStream, outSize))
            {
                return false;
            }

            output = outputStream.ToArray();
            return true;
        }

        public static bool TryDecodeLzma2(byte[] input, byte[] properties, ulong unpackSize, out byte[] output)
        {
            output = Array.Empty<byte>();
            if (input == null || input.Length == 0)
            {
                return false;
            }

            byte prop = properties != null && properties.Length > 0 ? properties[0] : (byte)0;
            uint dictSize = Lzma2Decoder.DecodeDictionarySize(prop);
            if (dictSize == 0)
            {
                dictSize = 1;
            }

            using MemoryStream inputStream = new MemoryStream(input, writable: false);
            using MemoryStream outputStream = new MemoryStream();
            Lzma2Decoder decoder = new Lzma2Decoder(dictSize);
            long outSize = unpackSize > 0 && unpackSize <= int.MaxValue ? (long)unpackSize : -1;
            if (!decoder.Decode(inputStream, outputStream, outSize))
            {
                return false;
            }

            output = outputStream.ToArray();
            return true;
        }

        private sealed class Lzma2Decoder
        {
            private readonly uint _dictSize;
            private LzmaDecoder _decoder;
            private byte _lzmaProps;
            private bool _propsInitialized;

            public Lzma2Decoder(uint dictSize)
            {
                _dictSize = dictSize;
                _decoder = new LzmaDecoder();
            }

            public static uint DecodeDictionarySize(byte prop)
            {
                if (prop > 40)
                {
                    return 0;
                }

                uint dictSize = (uint)(2 | (prop & 1));
                int shift = (prop / 2) + 11;
                dictSize <<= shift;
                return dictSize;
            }

            public bool Decode(Stream input, Stream output, long outSize)
            {
                long written = 0;
                while (outSize < 0 || written < outSize)
                {
                    int control = input.ReadByte();
                    if (control < 0)
                    {
                        return false;
                    }

                    if (control == 0x00)
                    {
                        return true;
                    }

                    if (control <= 0x02)
                    {
                        int sizeHigh = control - 1;
                        int sizeLow = ReadUInt16(input);
                        if (sizeLow < 0)
                        {
                            return false;
                        }
                        int chunkSize = (sizeHigh << 16) + sizeLow + 1;
                        if (control == 0x01)
                        {
                            _decoder = new LzmaDecoder();
                            _decoder.SetDecoderProperties(0, 0, 2, _dictSize);
                        }

                        if (!CopyBytes(input, output, chunkSize))
                        {
                            return false;
                        }

                        written += chunkSize;
                        continue;
                    }

                    bool resetDict = (control & 0x40) != 0;
                    bool resetState = (control & 0x20) != 0;
                    bool newProps = (control & 0x10) != 0;
                    int unpackLow = ReadUInt16(input);
                    int packLow = ReadUInt16(input);
                    if (unpackLow < 0 || packLow < 0)
                    {
                        return false;
                    }
                    int unpackSize = ((control & 0x1F) << 16) + unpackLow + 1;
                    int packSize = packLow + 1;

                    if (newProps)
                    {
                        int prop = input.ReadByte();
                        if (prop < 0)
                        {
                            return false;
                        }

                        int lc = prop % 9;
                        int lp = prop / 9;
                        int pb = 2;
                        _lzmaProps = (byte)(((pb * 5 + lp) * 9) + lc);
                        _propsInitialized = true;
                    }

                    if (!_propsInitialized)
                    {
                        int lc = 0;
                        int lp = 0;
                        int pb = 2;
                        _lzmaProps = (byte)(((pb * 5 + lp) * 9) + lc);
                        _propsInitialized = true;
                    }

                    if (resetDict || resetState)
                    {
                        _decoder = new LzmaDecoder();
                    }

                    if (!_decoder.SetDecoderProperties(_lzmaProps, _dictSize))
                    {
                        return false;
                    }

                    byte[] packed = ReadBytes(input, packSize);
                    using MemoryStream packedStream = new MemoryStream(packed, writable: false);
                    using MemoryStream tempOut = new MemoryStream();
                    if (!_decoder.Decode(packedStream, tempOut, unpackSize))
                    {
                        return false;
                    }

                    byte[] decoded = tempOut.ToArray();
                    output.Write(decoded, 0, decoded.Length);
                    written += decoded.Length;
                }

                return true;
            }

            private static int ReadUInt16(Stream stream)
            {
                int lo = stream.ReadByte();
                int hi = stream.ReadByte();
                if (lo < 0 || hi < 0)
                {
                    return -1;
                }

                return lo | (hi << 8);
            }
        }

        private sealed class LzmaDecoder
        {
            private const int kNumStates = 12;
            private const int kNumPosBitsMax = 4;
            private const int kNumPosStatesMax = 1 << kNumPosBitsMax;
            private const int kNumLenToPosStates = 4;
            private const int kNumAlignBits = 4;
            private const uint kStartPosModelIndex = 4;
            private const uint kEndPosModelIndex = 14;
            private const uint kNumFullDistances = 1 << (int)(kEndPosModelIndex / 2);
            private const int kMatchMinLen = 2;

            private readonly LzmaBitDecoder[] _isMatch = new LzmaBitDecoder[kNumStates << kNumPosBitsMax];
            private readonly LzmaBitDecoder[] _isRep = new LzmaBitDecoder[kNumStates];
            private readonly LzmaBitDecoder[] _isRepG0 = new LzmaBitDecoder[kNumStates];
            private readonly LzmaBitDecoder[] _isRepG1 = new LzmaBitDecoder[kNumStates];
            private readonly LzmaBitDecoder[] _isRepG2 = new LzmaBitDecoder[kNumStates];
            private readonly LzmaBitDecoder[] _isRep0Long = new LzmaBitDecoder[kNumStates << kNumPosBitsMax];
            private readonly LzmaBitTreeDecoder[] _posSlotDecoder = new LzmaBitTreeDecoder[kNumLenToPosStates];
            private readonly LzmaBitDecoder[] _posDecoders = new LzmaBitDecoder[kNumFullDistances - kEndPosModelIndex];
            private readonly LzmaBitTreeDecoder _posAlignDecoder = new LzmaBitTreeDecoder(kNumAlignBits);
            private readonly LzmaLenDecoder _lenDecoder = new LzmaLenDecoder();
            private readonly LzmaLenDecoder _repLenDecoder = new LzmaLenDecoder();
            private readonly LzmaLiteralDecoder _literalDecoder = new LzmaLiteralDecoder();
            private readonly LzmaOutWindow _outWindow = new LzmaOutWindow();
            private readonly LzmaRangeDecoder _rangeDecoder = new LzmaRangeDecoder();

            private int _posStateMask;
            private bool _propertiesSet;

            public static bool TryParseProperties(byte[] properties, out int lc, out int lp, out int pb)
            {
                lc = 0;
                lp = 0;
                pb = 0;
                if (properties == null || properties.Length < 1)
                {
                    return false;
                }

                byte prop = properties[0];
                lc = prop % 9;
                int remainder = prop / 9;
                lp = remainder % 5;
                pb = remainder / 5;
                return pb <= 4;
            }

            public bool SetDecoderProperties(byte prop, uint dictSize)
            {
                int lc;
                int lp;
                int pb;
                byte[] props = new byte[] { prop, 0, 0, 0, 0 };
                BitConverter.GetBytes(dictSize).CopyTo(props, 1);
                if (!TryParseProperties(props, out lc, out lp, out pb))
                {
                    return false;
                }

                return SetDecoderProperties(lc, lp, pb, dictSize);
            }

            public bool SetDecoderProperties(int lc, int lp, int pb, uint dictSize)
            {
                if (lc > 8 || lp > 4 || pb > 4)
                {
                    return false;
                }

                _literalDecoder.Create(lp, lc);
                uint posStates = (uint)(1 << pb);
                _lenDecoder.Create(posStates);
                _repLenDecoder.Create(posStates);
                _posStateMask = (int)posStates - 1;
                _outWindow.Create(dictSize);
                _propertiesSet = true;
                return true;
            }

            public bool Decode(Stream input, Stream output, long outSize)
            {
                if (!_propertiesSet)
                {
                    return false;
                }

                _rangeDecoder.Init(input);
                _outWindow.Init(output, solid: false);
                Init();

                uint state = 0;
                uint rep0 = 0;
                uint rep1 = 0;
                uint rep2 = 0;
                uint rep3 = 0;
                ulong nowPos = 0;
                byte prevByte = 0;

                while (outSize < 0 || nowPos < (ulong)outSize)
                {
                    uint posState = (uint)nowPos & (uint)_posStateMask;
                    if (_isMatch[(state << kNumPosBitsMax) + posState].Decode(_rangeDecoder) == 0)
                    {
                        byte b = _literalDecoder.Decode(_rangeDecoder, nowPos, prevByte, _outWindow.GetByte(0), state);
                        _outWindow.PutByte(b);
                        prevByte = b;
                        state = StateUpdateChar(state);
                        nowPos++;
                    }
                    else
                    {
                        uint len;
                        if (_isRep[state].Decode(_rangeDecoder) == 1)
                        {
                            if (_isRepG0[state].Decode(_rangeDecoder) == 0)
                            {
                                if (_isRep0Long[(state << kNumPosBitsMax) + posState].Decode(_rangeDecoder) == 0)
                                {
                                    state = StateUpdateShortRep(state);
                                    byte b = _outWindow.GetByte((int)rep0);
                                    _outWindow.PutByte(b);
                                    prevByte = b;
                                    nowPos++;
                                    continue;
                                }
                            }
                            else
                            {
                                uint dist;
                                if (_isRepG1[state].Decode(_rangeDecoder) == 0)
                                {
                                    dist = rep1;
                                }
                                else
                                {
                                    if (_isRepG2[state].Decode(_rangeDecoder) == 0)
                                    {
                                        dist = rep2;
                                    }
                                    else
                                    {
                                        dist = rep3;
                                        rep3 = rep2;
                                    }

                                    rep2 = rep1;
                                }

                                rep1 = rep0;
                                rep0 = dist;
                            }

                            len = _repLenDecoder.Decode(_rangeDecoder, posState) + kMatchMinLen;
                            state = StateUpdateRep(state);
                        }
                        else
                        {
                            rep3 = rep2;
                            rep2 = rep1;
                            rep1 = rep0;
                            len = _lenDecoder.Decode(_rangeDecoder, posState) + kMatchMinLen;
                            state = StateUpdateMatch(state);
                            uint posSlot = _posSlotDecoder[GetLenToPosState(len)].Decode(_rangeDecoder);
                            if (posSlot >= kStartPosModelIndex)
                            {
                                int numDirectBits = (int)((posSlot >> 1) - 1);
                                rep0 = (uint)((2 | (posSlot & 1)) << numDirectBits);
                                if (posSlot < kEndPosModelIndex)
                                {
                                    rep0 += LzmaBitTreeDecoder.ReverseDecode(_posDecoders, rep0 - posSlot - 1, _rangeDecoder, numDirectBits);
                                }
                                else
                                {
                                    rep0 += _rangeDecoder.DecodeDirectBits(numDirectBits - kNumAlignBits) << kNumAlignBits;
                                    rep0 += _posAlignDecoder.ReverseDecode(_rangeDecoder);
                                }
                            }
                            else
                            {
                                rep0 = posSlot;
                            }
                        }

                        if (rep0 >= _outWindow.GetTotalPos())
                        {
                            return false;
                        }

                        _outWindow.CopyBlock((int)rep0, (int)len);
                        nowPos += len;
                        prevByte = _outWindow.GetByte(0);
                    }
                }

                _outWindow.Flush();
                return true;
            }

            private void Init()
            {
                for (int i = 0; i < _isMatch.Length; i++)
                {
                    _isMatch[i].Init();
                }
                for (int i = 0; i < _isRep.Length; i++)
                {
                    _isRep[i].Init();
                    _isRepG0[i].Init();
                    _isRepG1[i].Init();
                    _isRepG2[i].Init();
                }
                for (int i = 0; i < _isRep0Long.Length; i++)
                {
                    _isRep0Long[i].Init();
                }
                for (int i = 0; i < _posDecoders.Length; i++)
                {
                    _posDecoders[i].Init();
                }
                for (int i = 0; i < kNumLenToPosStates; i++)
                {
                    _posSlotDecoder[i] = new LzmaBitTreeDecoder(6);
                }
                _lenDecoder.Init();
                _repLenDecoder.Init();
                _literalDecoder.Init();
            }

            private static uint StateUpdateChar(uint index) => index < 4 ? 0 : (index < 10 ? index - 3 : index - 6);
            private static uint StateUpdateMatch(uint index) => index < 7 ? 7u : 10u;
            private static uint StateUpdateRep(uint index) => index < 7 ? 8u : 11u;
            private static uint StateUpdateShortRep(uint index) => index < 7 ? 9u : 11u;
            private static uint GetLenToPosState(uint len)
            {
                len -= kMatchMinLen;
                if (len < kNumLenToPosStates)
                {
                    return len;
                }

                return kNumLenToPosStates - 1;
            }
        }

        private struct LzmaBitDecoder
        {
            private const int kNumBitModelTotalBits = 11;
            private const uint kBitModelTotal = 1u << kNumBitModelTotalBits;
            private const int kNumMoveBits = 5;
            private uint _prob;

            public void Init()
            {
                _prob = kBitModelTotal >> 1;
            }

            public uint Decode(LzmaRangeDecoder rangeDecoder)
            {
                uint bound = (rangeDecoder.Range >> kNumBitModelTotalBits) * _prob;
                if (rangeDecoder.Code < bound)
                {
                    rangeDecoder.Range = bound;
                    _prob += (kBitModelTotal - _prob) >> kNumMoveBits;
                    if (rangeDecoder.Range < LzmaRangeDecoder.kTopValue)
                    {
                        rangeDecoder.Code = (rangeDecoder.Code << 8) | (byte)rangeDecoder.ReadByte();
                        rangeDecoder.Range <<= 8;
                    }
                    return 0;
                }

                rangeDecoder.Range -= bound;
                rangeDecoder.Code -= bound;
                _prob -= _prob >> kNumMoveBits;
                if (rangeDecoder.Range < LzmaRangeDecoder.kTopValue)
                {
                    rangeDecoder.Code = (rangeDecoder.Code << 8) | (byte)rangeDecoder.ReadByte();
                    rangeDecoder.Range <<= 8;
                }
                return 1;
            }
        }

        private sealed class LzmaRangeDecoder
        {
            public const uint kTopValue = 1u << 24;
            private Stream _stream;
            public uint Range { get; set; }
            public uint Code { get; set; }

            public void Init(Stream stream)
            {
                _stream = stream;
                Code = 0;
                Range = 0xFFFFFFFF;
                for (int i = 0; i < 5; i++)
                {
                    Code = (Code << 8) | (byte)ReadByte();
                }
            }

            public int ReadByte()
            {
                int value = _stream.ReadByte();
                return value < 0 ? 0 : value;
            }

            public uint DecodeDirectBits(int numTotalBits)
            {
                uint result = 0;
                for (int i = numTotalBits; i > 0; i--)
                {
                    Range >>= 1;
                    uint t = (Code - Range) >> 31;
                    Code -= Range & (t - 1);
                    result = (result << 1) | (1 - t);
                    if (Range < kTopValue)
                    {
                        Code = (Code << 8) | (byte)ReadByte();
                        Range <<= 8;
                    }
                }
                return result;
            }
        }

        private sealed class LzmaBitTreeDecoder
        {
            private readonly LzmaBitDecoder[] _models;
            private readonly int _numBitLevels;

            public LzmaBitTreeDecoder(int numBitLevels)
            {
                _numBitLevels = numBitLevels;
                _models = new LzmaBitDecoder[1 << numBitLevels];
            }

            public void Init()
            {
                for (int i = 1; i < _models.Length; i++)
                {
                    _models[i].Init();
                }
            }

            public uint Decode(LzmaRangeDecoder rangeDecoder)
            {
                uint m = 1;
                for (int i = _numBitLevels; i > 0; i--)
                {
                    m = (m << 1) + _models[m].Decode(rangeDecoder);
                }
                return m - ((uint)1 << _numBitLevels);
            }

            public uint ReverseDecode(LzmaRangeDecoder rangeDecoder)
            {
                return ReverseDecode(_models, 0, rangeDecoder, _numBitLevels);
            }

            public static uint ReverseDecode(LzmaBitDecoder[] models, uint startIndex, LzmaRangeDecoder rangeDecoder, int numBitLevels)
            {
                uint m = 1;
                uint symbol = 0;
                for (int i = 0; i < numBitLevels; i++)
                {
                    uint bit = models[startIndex + m].Decode(rangeDecoder);
                    m = (m << 1) + bit;
                    symbol |= bit << i;
                }
                return symbol;
            }
        }

        private sealed class LzmaLenDecoder
        {
            private readonly LzmaBitDecoder _choice = new LzmaBitDecoder();
            private readonly LzmaBitDecoder _choice2 = new LzmaBitDecoder();
            private LzmaBitTreeDecoder[] _lowCoder = Array.Empty<LzmaBitTreeDecoder>();
            private LzmaBitTreeDecoder[] _midCoder = Array.Empty<LzmaBitTreeDecoder>();
            private readonly LzmaBitTreeDecoder _highCoder = new LzmaBitTreeDecoder(8);
            private uint _numPosStates;

            public void Create(uint numPosStates)
            {
                if (_numPosStates == numPosStates)
                {
                    return;
                }

                _numPosStates = numPosStates;
                _lowCoder = new LzmaBitTreeDecoder[numPosStates];
                _midCoder = new LzmaBitTreeDecoder[numPosStates];
                for (uint i = 0; i < numPosStates; i++)
                {
                    _lowCoder[i] = new LzmaBitTreeDecoder(3);
                    _midCoder[i] = new LzmaBitTreeDecoder(3);
                }
            }

            public void Init()
            {
                _choice.Init();
                _choice2.Init();
                for (uint i = 0; i < _numPosStates; i++)
                {
                    _lowCoder[i].Init();
                    _midCoder[i].Init();
                }
                _highCoder.Init();
            }

            public uint Decode(LzmaRangeDecoder rangeDecoder, uint posState)
            {
                if (_choice.Decode(rangeDecoder) == 0)
                {
                    return _lowCoder[posState].Decode(rangeDecoder);
                }
                uint symbol = 8;
                if (_choice2.Decode(rangeDecoder) == 0)
                {
                    symbol += _midCoder[posState].Decode(rangeDecoder);
                }
                else
                {
                    symbol += 8 + _highCoder.Decode(rangeDecoder);
                }
                return symbol;
            }
        }

        private sealed class LzmaLiteralDecoder
        {
            private Decoder2[] _coders = Array.Empty<Decoder2>();
            private int _numPrevBits;
            private int _numPosBits;
            private uint _posMask;

            public void Create(int numPosBits, int numPrevBits)
            {
                if (_coders.Length != (1 << (numPosBits + numPrevBits)))
                {
                    _coders = new Decoder2[1 << (numPosBits + numPrevBits)];
                }
                _numPosBits = numPosBits;
                _posMask = (uint)((1 << numPosBits) - 1);
                _numPrevBits = numPrevBits;
            }

            public void Init()
            {
                uint numStates = (uint)1 << (_numPrevBits + _numPosBits);
                for (uint i = 0; i < numStates; i++)
                {
                    _coders[i].Init();
                }
            }

            public byte Decode(LzmaRangeDecoder rangeDecoder, ulong pos, byte prevByte, byte matchByte, uint state)
            {
                uint index = ((uint)pos & _posMask) << _numPrevBits;
                index += (uint)(prevByte >> (8 - _numPrevBits));
                return state < 7
                    ? _coders[index].DecodeNormal(rangeDecoder)
                    : _coders[index].DecodeWithMatchByte(rangeDecoder, matchByte);
            }

            private struct Decoder2
            {
                private LzmaBitDecoder[] _decoders;

                public void Init()
                {
                    if (_decoders == null || _decoders.Length != 0x300)
                    {
                        _decoders = new LzmaBitDecoder[0x300];
                    }

                    for (int i = 0; i < _decoders.Length; i++)
                    {
                        _decoders[i].Init();
                    }
                }

                public byte DecodeNormal(LzmaRangeDecoder rangeDecoder)
                {
                    uint symbol = 1;
                    while (symbol < 0x100)
                    {
                        symbol = (symbol << 1) | _decoders[symbol].Decode(rangeDecoder);
                    }
                    return (byte)symbol;
                }

                public byte DecodeWithMatchByte(LzmaRangeDecoder rangeDecoder, byte matchByte)
                {
                    uint symbol = 1;
                    do
                    {
                        uint matchBit = (uint)(matchByte >> 7) & 1;
                        matchByte <<= 1;
                        uint bit = _decoders[((1 + matchBit) << 8) + symbol].Decode(rangeDecoder);
                        symbol = (symbol << 1) | bit;
                        if (matchBit != bit)
                        {
                            while (symbol < 0x100)
                            {
                                symbol = (symbol << 1) | _decoders[symbol].Decode(rangeDecoder);
                            }
                            break;
                        }
                    }
                    while (symbol < 0x100);
                    return (byte)symbol;
                }
            }
        }

        private sealed class LzmaOutWindow
        {
            private byte[] _buffer = Array.Empty<byte>();
            private int _pos;
            private int _windowSize;
            private int _streamPos;
            private Stream _stream;
            private uint _totalPos;

            public void Create(uint windowSize)
            {
                if (_windowSize != windowSize)
                {
                    _buffer = new byte[windowSize];
                }
                _windowSize = (int)windowSize;
                _pos = 0;
                _streamPos = 0;
            }

            public void Init(Stream stream, bool solid)
            {
                _stream = stream;
                if (!solid)
                {
                    _pos = 0;
                    _streamPos = 0;
                    _totalPos = 0;
                }
            }

            public void Flush()
            {
                int size = _pos - _streamPos;
                if (size <= 0)
                {
                    return;
                }

                _stream.Write(_buffer, _streamPos, size);
                if (_pos >= _windowSize)
                {
                    _pos = 0;
                }
                _streamPos = _pos;
            }

            public void PutByte(byte b)
            {
                _buffer[_pos++] = b;
                _totalPos++;
                if (_pos >= _windowSize)
                {
                    Flush();
                }
            }

            public byte GetByte(int distance)
            {
                int pos = _pos - distance - 1;
                if (pos < 0)
                {
                    pos += _windowSize;
                }
                return _buffer[pos];
            }

            public void CopyBlock(int distance, int len)
            {
                for (int i = 0; i < len; i++)
                {
                    PutByte(GetByte(distance));
                }
            }

            public uint GetTotalPos()
            {
                return _totalPos;
            }
        }

        private static bool CopyBytes(Stream input, Stream output, int count)
        {
            byte[] buffer = new byte[Math.Min(count, 4096)];
            int remaining = count;
            while (remaining > 0)
            {
                int read = input.Read(buffer, 0, Math.Min(buffer.Length, remaining));
                if (read <= 0)
                {
                    return false;
                }

                output.Write(buffer, 0, read);
                remaining -= read;
            }

            return true;
        }

        private static byte[] ReadBytes(Stream stream, int count)
        {
            byte[] buffer = new byte[count];
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = stream.Read(buffer, totalRead, count - totalRead);
                if (read <= 0)
                {
                    break;
                }
                totalRead += read;
            }

            if (totalRead == count)
            {
                return buffer;
            }

            byte[] trimmed = new byte[totalRead];
            Array.Copy(buffer, trimmed, totalRead);
            return trimmed;
        }
    }
}
