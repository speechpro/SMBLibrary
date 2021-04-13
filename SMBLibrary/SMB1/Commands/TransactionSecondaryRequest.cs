/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_TRANSACTION_SECONDARY Request
    /// </summary>
    public class TransactionSecondaryRequest : SMB1Command
    {
        public const int SMBParametersLength = 16;
        // Parameters:
        public ushort TotalParameterCount;
        public ushort TotalDataCount;
        protected ushort ParameterCount;
        protected ushort ParameterOffset;
        public ushort ParameterDisplacement;
        protected ushort DataCount;
        protected ushort DataOffset;
        public ushort DataDisplacement;
        // Data:
        // Padding (alignment to 4 byte boundary)
        public byte[] TransParameters; // Trans_Parameters
        // Padding (alignment to 4 byte boundary)
        public byte[] TransData; // Trans_Data

        public override SMB1Command Init()
        {
            base.Init();
            TotalParameterCount = default;
            TotalDataCount = default;
            ParameterCount = default;
            ParameterOffset = default;
            ParameterDisplacement = default;
            DataCount = default;
            DataOffset = default;
            DataDisplacement = default;
            return this;
        }

        public virtual SMB1Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            TotalParameterCount = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 0);
            TotalDataCount = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 2);
            ParameterCount = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 4);
            ParameterOffset = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 6);
            ParameterDisplacement = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 8);
            DataCount = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 10);
            DataOffset = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 12);
            DataDisplacement = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 14);

            TransParameters = ByteReader.ReadBytes_RentArray(buffer, ParameterOffset, ParameterCount);
            TransData = ByteReader.ReadBytes_RentArray(buffer, DataOffset, DataCount);
            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            ParameterCount = (ushort)TransParameters.Length;
            DataCount = (ushort)TransData.Length;

            // WordCount + ByteCount are additional 3 bytes
            ParameterOffset = SMB1Header.Length + 3 + SMBParametersLength;
            var padding1 = (4 - (ParameterOffset % 4)) % 4;
            ParameterOffset += (ushort)padding1;
            DataOffset = (ushort)(ParameterOffset + ParameterCount);
            var padding2 = (4 - (DataOffset % 4)) % 4;
            DataOffset += (ushort)padding2;

            SmbParameters = Arrays.Rent(SMBParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, TotalParameterCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 2, TotalDataCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, ParameterCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, ParameterOffset);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 8, ParameterDisplacement);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 10, DataCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 12, DataOffset);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 14, DataDisplacement);

            SmbData = Arrays.Rent(ParameterCount + DataCount + padding1 + padding2);
            BufferWriter.WriteBytes(SmbData.Memory.Span, padding1, TransParameters);
            BufferWriter.WriteBytes(SmbData.Memory.Span, padding1 + ParameterCount + padding2, TransData);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_TRANSACTION_SECONDARY;
    }
}
