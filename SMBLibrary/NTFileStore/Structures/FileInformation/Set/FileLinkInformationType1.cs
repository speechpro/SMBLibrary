/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using DevTools.MemoryPools.Memory;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.21.1 - FileLinkInformation Type 1
    /// </summary>
    /// <remarks>
    /// [MS-FSA] 2.1.5.14.6
    /// FILE_LINK_INFORMATION_TYPE_1: Used for 32-bit local clients and the SMB1 protocol.
    /// FILE_LINK_INFORMATION_TYPE_2: Used for 64-bit local clients and the SMB2 protocol.
    /// </remarks>
    public class FileLinkInformationType1 : FileInformation
    {
        public const int FixedLength = 12;

        public bool ReplaceIfExists;
        // 3 reserved bytes
        public uint RootDirectory;
        private uint FileNameLength;
        public IMemoryOwner<char> FileName = MemoryOwner<char>.Empty;

        public FileLinkInformationType1()
        {
        }

        public FileLinkInformationType1(Span<byte> buffer, int offset)
        {
            ReplaceIfExists = Conversion.ToBoolean(ByteReader.ReadByte(buffer, offset + 0));
            RootDirectory = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileName = Arrays.Rent<char>((int) FileNameLength / 2);
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, offset + 12, (int)FileNameLength / 2);
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            FileNameLength = (uint)(FileName.Memory.Length * 2);
            BufferWriter.WriteByte(buffer, offset + 0, Convert.ToByte(ReplaceIfExists));
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, RootDirectory);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, FileNameLength);
            BufferWriter.WriteUTF16String(buffer, offset + 12, FileName.Memory.Span);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileLinkInformation;

        public override int Length => FixedLength + FileName.Memory.Length * 2;
    }
}
