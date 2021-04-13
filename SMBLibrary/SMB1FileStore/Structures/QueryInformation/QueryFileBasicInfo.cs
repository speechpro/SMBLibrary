/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB_QUERY_FILE_BASIC_INFO
    /// </summary>
    public class QueryFileBasicInfo : QueryInformation
    {
        public const int Length = 40;

        public DateTime? CreationTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? LastChangeTime;
        public ExtendedFileAttributes ExtFileAttributes;
        public uint Reserved;

        public QueryFileBasicInfo()
        {
        }

        public QueryFileBasicInfo(Span<byte> buffer, int offset)
        {
            CreationTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastChangeTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            ExtFileAttributes = LittleEndianReader.ReadUInt32(buffer, ref offset);
            Reserved = LittleEndianReader.ReadUInt32(buffer, ref offset);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            var offset = 0;
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, CreationTime);
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, LastAccessTime);
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, LastWriteTime);
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, LastChangeTime);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, Reserved);
            return buffer;
        }

        public override QueryInformationLevel InformationLevel => QueryInformationLevel.SMB_QUERY_FILE_BASIC_INFO;
    }
}
