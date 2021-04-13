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
    /// SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO
    /// </summary>
    public class FindFileIDBothDirectoryInfo : FindInformation
    {
        public const int FixedLength = 104;

        // uint NextEntryOffset;
        public uint FileIndex; // SHOULD be set to zero when sent in a response and SHOULD be ignored when received by the client
        public DateTime? CreationTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? LastChangeTime;
        public long EndOfFile;
        public long AllocationSize;
        public ExtendedFileAttributes ExtFileAttributes;
        //uint FileNameLength; // In bytes, MUST exclude the null termination.
        public uint EASize;
        //byte ShortNameLength; // In bytes
        public byte Reserved;
        public IMemoryOwner<char> ShortName; // 24 bytes, 8.3 name of the file in Unicode format
        public ushort Reserved2;
        public ulong FileID;
        public IMemoryOwner<char> FileName; // OEM / Unicode character array. MUST be written as SMB_STRING, and read as fixed length string.
        // Omitting the NULL termination from the FileName field in a single SMB_FIND_FILE_BOTH_DIRECTORY_INFO structure
        // (as a response to TRANS2_QUERY_PATH_INFORMATION on a single directory)
        // Will, in some rare but repeatable cases, cause issues with Windows XP SP3 as a client
        // (the client will display an error message that the folder "refers to a location that is unavailable"...)

        public FindFileIDBothDirectoryInfo()
        {
        }

        public FindFileIDBothDirectoryInfo(Span<byte> buffer, int offset, bool isUnicode)
        {
            NextEntryOffset = LittleEndianReader.ReadUInt32(buffer, ref offset);
            FileIndex = LittleEndianReader.ReadUInt32(buffer, ref offset);
            CreationTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastChangeTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            EndOfFile = LittleEndianReader.ReadInt64(buffer, ref offset);
            AllocationSize = LittleEndianReader.ReadInt64(buffer, ref offset);
            ExtFileAttributes = LittleEndianReader.ReadUInt32(buffer, ref offset);
            var fileNameLength = LittleEndianReader.ReadUInt32(buffer, ref offset);
            EASize = LittleEndianReader.ReadUInt32(buffer, ref offset);
            var shortNameLength = ByteReader.ReadByte(buffer, ref offset);
            Reserved = ByteReader.ReadByte(buffer, ref offset);
            using var shortName = Arrays.Rent<char>(12);
            Reserved2 = LittleEndianReader.ReadUInt16(buffer, ref offset);
            FileID = LittleEndianReader.ReadUInt64(buffer, ref offset);
            FileName = Arrays.Rent<char>((int)fileNameLength);
                
            SMB1Helper.ReadFixedLengthString(FileName.Memory.Span, buffer, ref offset, isUnicode, (int)fileNameLength);
            
            ByteReader.ReadUTF16String(ShortName.Memory.Span, buffer, ref offset, 12);
            ShortName = shortName.Slice(0, shortNameLength);
        }

        public override void WriteBytes(Span<byte> buffer, ref int offset, bool isUnicode)
        {
            var fileNameLength = (uint)(isUnicode ? FileName.Memory.Length * 2 : FileName.Memory.Length);
            var shortNameLength = (byte)(ShortName.Memory.Length * 2);

            LittleEndianWriter.WriteUInt32(buffer, ref offset, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, FileIndex);
            FileTimeHelper.WriteFileTime(buffer, ref offset, CreationTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastAccessTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastWriteTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastChangeTime);
            LittleEndianWriter.WriteInt64(buffer, ref offset, EndOfFile);
            LittleEndianWriter.WriteInt64(buffer, ref offset, AllocationSize);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, fileNameLength);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, EASize);
            BufferWriter.WriteByte(buffer, ref offset, shortNameLength);
            BufferWriter.WriteByte(buffer, ref offset, Reserved);
            BufferWriter.WriteUTF16String(buffer, ref offset, ShortName.Memory.Span, 12);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, Reserved2);
            LittleEndianWriter.WriteUInt64(buffer, ref offset, FileID);
            SMB1Helper.WriteSMBString(buffer, ref offset, isUnicode, FileName.Memory.Span);
        }

        public override int GetLength(bool isUnicode)
        {
            var length = FixedLength;

            if (isUnicode)
            {
                length += FileName.Memory.Length * 2 + 2;
            }
            else
            {
                length += FileName.Memory.Length + 1;
            }
            return length;
        }

        public override FindInformationLevel InformationLevel => FindInformationLevel.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO;
    }
}
