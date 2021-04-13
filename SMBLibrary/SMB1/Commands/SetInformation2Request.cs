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
    /// SMB_COM_SET_INFORMATION2 Request
    /// </summary>
    public class SetInformation2Request : SMB1Command
    {
        public const int ParametersLength = 14;
        // Parameters:
        public ushort FID;
        public DateTime? CreationDateTime;   // A date and time value of 0 indicates to the server that the values MUST NOT be changed
        public DateTime? LastAccessDateTime; // A date and time value of 0 indicates to the server that the values MUST NOT be changed
        public DateTime? LastWriteDateTime;  // A date and time value of 0 indicates to the server that the values MUST NOT be changed

        public override SMB1Command Init()
        {
            FID = default;
            CreationDateTime = default;   
            LastAccessDateTime = default; 
            LastWriteDateTime = default;
            return this;
        }

        public SetInformation2Request Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            CreationDateTime = SMB1Helper.ReadNullableSMBDateTime(SmbParameters.Memory.Span, 2);
            LastAccessDateTime = SMB1Helper.ReadNullableSMBDateTime(SmbParameters.Memory.Span, 6);
            LastWriteDateTime = SMB1Helper.ReadNullableSMBDateTime(SmbParameters.Memory.Span, 10);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, FID);
            SMB1Helper.WriteSMBDateTime(SmbParameters.Memory.Span, 2, CreationDateTime);
            SMB1Helper.WriteSMBDateTime(SmbParameters.Memory.Span, 6, LastAccessDateTime);
            SMB1Helper.WriteSMBDateTime(SmbParameters.Memory.Span, 10, LastWriteDateTime);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_SET_INFORMATION2;
    }
}
