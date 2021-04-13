/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using DevTools.MemoryPools.Memory;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_LOGOFF_ANDX Response
    /// </summary>
    public class LogoffAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 4;

        public LogoffAndXResponse Init()
        {
            base.Init();

            return this;
        }

        public LogoffAndXResponse Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_LOGOFF_ANDX;
    }
}
