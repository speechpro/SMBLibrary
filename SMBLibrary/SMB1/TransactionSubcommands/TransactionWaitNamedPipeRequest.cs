/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using DevTools.MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_WAIT_NMPIPE Request
    /// </summary>
    public class TransactionWaitNamedPipeRequest : TransactionSubcommand
    {
        // Setup:
        public ushort Priority;

        public TransactionWaitNamedPipeRequest()
        {
        }

        public TransactionWaitNamedPipeRequest(Span<byte> setup)
        {
            Priority = LittleEndianConverter.ToUInt16(setup, 2);
        }

        public override IMemoryOwner<byte> GetSetup()
        {
            var setup = Arrays.Rent(4);
            LittleEndianWriter.WriteUInt16(setup, 0, (ushort)SubcommandName);
            LittleEndianWriter.WriteUInt16(setup, 2, Priority);
            return setup;
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_WAIT_NMPIPE;
    }
}
