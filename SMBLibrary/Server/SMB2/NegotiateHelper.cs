/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using MemoryPools.Memory;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.NetBios;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;
using Utilities;
using Capabilities = SMBLibrary.SMB2.Capabilities;
using ErrorResponse = SMBLibrary.SMB2.ErrorResponse;
using NegotiateRequest = SMBLibrary.SMB2.NegotiateRequest;
using NegotiateResponse = SMBLibrary.SMB2.NegotiateResponse;
using SecurityMode = SMBLibrary.SMB2.SecurityMode;

namespace SMBLibrary.Server.SMB2
{
    /// <summary>
    /// Negotiate helper
    /// </summary>
    internal class NegotiateHelper
    {
        public const string SMB2002Dialect = "SMB 2.002";
        public const string SMB2xxxDialect = "SMB 2.???";
        public const uint ServerMaxTransactSize = 65536;
        public const uint ServerMaxReadSize = 65536;
        public const uint ServerMaxWriteSize = 65536;
        public const uint ServerMaxTransactSizeLargeMTU = 1048576;
        public const uint ServerMaxReadSizeLargeMTU = 1048576;
        public const uint ServerMaxWriteSizeLargeMTU = 1048576;

        // Special case - SMB2 client initially connecting using SMB1
        internal static SMB2Command GetNegotiateResponse(List<string> smb2Dialects, GSSProvider securityProvider, ConnectionState state, SMBTransportType transportType, Guid serverGuid, DateTime serverStartTime)
        {
            var response = new NegotiateResponse();
            response.Header.Credits = 1;

            if (smb2Dialects.Contains(SMB2xxxDialect))
            {
                response.DialectRevision = SMB2Dialect.SMB2xx;
            }
            else if (smb2Dialects.Contains(SMB2002Dialect))
            {
                state.Dialect = SMBDialect.SMB202;
                response.DialectRevision = SMB2Dialect.SMB202;
            }
            else
            {
                throw new ArgumentException("SMB2 dialect is not present");
            }
            response.SecurityMode = SecurityMode.SigningEnabled;
            response.ServerGuid = serverGuid;
            if (state.Dialect != SMBDialect.SMB202 && transportType == SMBTransportType.DirectTCPTransport)
            {
                response.Capabilities = Capabilities.LargeMTU;
                response.MaxTransactSize = ServerMaxTransactSizeLargeMTU;
                response.MaxReadSize = ServerMaxReadSizeLargeMTU;
                response.MaxWriteSize = ServerMaxWriteSizeLargeMTU;
                // [MS-SMB2] 3.3.5.2 Receiving Any Message - If the length of the message exceeds Connection.MaxTransactSize + 256, the server MUST disconnect the connection.
                var maxPacketSize = SessionPacketBase.HeaderLength + (int)ServerMaxTransactSizeLargeMTU + 256;
                if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                {
                    state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                }
            }
            else
            {
                response.MaxTransactSize = ServerMaxTransactSize;
                response.MaxReadSize = ServerMaxReadSize;
                response.MaxWriteSize = ServerMaxWriteSize;
            }
            response.SystemTime = DateTime.Now;
            response.ServerStartTime = serverStartTime;
            response.SecurityBuffer = securityProvider.GetSPNEGOTokenInitBytes();
            return response;
        }

        internal static SMB2Command GetNegotiateResponse(NegotiateRequest request, GSSProvider securityProvider, ConnectionState state, SMBTransportType transportType, Guid serverGuid, DateTime serverStartTime)
        {
            var response = new NegotiateResponse();
            if (request.Dialects.Contains(SMB2Dialect.SMB210))
            {
                state.Dialect = SMBDialect.SMB210;
                response.DialectRevision = SMB2Dialect.SMB210;
            }
            else if (request.Dialects.Contains(SMB2Dialect.SMB202))
            {
                state.Dialect = SMBDialect.SMB202;
                response.DialectRevision = SMB2Dialect.SMB202;
            }
            else
            {
                state.LogToServer(Severity.Verbose, "Negotiate failure: None of the requested SMB2 dialects is supported");
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_NOT_SUPPORTED);
            }
            response.SecurityMode = SecurityMode.SigningEnabled;
            response.ServerGuid = serverGuid;
            if (state.Dialect != SMBDialect.SMB202 && transportType == SMBTransportType.DirectTCPTransport)
            {
                response.Capabilities = Capabilities.LargeMTU;
                response.MaxTransactSize = ServerMaxTransactSizeLargeMTU;
                response.MaxReadSize = ServerMaxReadSizeLargeMTU;
                response.MaxWriteSize = ServerMaxWriteSizeLargeMTU;
                // [MS-SMB2] 3.3.5.2 Receiving Any Message - If the length of the message exceeds Connection.MaxTransactSize + 256, the server MUST disconnect the connection.
                var maxPacketSize = SessionPacketBase.HeaderLength + (int)ServerMaxTransactSizeLargeMTU + 256;
                if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                {
                    state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                }
            }
            else
            {
                response.MaxTransactSize = ServerMaxTransactSize;
                response.MaxReadSize = ServerMaxReadSize;
                response.MaxWriteSize = ServerMaxWriteSize;
            }
            response.SystemTime = DateTime.Now;
            response.ServerStartTime = serverStartTime;
            response.SecurityBuffer = securityProvider.GetSPNEGOTokenInitBytes();
            return response;
        }

        internal static List<string> FindSMB2Dialects(SMB1Message message)
        {
            if (message.Commands.Count > 0 && message.Commands[0] is SMBLibrary.SMB1.NegotiateRequest)
            {
                var request = (SMBLibrary.SMB1.NegotiateRequest)message.Commands[0];
                return FindSMB2Dialects(request);
            }
            return new List<string>();
        }

        internal static List<string> FindSMB2Dialects(SMBLibrary.SMB1.NegotiateRequest request)
        {
            var result = new List<string>();
            if (request.Dialects.Contains(SMB2002Dialect))
            {
                result.Add(SMB2002Dialect);
            }
            if (request.Dialects.Contains(SMB2xxxDialect))
            {
                result.Add(SMB2xxxDialect);
            }
            return result;
        }
    }
}
