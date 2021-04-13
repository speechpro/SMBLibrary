/* Copyright (C) 2017-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using DevTools.MemoryPools.Memory;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    /// <summary>
    /// Session Setup helper
    /// </summary>
    internal class SessionSetupHelper
    {
        internal static SMB2Command GetSessionSetupResponse(SessionSetupRequest request, GSSProvider securityProvider, SMB2ConnectionState state)
        {
            // [MS-SMB2] Windows [..] will also accept raw Kerberos messages and implicit NTLM messages as part of GSS authentication.
            var response = ObjectsPool<SessionSetupResponse>.Get().Init();
            IMemoryOwner<byte> outputToken;
            var status = securityProvider.AcceptSecurityContext(ref state.AuthenticationContext, request.SecurityBuffer.Memory.Span, out outputToken);
            if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.SEC_I_CONTINUE_NEEDED)
            {
                var userName = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.UserName) as string;
                var domainName = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.DomainName) as string;
                var machineName = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.MachineName) as string;
                var osVersion = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.OSVersion) as string;
                state.LogToServer(Severity.Information, "Session Setup: User '{0}' failed authentication (Domain: '{1}', Workstation: '{2}', OS version: '{3}'), NTStatus: {4}", userName, domainName, machineName, osVersion, status);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, status);
            }

            if (outputToken != null)
            {
                response.SecurityBuffer = outputToken;
            }

            // According to [MS-SMB2] 3.3.5.5.3, response.Header.SessionID must be allocated if the server returns STATUS_MORE_PROCESSING_REQUIRED
            if (request.Header.SessionId == 0)
            {
                var sessionID = state.AllocateSessionID();
                if (!sessionID.HasValue)
                {
                    return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_TOO_MANY_SESSIONS);
                }
                response.Header.SessionId = sessionID.Value;
            }

            if (status == NTStatus.SEC_I_CONTINUE_NEEDED)
            {
                response.Header.Status = NTStatus.STATUS_MORE_PROCESSING_REQUIRED;
            }
            else // status == STATUS_SUCCESS
            {
                var userName = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.UserName) as string;
                var domainName = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.DomainName) as string;
                var machineName = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.MachineName) as string;
                var osVersion = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.OSVersion) as string;
                var sessionKey = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.SessionKey) as byte[];
                var accessToken = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.AccessToken);
                var isGuest = securityProvider.GetContextAttribute(state.AuthenticationContext, GSSAttributeName.IsGuest) as bool?;
                if (!isGuest.HasValue || !isGuest.Value)
                {
                    state.LogToServer(Severity.Information, "Session Setup: User '{0}' authenticated successfully (Domain: '{1}', Workstation: '{2}', OS version: '{3}').", userName, domainName, machineName, osVersion);
                    var signingRequired = (request.SecurityMode & SecurityMode.SigningRequired) > 0;
                    state.CreateSession(request.Header.SessionId, userName, machineName, sessionKey, accessToken, signingRequired);
                }
                else
                {
                    state.LogToServer(Severity.Information, "Session Setup: User '{0}' failed authentication (Domain: '{1}', Workstation: '{2}', OS version: '{3}'), logged in as guest.", userName, domainName, machineName, osVersion);
                    state.CreateSession(request.Header.SessionId, "Guest", machineName, sessionKey, accessToken, false);
                    response.SessionFlags = SessionFlags.IsGuest;
                }
            }
            return response;
        }
    }
}
