using System.Diagnostics;
using DevTools.Samba.Metrics.Config;
using DevTools.Samba.Metrics.Helpers;
using SMBLibrary.Client;
using SMBLibrary.NetBios;
using SMBLibrary.SMB1;

namespace SMBLibrary.Metrics
{
	public class Smb1ClientWithMetrics : SMB1Client
	{
		private static readonly DiagnosticSource SambaMetricsSource =
				new DiagnosticListener(SambaMetricsConstants.Samba1MetricsListenerName);

		public Smb1ClientWithMetrics(ISmbLibraryInternalObjectsFactory factory) : base(factory)
		{

		}

		protected override void ProcessPacket(SessionPacketBase packet, ConnectionState state)
		{
			SambaMetricsSource.WriteCount(SambaMetricsConstants.EventNames.IncomingTraffic, packet.Length);

			base.ProcessPacket(packet, state);
		}

		protected override void TrySendPacket(SessionPacketBase packet)
		{
			SambaMetricsSource.WriteCount(SambaMetricsConstants.EventNames.OutgoingTraffic, packet.Length);

			base.TrySendPacket(packet);
		}

		internal override SMB1Message WaitForCommand(CommandName commandName, Stopwatch stopwatch, int timeOut)
		{
			SMB1Message message = base.WaitForCommand(commandName, stopwatch, timeOut);

			double elapsed = stopwatch.ElapsedNanoseconds();
			SambaMetricsSource.WriteTime(SambaMetricsConstants.EventNames.ResponseDelay, elapsed);

			NTStatus messageStatus = message.Header.Status;
			if (messageStatus != NTStatus.STATUS_SUCCESS)
			{
				string errorName = messageStatus.ToString();
				SambaMetricsSource.WriteError(SambaMetricsConstants.EventNames.Error, errorName);
			}

			return message;
		}
	}
}