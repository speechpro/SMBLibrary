using System.Diagnostics;
using System.Net.Sockets;
using System.Threading.Tasks;
using DevTools.Samba.Metrics.Config;
using DevTools.Samba.Metrics.Helpers;
using SMBLibrary.Client;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;

namespace SMBLibrary.Metrics
{
	public class Smb2ClientWithMetrics : Smb2Client
	{
		private static readonly DiagnosticSource SambaMetricsSource =
				new DiagnosticListener(SambaMetricsConstants.Samba2MetricsListenerName);

		public Smb2ClientWithMetrics(ISmbLibraryInternalObjectsFactory factory) : base(factory)
		{

		}

		protected override void ProcessPacket(SessionPacketBase packet, ConnectionState state)
		{
			SambaMetricsSource.WriteCount(SambaMetricsConstants.EventNames.IncomingTraffic, packet.Length);

			base.ProcessPacket(packet, state);
		}

		public override void TrySendPacket(Socket socket, SessionPacketBase packet)
		{
			SambaMetricsSource.WriteCount(SambaMetricsConstants.EventNames.OutgoingTraffic, packet.Length);

			base.TrySendPacket(socket, packet);
		}

		internal override SMB2Command WaitForCommand(SMB2CommandName commandName, Stopwatch stopwatch, int timeOut)
		{
			SMB2Command command = base.WaitForCommand(commandName, stopwatch, timeOut);

			NTStatus commandStatus = command.Header.Status;

			WriteCommandMetrics(commandStatus, stopwatch);

			return command;
		}

		private void WriteCommandMetrics(NTStatus commandStatus, Stopwatch stopwatch)
		{
			double elapsed = stopwatch.ElapsedNanoseconds();
			SambaMetricsSource.WriteTime(SambaMetricsConstants.EventNames.ResponseDelay, elapsed);

			if (commandStatus != NTStatus.STATUS_SUCCESS)
			{
				string errorName = commandStatus.ToString();
				SambaMetricsSource.WriteError(SambaMetricsConstants.EventNames.Error, errorName);
			}
		}
	}
}