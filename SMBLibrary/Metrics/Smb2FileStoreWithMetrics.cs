using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using DevTools.Samba.Metrics.Config;
using DevTools.Samba.Metrics.Helpers;
using SMBLibrary.Client;

namespace SMBLibrary.Metrics
{
	public class Smb2FileStoreWithMetrics : Smb2FileStore
	{
		private static readonly DiagnosticSource SambaMetricsSource =
			new DiagnosticListener(SambaMetricsConstants.Samba2MetricsListenerName);

		public Smb2FileStoreWithMetrics(Smb2Client client, uint treeId)
			: base(client, treeId)
		{

		}

		public override NTStatus CreateFile(
			out object handle,
			out FileStatus fileStatus,
			IMemoryOwner<char> path,
			AccessMask desiredAccess,
			FileAttributes fileAttributes,
			ShareAccess shareAccess,
			CreateDisposition createDisposition,
			CreateOptions createOptions,
			SecurityContext securityContext)
		{
			NTStatus status = base.CreateFile(
				out handle,
				out fileStatus,
				path,
				desiredAccess,
				fileAttributes,
				shareAccess,
				createDisposition,
				createOptions,
				securityContext);

			SambaMetricsSource.Write(SambaMetricsConstants.EventNames.FileOpened);

			return status;
		}

		public override NTStatus CloseFile(object handle)
		{
			NTStatus status = base.CloseFile(handle);

			SambaMetricsSource.Write(SambaMetricsConstants.EventNames.FileClosed);
			
			return status;
		}

		public override NTStatus QueryDirectory(
			out List<FindFilesQueryResult> result, 
			object handle, 
			string fileName, 
			FileInformationClass informationClass)
		{
			NTStatus status = base.QueryDirectory(out result, handle, fileName, informationClass);
			
			SambaMetricsSource.WriteCount(SambaMetricsConstants.EventNames.FilesEnumerated, result.Count);

			return status;
		}

		public override async IAsyncEnumerable<FindFilesQueryResult> QueryDirectoryAsync(
			object handle, 
			string fileName, 
			FileInformationClass informationClass,
			bool closeOnFinish, 
			[EnumeratorCancellation] CancellationToken outerToken = new CancellationToken())
		{
			IAsyncEnumerable<FindFilesQueryResult> smbStoreEnumerable =
				base.QueryDirectoryAsync(handle, fileName, informationClass, closeOnFinish, outerToken);

			int filesEnumerated = 0;
			await foreach (FindFilesQueryResult result in smbStoreEnumerable.WithCancellation(outerToken))
			{
				yield return result;
				filesEnumerated++;
			}
			
			SambaMetricsSource.WriteCount(SambaMetricsConstants.EventNames.FilesEnumerated, filesEnumerated);
		}
	}
}