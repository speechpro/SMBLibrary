using SMBLibrary.Client;

namespace SMBLibrary.Metrics
{
	public class SmbLibraryInternalObjectsWithMetricsFactory : ISmbLibraryInternalObjectsFactory
	{
		public ISMBFileStore CreateSmb1FileStore(SMB1Client client, ushort treeId)
		{
			var fileStoreWithMetrics = new Smb1FileStoreWithMetrics(client, treeId);
			return fileStoreWithMetrics;
		}

		public ISMBFileStore CreateSmb2FileStore(Smb2Client client, uint treeId)
		{
			var fileStoreWithMetrics = new Smb2FileStoreWithMetrics(client, treeId);
			return fileStoreWithMetrics;
		}
	}
}
