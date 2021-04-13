using SMBLibrary.Client;

namespace SMBLibrary.Metrics
{
	public class SmbLibraryObjectsWithMetricsFactory : ISmbLibraryObjectsFactory
	{
		private readonly SmbLibraryInternalObjectsWithMetricsFactory _smbLibraryObjectsFactory;

		public SmbLibraryObjectsWithMetricsFactory()
		{
			_smbLibraryObjectsFactory = new SmbLibraryInternalObjectsWithMetricsFactory();
		}

		public ISMBFileStore CreateSmb1FileStore(SMB1Client client, ushort treeId)
		{
			return _smbLibraryObjectsFactory.CreateSmb1FileStore(client, treeId);
		}

		public ISMBFileStore CreateSmb2FileStore(Smb2Client client, uint treeId)
		{
			return _smbLibraryObjectsFactory.CreateSmb2FileStore(client, treeId);
		}

		public ISmbClient CreateSmb1Client()
		{
			return new Smb1ClientWithMetrics(_smbLibraryObjectsFactory);
		}

		public ISmbClient CreateSmb2Client()
		{
			return new Smb2ClientWithMetrics(_smbLibraryObjectsFactory);
		}
	}
}
