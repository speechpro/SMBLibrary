using SMBLibrary.Client;

namespace SMBLibrary.Metrics
{
	public class SmbLibraryObjectsFactory : ISmbLibraryObjectsFactory
	{
		private readonly SmbLibraryInternalObjectsFactory _smbLibraryObjectsFactory;

		public SmbLibraryObjectsFactory()
		{
			_smbLibraryObjectsFactory = new SmbLibraryInternalObjectsFactory();
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
			return new SMB1Client(_smbLibraryObjectsFactory);
		}

		public ISmbClient CreateSmb2Client()
		{
			return new Smb2Client(_smbLibraryObjectsFactory);
		}
	}
}
