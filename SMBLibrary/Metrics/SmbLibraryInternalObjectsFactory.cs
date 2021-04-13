using SMBLibrary.Client;

namespace SMBLibrary.Metrics
{
	public class SmbLibraryInternalObjectsFactory : ISmbLibraryInternalObjectsFactory
	{
		public ISMBFileStore CreateSmb1FileStore(SMB1Client client, ushort treeId)
		{
			var fileStore = new SMB1FileStore(client, treeId);
			return fileStore;
		}

		public ISMBFileStore CreateSmb2FileStore(Smb2Client client, uint treeId)
		{
			var fileStore = new Smb2FileStore(client, treeId);
			return fileStore;
		}
	}
}
