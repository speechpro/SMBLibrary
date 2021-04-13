using SMBLibrary.Client;

namespace SMBLibrary.Metrics
{
	public interface ISmbLibraryInternalObjectsFactory
	{
		ISMBFileStore CreateSmb1FileStore(SMB1Client client, ushort treeId);
		ISMBFileStore CreateSmb2FileStore(Smb2Client client, uint treeId);
	}
}
