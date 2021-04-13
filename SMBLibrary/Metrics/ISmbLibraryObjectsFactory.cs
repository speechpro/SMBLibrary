using SMBLibrary.Client;

namespace SMBLibrary.Metrics
{
	public interface ISmbLibraryObjectsFactory : ISmbLibraryInternalObjectsFactory
	{
		ISmbClient CreateSmb1Client();
		ISmbClient CreateSmb2Client();
	}
}
