using System.IO.Compression;

sealed class ArchiveScope
{
    private ArchiveEntryLookalike entry = new ArchiveEntryLookalike();

    void Review(string destination, ZipArchiveEntry importedEntry)
    {
        {
            ZipArchiveEntry entry = importedEntry;
        }
        entry.ExtractToFile(destination);
    }
}

sealed class ArchiveEntryLookalike
{
    public string FullName => "fixed.txt";
    public void ExtractToFile(string destination) { }
}
