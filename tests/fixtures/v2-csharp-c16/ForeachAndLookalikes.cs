using System.IO;
using System.IO.Compression;

internal sealed class ForeachAndLookalikes
{
    internal void ExplicitForeach(ZipArchive archive, string root)
    {
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            entry.ExtractToFile(Path.Combine(root, entry.FullName));
        }
    }

    internal void BasenameOnly(ZipArchiveEntry entry, string root)
    {
        entry.ExtractToFile(Path.Combine(root, entry.Name));
    }

    internal void Shadow(ZipArchiveEntryLookalike entry, string root)
    {
        entry.ExtractToFile(Path.Combine(root, entry.FullName));
    }
}

internal sealed class ZipArchiveEntryLookalike
{
    internal string FullName => "lookalike";
    internal void ExtractToFile(string path) { }
}
