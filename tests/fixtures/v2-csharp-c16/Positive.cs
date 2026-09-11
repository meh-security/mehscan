using System;
using System.IO;
using System.IO.Compression;
using EntryAlias = System.IO.Compression.ZipArchiveEntry;

internal sealed class Positive
{
    internal void Direct(ZipArchiveEntry entry, string root)
    {
        entry.ExtractToFile(Path.Combine(root, entry.FullName));
    }

    internal void Propagated(EntryAlias entry, string root)
    {
        var destination = Path.Combine(root, entry.FullName);
        entry.ExtractToFile(destination);
    }

    internal void ExtensionIsNotContainment(ZipArchiveEntry entry, string root)
    {
        if (entry.FullName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
        {
            entry.ExtractToFile(Path.Combine(root, entry.FullName));
        }
    }

    internal void CanonicalizationAloneIsNotContainment(ZipArchiveEntry entry, string root)
    {
        var destination = Path.GetFullPath(Path.Combine(root, entry.FullName));
        entry.ExtractToFile(destination);
    }
}
