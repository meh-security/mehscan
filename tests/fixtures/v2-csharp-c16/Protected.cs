using System;
using System.IO;
using System.IO.Compression;

internal sealed class Protected
{
    internal void PositiveGuard(ZipArchiveEntry entry, string extractionRoot)
    {
        var rootedBoundary = Path.GetFullPath(extractionRoot) + Path.DirectorySeparatorChar;
        var destination = Path.GetFullPath(Path.Combine(rootedBoundary, entry.FullName));
        if (destination.StartsWith(rootedBoundary, StringComparison.Ordinal))
        {
            entry.ExtractToFile(destination);
        }
    }

    internal void TerminatingNegativeGuard(ZipArchiveEntry entry, string extractionRoot)
    {
        var rootedBoundary = Path.GetFullPath(extractionRoot) + Path.DirectorySeparatorChar;
        var destination = Path.GetFullPath(Path.Combine(rootedBoundary, entry.FullName));
        if (!destination.StartsWith(rootedBoundary, StringComparison.Ordinal))
        {
            throw new InvalidDataException("archive entry escaped extraction root");
        }
        entry.ExtractToFile(destination);
    }

    internal void PrefixWithoutBoundaryIsNotEnough(ZipArchiveEntry entry, string extractionRoot)
    {
        var rooted = Path.GetFullPath(extractionRoot);
        var destination = Path.GetFullPath(Path.Combine(rooted, entry.FullName));
        if (destination.StartsWith(rooted, StringComparison.Ordinal))
        {
            entry.ExtractToFile(destination);
        }
    }

    internal void WrongComparisonIsReviewOnly(ZipArchiveEntry entry, string extractionRoot)
    {
        var rootedBoundary = Path.GetFullPath(extractionRoot) + Path.DirectorySeparatorChar;
        var destination = Path.GetFullPath(Path.Combine(rootedBoundary, entry.FullName));
        if (destination.StartsWith(rootedBoundary, StringComparison.OrdinalIgnoreCase))
        {
            entry.ExtractToFile(destination);
        }
    }

    internal void WrongComparedRootIsNotProtection(ZipArchiveEntry entry, string extractionRoot)
    {
        var rootedBoundary = Path.GetFullPath(extractionRoot) + Path.DirectorySeparatorChar;
        var unrelatedBoundary = Path.GetFullPath("other") + Path.DirectorySeparatorChar;
        var destination = Path.GetFullPath(Path.Combine(rootedBoundary, entry.FullName));
        if (destination.StartsWith(unrelatedBoundary, StringComparison.Ordinal))
        {
            entry.ExtractToFile(destination);
        }
    }
}
