using System.IO;
using System.IO.Compression;
using ArchiveAlias = System.IO.Compression.ZipArchive;
class ArchiveOperations {
    void Parameter(ArchiveAlias archive, string root) {
        foreach (var entry in archive.Entries) {
            var path = Path.GetFullPath(Path.Combine(root, entry.FullName));
            var outside = !path.StartsWith(root);
            entry.ExtractToFile(path, overwrite: true);
        }
    }
    void Open(string file, string root) {
        using (var archive = ZipFile.OpenRead(file)) {
            foreach (var entry in archive.Entries) {
                entry.ExtractToFile(Path.Combine(root, entry.FullName));
            }
        }
        File.Delete(file);
    }
    void Construct(Stream input, string root) {
        using var archive = new ZipArchive(input, ZipArchiveMode.Read);
        foreach (var entry in archive.Entries) {
            entry.ExtractToFile(Path.Combine(root, entry.FullName));
        }
    }
    void Unknown(FakeArchive archive, string root) {
        foreach (var entry in archive.Entries) {
            entry.ExtractToFile(Path.Combine(root, entry.FullName));
        }
    }
}
class FakeArchive { public FakeEntry[] Entries; }
class FakeEntry { public string FullName; public void ExtractToFile(string path) {} }
