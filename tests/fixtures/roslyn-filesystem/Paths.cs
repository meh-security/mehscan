using System;
using System.IO;

class Paths
{
    public string ManifestPath { get; set; }
    void FixedReset() { var path = Console.ReadLine(); path = "known.txt"; File.Delete(path); }
    void FixedAlias() { var first = "known.txt"; var path = first; File.Delete(path); }
    void FixedCombine() { File.Delete(Path.Combine("data", "known.txt")); }
    void FixedNumber() { File.Delete(Path.Combine("data", 123.ToString())); }
    void FixedBoolean() { File.Delete(Path.Combine("data", true.ToString())); }
    void GuidParameter(Guid id) { File.Delete(Path.Combine("data", id.ToString())); }
    void GuidFormat(Guid id, string format) { File.Delete(Path.Combine("data", id.ToString(format))); }
    void GuidProvider(Guid id, string format, IFormatProvider provider) { File.Delete(Path.Combine("data", id.ToString(format, provider))); }
    void GuidSuffix(Guid id) { File.Delete(Path.Combine("data", id.ToString() + ".json")); }
    void GuidUnknownFilename(Guid id, string filename) { File.Delete(Path.Combine("data", id.ToString(), filename)); }
    void GuidUnknownRoot(Guid id, string root) { File.Delete(Path.Combine(root, id.ToString())); }
    void GuidLookalike(CustomGuid id) { File.Delete(Path.Combine("data", id.ToString())); }
    void UnknownNumber(int number) { File.Delete(Path.Combine("data", number.ToString())); }
    void Conversion() { CustomPath path = "known.txt"; File.Delete(path); }
    void ConditionalReset(bool reset) { var path = Console.ReadLine(); if (reset) path = "known.txt"; File.Delete(path); }
    void Accumulation() { var path = "data"; path += Console.ReadLine(); File.Delete(path); }
    void UnknownRoot(string root) { File.Delete(Path.Combine(root, Guid.NewGuid().ToString())); }
    void UnknownManifest() { File.Delete(ManifestPath); }
    void TempGuid() { var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()); Directory.CreateDirectory(path); }
    void TempRandom() { var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()); File.Delete(path); }
    void TempAlias() { var root = Path.GetTempPath(); var path = Path.Combine(root, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(path); }
    void TempFile() { var path = Path.GetTempFileName(); File.Delete(path); }
    void TempReads() { var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()); var exists = File.Exists(path); try { File.Delete(path); } catch {} }
    void TempResetInTry() { var path = ""; try { path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()); Directory.CreateDirectory(path); } catch {} }
    void TempCapturedRead() { var path = ""; try { path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()); Directory.CreateDirectory(path); Action log = () => Console.WriteLine(path); log(); } catch {} }
    void TempConditionalInTry(bool replace, string input) { var path = ""; try { if (replace) path = input; Directory.CreateDirectory(path); } catch {} }
    void TempExecutable() { File.Delete(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".exe")); }
    void FormatInput() { File.Delete(Path.Combine("data", 123.ToString(Console.ReadLine()))); }
    void Character(char input) { File.Delete(Path.Combine("data", input.ToString())); }
    void RefReplacement() { var path = "known.txt"; Replace(ref path); File.Delete(path); }
    static void Replace(ref string path) { path = Console.ReadLine(); }
    void Capture() { var path = "known.txt"; Action change = () => path = Console.ReadLine(); change(); File.Delete(path); }
    void TryReplacement() { var path = "known.txt"; try { path = Console.ReadLine(); } catch {} File.Delete(path); }
    void NamedCopy() { File.Copy(destFileName: "known.txt", sourceFileName: Console.ReadLine()); }
    void NamedMove() { File.Move(destFileName: Console.ReadLine(), sourceFileName: "known.txt"); }
    void NamedDirectoryMove() { Directory.Move(destDirName: Console.ReadLine(), sourceDirName: "known"); }
    void NamedStream() { using (var stream = new FileStream(mode: FileMode.Create, path: Console.ReadLine())) {} }
}

class CustomPath
{
    public static implicit operator CustomPath(string value) { return new CustomPath(); }
    public static implicit operator string(CustomPath value) { return Console.ReadLine(); }
}

class CustomGuid
{
    public override string ToString() { return Console.ReadLine(); }
}
