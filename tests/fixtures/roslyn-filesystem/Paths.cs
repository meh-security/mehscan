using System;
using System.IO;
using System.Linq;

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
    void ParsedNumber(string input) { File.Delete(Path.Combine("data", int.Parse(input).ToString())); }
    void IntegralFormat(int number) { File.Delete(Path.Combine("data", number.ToString("D8"))); }
    void BooleanValue(bool value) { File.Delete(Path.Combine("data", value.ToString())); }
    void ConvertedNumber(int number) { File.Delete(Path.Combine("data", Convert.ToString(number))); }
    void EnumValue(FileMode mode) { File.Delete(Path.Combine("data", mode.ToString())); }
    void DateFilename(DateTime time) { File.Delete(Path.Combine("data", time.ToString("dd-MM-yyyy-HH.mm.ss"))); }
    void InterpolatedId(Guid id) { File.Delete(Path.Combine("data", $"cache-{id:N}.json")); }
    void InterpolatedNumber(int id) { File.Delete(Path.Combine("data", $"cache-{id:D8}.json")); }
    void UnknownInterpolation(string input) { File.Delete(Path.Combine("data", $"cache-{input}.json")); }
    void UnknownNumericFormat(int id, string format) { File.Delete(Path.Combine("data", id.ToString(format))); }
    void UnknownNumericProvider(int id, IFormatProvider provider) { File.Delete(Path.Combine("data", id.ToString(provider))); }
    void RuntimeRoot() { File.Delete(Path.Combine(AppContext.BaseDirectory, "cache.json")); }
    void DomainRoot() { File.Delete(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cache.json")); }
    void WorkingRoot() { File.Delete(Path.Combine(Directory.GetCurrentDirectory(), "cache.json")); }
    void FolderRoot() { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "cache.json")); }
    void ParentOfKnownPath() { Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(AppContext.BaseDirectory, "data", "cache.json"))); }
    void ParentOfUnknownPath(string path) { Directory.CreateDirectory(Path.GetDirectoryName(path)); }
    void FixedArrayCombine() { File.Delete(Path.Combine(new[] { "data", "cache", "one", "two", "file.json" })); }
    void EnumeratedFiles() { foreach (var file in Directory.GetFiles("data")) File.Delete(file); }
    void EnumeratedUnknownRoot(string root) { foreach (var file in Directory.GetFiles(root)) File.Delete(file); }
    void MutatedFiles(string input) { var files = Directory.GetFiles("data"); files[0] = input; foreach (var file in files) File.Delete(file); }
    void EscapedFiles(string input) { var files = Directory.GetFiles("data"); ReplaceFiles(files, input); foreach (var file in files) File.Delete(file); }
    static void ReplaceFiles(string[] files, string input) { files[0] = input; }
    void FirstFile() { var file = Directory.GetFiles("data").FirstOrDefault(); File.Delete(file); }
    void KnownFileInfo() { File.Delete(new FileInfo("cache.json").FullName); }
    private readonly string KnownReadonlyPath = Path.Combine(AppContext.BaseDirectory, "cache.json");
    private readonly string OverwrittenReadonlyPath = "cache.json";
    private readonly string ReplacedReadonlyPath = "cache.json";
    public Paths(string input) { OverwrittenReadonlyPath = input; Replace(ref ReplacedReadonlyPath); }
    void ReadonlyPath() { File.Delete(KnownReadonlyPath); }
    void OverwrittenReadonly() { File.Delete(OverwrittenReadonlyPath); }
    void ReplacedReadonly() { File.Delete(ReplacedReadonlyPath); }
    void ClosedBranches(bool choice) { var path = choice ? "one.json" : "two.json"; File.Delete(path); }
    void MixedBranches(bool choice, string input) { var path = choice ? "one.json" : input; File.Delete(path); }
    void TempFinally() { var path = ""; try { path = Path.GetTempFileName(); } finally { File.Delete(path); } }
    void TempSuffixReset() { var path = Path.GetTempFileName(); path = path + ".json"; File.Delete(path); }
    void LoopReplacement(string input) { var path = "known.json"; while (true) { File.Delete(path); path = input; } }
    void PrivateTempUse() { var path = Path.GetTempFileName(); new TempOwner(path).PrivateTempDelete(); }
    private sealed class TempOwner {
        private readonly string path;
        public TempOwner(string path) { this.path = path; }
        public void PrivateTempDelete() { File.Delete(path); }
    }
    void PrivateUnknownUse(string input) { new UnknownOwner(input).PrivateUnknownDelete(); }
    private sealed class UnknownOwner {
        private readonly string path;
        public UnknownOwner(string path) { this.path = path; }
        public void PrivateUnknownDelete() { File.Delete(path); }
    }
    void MutatingConstructorUse() { new MutatingOwner(Path.GetTempFileName()).MutatingConstructorDelete(); }
    private sealed class MutatingOwner {
        private readonly string path;
        public MutatingOwner(string path) { path = Console.ReadLine(); this.path = path; }
        public void MutatingConstructorDelete() { File.Delete(path); }
    }
    void PublicOwnerUse() { new PublicOwner(Path.GetTempFileName()).PublicOwnerDelete(); }
    public sealed class PublicOwner {
        private readonly string path;
        public PublicOwner(string path) { this.path = path; }
        public void PublicOwnerDelete() { File.Delete(path); }
    }
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

partial class PartialOwner
{
    private readonly string path = "known.json";
    void PartialReadonlyDelete() { File.Delete(path); }
}
