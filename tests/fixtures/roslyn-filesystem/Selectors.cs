using System;
using System.IO;

static class SelectorHelpers
{
    public static string GuidName(Guid id) => id.ToString("N") + ".json";
    public static string DateName(DateTime date) { var name = date.ToString("yyyyMMdd"); return name + ".bak"; }
    public static string FilePath(string root, Guid id) => Path.Combine(root, GuidName(id));
    public static string StringPath(string input) => Path.Combine("data", input);
    public static string Replaced(string root) { root = Console.ReadLine(); return root; }
    public static string Recursive(string path) => Recursive(path);
}

class SelectorRecord
{
    public Guid Id { get; set; }
    public DateTime Updated { get; set; }
    public string Filename { get; set; }
    public string GuidName => Id.ToString("N") + ".json";
    public string DateName { get { return Updated.ToString("O"); } }
    public virtual string VirtualName => "default.json";
    public string InitializedName { get; } = "known.json";
    public string ReplacedName { get; } = "known.json";
    public SelectorRecord(string path) { ReplacedName = path; }
}
