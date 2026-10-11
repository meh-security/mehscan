using System.Threading.Tasks;

public static class Helpers
{
    public static Task<string> ResolveAsync(string input) => Task.FromResult(input);
    public static string Resolve(string input) => input;
    public static string Stored(Record record) => record.Key;
    public static string ManyStored(Many record) => record.Key;
}

public class Record { public string Key { get; set; } }
public class Imported { public string Key { get; set; } }
public class Many { public string Key { get; set; } }

public class Writers
{
    public Record Normal() => new Record { Key = System.Guid.NewGuid().ToString() };
    public void Import(Record target, Imported source) { target.Key = source.Key; }
    public void Namesake(Imported target) { target.Key = "unrelated"; }
    public void ManyWrites(Many target, string input)
    {
        target.Key = input + "1";
        target.Key = input + "2";
        target.Key = input + "3";
        target.Key = input + "4";
        target.Key = input + "5";
        target.Key = input + "6";
        target.Key = input + "7";
        target.Key = input + "8";
        target.Key = input + "9";
    }
}

public static class Other
{
    public static string Resolve(string input) => "data/" + input;
}
