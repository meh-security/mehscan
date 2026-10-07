using System.IO;
using System.Threading.Tasks;

class App
{
    async Task DirectAwait(string input)
    {
        var path = await Helpers.ResolveAsync(input);
        File.Delete(path);
    }

    async Task CfgAwait(string input)
    {
        var path = await Helpers.ResolveAsync(input);
        if (File.Exists(path)) File.Delete(path);
    }

    void Replaced(string input)
    {
        var path = Helpers.Resolve(input);
        path = Other.Resolve(input);
        File.Delete(path);
    }

    void Alternatives(string input, bool alternate)
    {
        var path = Helpers.Resolve(input);
        if (alternate) path = Other.Resolve(input);
        File.Delete(path);
    }

    void NestedArgument(string root, string input)
    {
        var path = Path.Combine(root, Helpers.Resolve(input));
        File.Delete(path);
    }

    void Stored(Record record)
    {
        var path = Helpers.Stored(record);
        if (File.Exists(path)) File.Delete(path);
    }

    void ManyStored(Many record)
    {
        File.Delete(Helpers.ManyStored(record));
    }
}
