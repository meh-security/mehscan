using System.IO;
using System.Threading.Tasks;

internal sealed class Lookalikes
{
    internal async Task Fake(Stream request, string path)
    {
        var reader = new MultipartReader("boundary", request);
        var section = await reader.ReadNextSectionAsync();
        using var destination = File.Create(path);
        await section.Body.CopyToAsync(destination);
    }
}

internal sealed class MultipartReader
{
    internal MultipartReader(string boundary, Stream body) { }
    internal Task<MultipartSection> ReadNextSectionAsync() => null;
}

internal sealed class MultipartSection
{
    internal Stream Body => Stream.Null;
}
