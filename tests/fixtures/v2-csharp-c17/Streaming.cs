using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using ReaderAlias = Microsoft.AspNetCore.WebUtilities.MultipartReader;

[ApiController]
internal sealed class StreamingController : ControllerBase
{
    [RequestSizeLimit(20_000_000)]
    [RequestFormLimits(MultipartBodyLengthLimit = 10_000_000)]
    internal async Task Direct(string boundary, string path)
    {
        var reader = new MultipartReader(boundary, Request.Body);
        reader.BodyLengthLimit = 5_000_000;
        reader.HeadersCountLimit = 24;
        var section = await reader.ReadNextSectionAsync();
        using var destination = File.Create(path);
        await section.Body.CopyToAsync(destination);
    }

    internal async Task AssignedSection(string boundary, string path)
    {
        var reader = new ReaderAlias(boundary, HttpContext.Request.Body);
        var section = await reader.ReadNextSectionAsync();
        section = await reader.ReadNextSectionAsync();
        await section.Body.CopyToAsync(new FileStream(path, FileMode.Create));
    }

    internal async Task RawRequest(HttpRequest request, string path)
    {
        using FileStream destination = File.Create(path);
        await request.Body.CopyToAsync(destination);
    }

    internal async Task ClientFilename(string boundary, string root)
    {
        var reader = new MultipartReader(boundary, Request.Body);
        var section = await reader.ReadNextSectionAsync();
        ContentDispositionHeaderValue.TryParse(
            section.ContentDisposition,
            out var disposition);
        var filename = disposition.FileName.Value;
        using var destination = File.Create(Path.Combine(root, filename));
        await section.Body.CopyToAsync(destination);
    }
}
