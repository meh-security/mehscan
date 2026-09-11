using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

[ApiController]
internal sealed class ControlsController : ControllerBase
{
    internal async Task MemoryOnly(string boundary)
    {
        var reader = new MultipartReader(boundary, Request.Body);
        var section = await reader.ReadNextSectionAsync();
        using var destination = new MemoryStream();
        await section.Body.CopyToAsync(destination);
    }

    internal async Task TrustedStream(Stream trusted, string boundary, string path)
    {
        var reader = new MultipartReader(boundary, trusted);
        var section = await reader.ReadNextSectionAsync();
        using var destination = File.Create(path);
        await section.Body.CopyToAsync(destination);
    }

    internal async Task ContentTypeIsContextOnly(string boundary, string path)
    {
        var reader = new MultipartReader(boundary, Request.Body);
        var section = await reader.ReadNextSectionAsync();
        if (section.ContentType == "image/png")
        {
            using var destination = File.Create(path);
            await section.Body.CopyToAsync(destination);
        }
    }
}
