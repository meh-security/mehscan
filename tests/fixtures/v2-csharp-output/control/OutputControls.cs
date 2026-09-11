using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

public sealed class OutputControlsController : Controller
{
    private readonly ILogger<OutputControlsController> _logger;

    public OutputControlsController(ILogger<OutputControlsController> logger)
    {
        _logger = logger;
    }

    [HttpGet("/safe-download")]
    public IActionResult Download([FromHeader] string trace, [FromQuery] string filename)
    {
        if (trace.Contains('\r') || trace.Contains('\n'))
        {
            return BadRequest();
        }

        Response.Headers.Append("X-Trace", trace);

        var disposition = new ContentDispositionHeaderValue("attachment");
        disposition.FileNameStar = filename;
        Response.GetTypedHeaders().ContentDisposition = disposition;

        _logger.LogInformation("Download requested for {FileName}", filename);
        return File(new byte[] { 1 }, "application/octet-stream", filename);
    }
}

public sealed class SimilarNamesAreNotLogging
{
    public void Run(string message)
    {
        collector.LogInformation(message);
    }
}
