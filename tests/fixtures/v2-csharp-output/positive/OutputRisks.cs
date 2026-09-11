using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Html;
using Microsoft.Extensions.Logging;

public sealed class OutputRisksController : Controller
{
    private readonly ILogger<OutputRisksController> _logger;

    public OutputRisksController(ILogger<OutputRisksController> logger)
    {
        _logger = logger;
    }

    [HttpGet("/download")]
    public IActionResult Download(
        [FromHeader] string trace,
        [FromQuery] string filename,
        [FromQuery] string message,
        [FromQuery] string password,
        [FromQuery] string resetToken)
    {
        Response.Headers.Append("X-Trace", trace);
        Response.Headers["Content-Disposition"] = "attachment; filename=" + filename;

        _logger.LogWarning(message);
        _logger.LogWarning($"Rejected password: {password}");
        _logger.LogInformation("Reset token {ResetToken}", resetToken);

        var trustedMarkup = new HtmlString(message);

        return Content("<strong>" + message + "</strong>", "text/html");
    }
}
