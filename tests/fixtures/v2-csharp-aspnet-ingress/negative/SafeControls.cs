public record SearchRequest(string Query);
public sealed class RunnerService
{
    public string Command { get; init; }
}

public class SafeControlsController
{
    public object Ordinary(string command)
    {
        Process.Start(command);
        return command;
    }

    [HttpGet]
    public object Injected([FromServices] RunnerService service)
    {
        Process.Start(service.Command);
        return service;
    }

    [HttpGet]
    public object Framework(HttpContext context)
    {
        Process.Start(context.TraceIdentifier);
        return context;
    }

    [HttpPost]
    public object Ambiguous(SearchRequest request)
    {
        Process.Start(request.Query);
        return request;
    }

    [HttpGet]
    public object Reassigned([FromQuery] string command)
    {
        command = "fixed";
        Process.Start(command);
        return command;
    }

    [HttpGet]
    public object MemberNameCollision([FromQuery] string Command, RunnerService service)
    {
        Process.Start(service.Command);
        return service;
    }
}

app.MapGet("/service", ([FromServices] RunnerService service) => Process.Start(service.Command));
app.MapGet("/context", (HttpContext context) => Process.Start(context.TraceIdentifier));
app.MapGet("/complex", (SearchRequest request) => Process.Start(request.Query));
app.MapPost("/service-body", (RunnerService service) => Process.Start(service.Command));
app.MapGet("/deferred", HandleRequest);
