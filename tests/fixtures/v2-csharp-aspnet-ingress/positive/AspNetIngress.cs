public record RunRequest(string Command);

public class CommandsController
{
    [HttpGet]
    public object Query([FromQuery] string command)
    {
        Process.Start(command);
        return command;
    }

    [HttpGet]
    public object Header([FromHeader] string endpoint, HttpClient client)
    {
        var target = endpoint;
        return client.GetAsync(target);
    }

    [HttpGet("{next}")]
    public object Route([FromRoute] string next)
    {
        return Results.Redirect(next);
    }

    [HttpPost]
    public object Body([FromBody] RunRequest request)
    {
        Process.Start(request.Command);
        return request;
    }

    [HttpPost]
    public object Form([FromForm] string command)
    {
        Process.Start(command);
        return command;
    }

    [HttpPost]
    public object Upload(IFormFile file)
    {
        Process.Start(file.FileName);
        return file;
    }

    [HttpGet]
    public object Encoded([FromQuery] string content)
    {
        var encoded = HtmlEncoder.Default.Encode(content);
        return Response.WriteAsync(encoded);
    }
}

app.MapGet("/run/{command}", (string command) => Process.Start(command));
app.MapGet("/jump", ([FromQuery] string next) => Results.Redirect(next));
app.MapPost("/body", (RunRequest request) => Process.Start(request.Command));
app.MapGet("/header", ([FromHeader] string endpoint, HttpClient client) =>
{
    var target = endpoint;
    return client.GetAsync(target);
});
