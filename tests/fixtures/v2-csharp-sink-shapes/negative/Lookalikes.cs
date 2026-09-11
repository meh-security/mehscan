using Dapperish;

public sealed class Report
{
    public string CommandText { get; set; }
}

public sealed class FakeCommand
{
    public string CommandText { get; set; }
}

public sealed class SearchIndex
{
    public object Query(string query) => query;
    public object ExecuteSafe(string query) => query;
}

public sealed class DownloadClient
{
    public object DownloadString(string endpoint) => endpoint;
}

public class LookalikesController
{
    [HttpGet]
    public object UnrelatedCommandText([FromQuery] string query)
    {
        var report = new Report();
        report.CommandText = query;
        return report;
    }

    [HttpGet]
    public object ReassignedCommand([FromQuery] string query)
    {
        var command = new SqlCommand();
        command = new FakeCommand();
        command.CommandText = query;
        return command;
    }

    [HttpGet]
    public object NonDapperQuery([FromQuery] string query, SearchIndex database)
    {
        return database.Query(query);
    }

    [HttpGet]
    public object DifferentMethod([FromQuery] string query, IDbConnection database)
    {
        return database.ExecuteSafe(query);
    }

    [HttpGet]
    public object NonWebClient([FromQuery] string endpoint, DownloadClient client)
    {
        return client.DownloadString(endpoint);
    }

    [HttpGet]
    public object JsonContent([FromQuery] string content)
    {
        return Content(content, "application/json");
    }

    [HttpGet]
    public object LocalRedirect([FromQuery] string location)
    {
        return RedirectToAction(location);
    }

    [HttpGet]
    public object PathChecks([FromQuery] string path)
    {
        return File.Exists(path) && Directory.Exists(path);
    }
}
