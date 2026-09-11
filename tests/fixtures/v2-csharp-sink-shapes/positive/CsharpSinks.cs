using Dapper;

public class CsharpSinksController
{
    [HttpGet]
    public object TypedCommandText([FromQuery] string query)
    {
        SqlCommand command = new SqlCommand();
        command.CommandText = query;
        return command;
    }

    [HttpGet]
    public object InferredCommandText([FromQuery] string query)
    {
        var command = new Microsoft.Data.SqlClient.SqlCommand();
        command.CommandText = query;
        return command;
    }

    [HttpGet]
    public object DapperQuery([FromQuery] string query, IDbConnection database)
    {
        return database.Query<Row>(query);
    }

    [HttpGet]
    public object DapperExecute([FromQuery] string query, DbConnection database)
    {
        return database.Execute(query, new { value = 1 });
    }

    [HttpGet]
    public object DapperMultiple([FromQuery] string query, SqlConnection database)
    {
        return database.QueryMultiple(query);
    }

    [HttpGet]
    public object TrustedHtml([FromQuery] string content)
    {
        return Html.Raw(content);
    }

    [HttpGet]
    public object HtmlContent([FromQuery] string content)
    {
        return Content(content, "text/html");
    }

    [HttpGet]
    public object ControllerRedirect([FromQuery] string location)
    {
        return Redirect(location);
    }

    [HttpGet]
    public object PermanentRedirect([FromQuery] string location)
    {
        return RedirectPermanent(location);
    }

    [HttpGet]
    public object ReadLines([FromQuery] string path)
    {
        return File.ReadAllLines(path);
    }

    [HttpGet]
    public object ListDirectories([FromQuery] string path)
    {
        return Directory.GetDirectories(path);
    }

    [HttpDelete]
    public object DeleteFile([FromQuery] string path)
    {
        File.Delete(path);
        return path;
    }

    [HttpPost]
    public object CreateDirectory([FromQuery] string path)
    {
        return Directory.CreateDirectory(path);
    }

    [HttpGet]
    public object DownloadString([FromQuery] string endpoint, WebClient client)
    {
        return client.DownloadString(endpoint);
    }

    [HttpGet]
    public object DownloadData([FromQuery] string endpoint)
    {
        var client = new System.Net.WebClient();
        return client.DownloadDataTaskAsync(endpoint);
    }
}
