using System.Data;
using System.IO;
using System.Net.Http;
using System.Xml;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

public sealed class BreadthRisksController : Controller
{
    private readonly IHttpClientFactory _httpClientFactory;

    public BreadthRisksController(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet("/typed-http")]
    public object TypedHttp([FromQuery] string endpoint, HttpClient client)
    {
        _ = client.GetAsync("https://status.example/");
        return client.GetAsync(endpoint);
    }

    [HttpGet("/factory-http")]
    public object FactoryHttp([FromQuery] string endpoint)
    {
        var client = _httpClientFactory.CreateClient();
        return client.GetStringAsync(endpoint);
    }

    [HttpGet("/dapper")]
    public object DapperFactory([FromQuery] string query, ConnectionFactory factory)
    {
        var connection = factory.CreateConnection();
        return connection.QueryAsync(query);
    }

    [HttpPost("/json")]
    public object JsonNet([FromBody] string payload)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };
        var serializer = JsonSerializer.Create(settings);
        return serializer.Deserialize(payload);
    }

    [HttpPost("/xml")]
    public object Xml([FromBody] string payload)
    {
        var document = new XmlDocument
        {
            XmlResolver = new XmlUrlResolver()
        };
        document.LoadXml(payload);
        return document;
    }
}

public sealed class ConnectionFactory
{
    public IDbConnection CreateConnection() => null;
}
