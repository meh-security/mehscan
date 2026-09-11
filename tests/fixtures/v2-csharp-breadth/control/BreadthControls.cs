using System.Net.Http;
using System.Xml;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

public sealed class BreadthControlsController : Controller
{
    [HttpPost("/safe-json")]
    public object JsonNet([FromBody] string payload)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None
        };
        var serializer = JsonSerializer.Create(settings);
        return serializer.Deserialize(payload);
    }

    [HttpPost("/safe-xml")]
    public object Xml([FromBody] string payload)
    {
        var document = new XmlDocument
        {
            XmlResolver = null
        };
        document.LoadXml(payload);
        return document;
    }

    [HttpGet("/lookalike")]
    public object Lookalike([FromQuery] string endpoint, SearchClient client)
    {
        return client.GetAsync(endpoint);
    }
}

public sealed class SearchClient
{
    public object GetAsync(string value) => value;
}
