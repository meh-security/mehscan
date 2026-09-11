using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Xml.Serialization;

public class SafeController : ControllerBase
{
    [HttpPost]
    public Payload Json([FromBody] string payload)
    {
        return JsonSerializer.Deserialize<Payload>(payload);
    }

    [HttpPost]
    public object DataContract([FromBody] Stream payload)
    {
        return new DataContractSerializer(typeof(Payload)).ReadObject(payload);
    }

    [HttpPost]
    public object Xml([FromBody] Stream payload)
    {
        return new XmlSerializer(typeof(Payload)).Deserialize(payload);
    }
}

public class Payload
{
    public string Value { get; set; }
}
