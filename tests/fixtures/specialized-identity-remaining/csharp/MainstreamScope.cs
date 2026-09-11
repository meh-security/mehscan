using System.Xml;
using Newtonsoft.Json;

class MainstreamScope
{
    dynamic document;
    dynamic settings;

    void Parse(string payload)
    {
        {
            XmlDocument document = null;
        }
        document.XmlResolver = new XmlUrlResolver();
        document.LoadXml(payload);
    }

    void Deserialize(string payload)
    {
        {
            JsonSerializerSettings settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
        }
        JsonConvert.DeserializeObject(payload, settings);
    }
}
