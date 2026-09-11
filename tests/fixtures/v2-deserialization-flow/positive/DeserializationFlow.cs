using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;

class DeserializationFlow
{
    object Direct(dynamic Request)
    {
        return new BinaryFormatter().Deserialize(Request.Form["payload"]);
    }

    object Propagated(dynamic Request)
    {
        var serialized = Request.Form["payload"];
        var forwardedValue = serialized;
        return new BinaryFormatter().Deserialize(forwardedValue);
    }

    UploadDto Restricted(dynamic Request)
    {
        return JsonSerializer.Deserialize<UploadDto>(Request.Form["restricted"]);
    }
}
