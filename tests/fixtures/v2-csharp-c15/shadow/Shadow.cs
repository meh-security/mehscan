using Microsoft.AspNetCore.Mvc;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.UI;

public class ShadowController : ControllerBase
{
    [HttpPost]
    public object Restore([FromBody] string payload)
    {
        new BinaryFormatter().Deserialize(payload);
        new LosFormatter().Deserialize(payload);
        return payload;
    }
}

public class BinaryFormatter
{
    public object Deserialize(string value) => value;
}

public class LosFormatter
{
    public object Deserialize(string value) => value;
}
