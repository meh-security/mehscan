using Microsoft.AspNetCore.Mvc;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.UI;

public class ModernController : ControllerBase
{
    [HttpPost]
    public object Binary([FromBody] string payload)
    {
        return new BinaryFormatter().Deserialize(payload);
    }

    [HttpPost]
    public object FrameworkOnly([FromBody] string payload)
    {
        return new LosFormatter().Deserialize(payload);
    }
}
