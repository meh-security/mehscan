using Microsoft.AspNetCore.Mvc;
using System.Runtime.Serialization.Formatters.Binary;

public class CompatibilityController : ControllerBase
{
    [HttpPost]
    public object Restore([FromBody] string payload)
    {
        return new BinaryFormatter().Deserialize(payload);
    }
}
