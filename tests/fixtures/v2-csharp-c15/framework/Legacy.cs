using Microsoft.AspNetCore.Mvc;
using BF = System.Runtime.Serialization.Formatters.Binary.BinaryFormatter;
using Soap = System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization;
using WebState = System.Web.UI;

public class LegacyController : ControllerBase
{
    [HttpPost]
    public object Binary([FromBody] string payload)
    {
        return new BF().Deserialize(payload);
    }

    [HttpPost]
    public object SoapGraph([FromBody] string payload)
    {
        var formatter = new Soap.SoapFormatter();
        return formatter.Deserialize(payload);
    }

    [HttpPost]
    public object NetData([FromBody] string payload)
    {
        NetDataContractSerializer formatter = new NetDataContractSerializer();
        return formatter.ReadObject(payload);
    }

    [HttpPost]
    public object Los([FromBody] string payload)
    {
        var formatter = new WebState.LosFormatter();
        return formatter.Deserialize(payload);
    }

    [HttpPost]
    public object ObjectState([FromBody] string payload)
    {
        WebState.ObjectStateFormatter formatter = new WebState.ObjectStateFormatter();
        return formatter.Deserialize(payload);
    }
}
