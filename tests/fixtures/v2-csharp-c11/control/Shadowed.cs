using Microsoft.AspNetCore.Mvc;
using Microsoft.Security.Application;
using System.DirectoryServices;

public class ShadowedController : ControllerBase
{
    [HttpGet]
    public object Search([FromQuery] string value)
    {
        return new DirectorySearcher("(uid=" + Encoder.LdapFilterEncode(value) + ")");
    }
}

public class DirectorySearcher
{
    public DirectorySearcher(string filter) { }
}

public static class Encoder
{
    public static string LdapFilterEncode(string value) => value;
}
