using Microsoft.AspNetCore.Mvc;
using Microsoft.Security.Application;
using System.Diagnostics;
using System.DirectoryServices;
using LdapEncoder = Microsoft.Security.Application.Encoder;

public class InjectionControlsController : ControllerBase
{
    [HttpGet]
    public object EncodedFilter([FromQuery] string user)
    {
        return new DirectorySearcher("(uid=" + Encoder.LdapFilterEncode(user) + ")");
    }

    [HttpGet]
    public object EncodedDn([FromQuery] string name)
    {
        return new DirectoryEntry(
            $"LDAP://CN={Encoder.LdapDistinguishedNameEncode(name)},OU=Users,DC=example,DC=test");
    }

    [HttpGet]
    public object AliasEncodedFilter([FromQuery] string user)
    {
        return new DirectorySearcher(
            "(employeeNumber=" + LdapEncoder.LdapFilterEncode(user) + ")");
    }

    [HttpGet]
    public object WrongContextEncoder([FromQuery] string user)
    {
        return new DirectorySearcher(
            "(uid=" + Encoder.LdapDistinguishedNameEncode(user) + ")");
    }

    [HttpPost]
    public void StructuredArguments([FromBody] string argument)
    {
        var startInfo = new ProcessStartInfo("trusted-tool")
        {
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add(argument);
        Process.Start(startInfo);
    }
}

public class LookalikeController : ControllerBase
{
    [HttpGet]
    public object Search([FromQuery] string value)
    {
        var searcher = new DirectorySearcherLookalike(value);
        searcher.Filter = value;
        return searcher;
    }
}

public class DirectorySearcherLookalike
{
    public DirectorySearcherLookalike(string value) { }
    public string Filter { get; set; } = "";
}
