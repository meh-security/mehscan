using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using DS = System.DirectoryServices;

public class InjectionRisksController : ControllerBase
{
    [HttpGet]
    public object Filter([FromQuery] string user)
    {
        return new DirectorySearcher("(uid=" + user + ")");
    }

    [HttpGet]
    public object AssignedFilter([FromQuery] string user)
    {
        var searcher = new DirectorySearcher();
        searcher.Filter = $"(mail={user})";
        return searcher;
    }

    [HttpGet]
    public object AliasFilter([FromQuery] string user)
    {
        return new DS.DirectorySearcher("(employeeNumber=" + user + ")");
    }

    [HttpGet]
    public object DistinguishedName([FromQuery] string name)
    {
        return new DirectoryEntry($"LDAP://CN={name},OU=Users,DC=example,DC=test");
    }

    [HttpGet]
    public object ProtocolFilter([FromQuery] string user)
    {
        return new SearchRequest("DC=example,DC=test", "(uid=" + user + ")", SearchScope.Subtree);
    }

    [HttpGet]
    public object ProtocolDn([FromQuery] string baseDn)
    {
        return new SearchRequest(baseDn, "(objectClass=user)", SearchScope.Subtree);
    }

    [HttpPost]
    public void FreeFormArguments([FromBody] string argument)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "trusted-tool",
            Arguments = argument,
            UseShellExecute = false
        };
        Process.Start(startInfo);
    }

    [HttpPost]
    public void ConstructorArguments([FromBody] string argument)
    {
        var startInfo = new ProcessStartInfo("trusted-tool", argument);
        Process.Start(startInfo);
    }

    [HttpPost]
    public void ExplicitInterpreter([FromBody] string command)
    {
        var startInfo = new ProcessStartInfo("cmd.exe")
        {
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add(command);
        Process.Start(startInfo);
    }
}
