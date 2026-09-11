using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Management.Automation;
using System.Xml;

public class SafeAndLookalikeController : ControllerBase
{
    [HttpPost]
    public object JsonNet([FromBody] string payload)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None
        };
        return JsonConvert.DeserializeObject(payload, settings);
    }

    [HttpPost]
    public void Xml([FromBody] string document)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };
        using var reader = XmlReader.Create(document, settings);
    }

    [HttpPost]
    public void CommandArgument([FromBody] string argument)
    {
        var shell = PowerShell.Create();
        shell.AddCommand("Get-Item").AddArgument(argument).Invoke();

        var startInfo = new ProcessStartInfo("trusted-tool");
        startInfo.ArgumentList.Add(argument);
        System.Diagnostics.Process.Start(startInfo);
    }

    [HttpPost]
    public void AmbiguousFileMode([FromQuery] string path)
    {
        using var stream = new FileStream(path, FileMode.OpenOrCreate);
    }

    [HttpPost]
    public void Lookalike([FromQuery] string path, FakeZipEntry entry)
    {
        entry.ExtractToFile(path);
    }

    [HttpPost]
    public object LocalFactory([FromQuery] string name)
    {
        return Create(name);
    }

    private object Create(string name) => new { name };
}

public class FakeZipEntry
{
    public void ExtractToFile(string path) { }
}
