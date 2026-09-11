using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Management.Automation;
using System.Xml;

public class MainstreamController : ControllerBase
{
    [HttpPost]
    public object JsonNet([FromBody] string payload)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.Auto
        };
        return JsonConvert.DeserializeObject(payload, settings);
    }

    [HttpPost]
    public void Xml([FromBody] string document)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = new XmlUrlResolver();
        using var reader = XmlReader.Create(document, settings);
    }

    [HttpPost]
    public void Script([FromBody] string script)
    {
        using var shell = PowerShell.Create();
        shell.AddScript(script);
        shell.Invoke();
    }

    [HttpPost]
    public void Process([FromQuery] string command)
    {
        var startInfo = new ProcessStartInfo { FileName = command };
        System.Diagnostics.Process.Start(startInfo);
    }

    [HttpGet]
    public object Read([FromQuery] string path)
    {
        return new FileStream(path, FileMode.Open);
    }

    [HttpPost]
    public object Write([FromQuery] string path)
    {
        return new FileStream(path, FileMode.Create);
    }

    [HttpPost]
    public void Copy([FromQuery] string source, [FromQuery] string destination)
    {
        File.Copy(source, destination);
    }

    [HttpPost]
    public void Move([FromQuery] string source, [FromQuery] string destination)
    {
        File.Move(source, destination);
    }

    [HttpPost]
    public void Extract([FromQuery] string destination, ZipArchiveEntry entry)
    {
        entry.ExtractToFile(destination);
    }
}
