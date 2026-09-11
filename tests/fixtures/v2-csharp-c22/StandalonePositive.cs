using System;
using System.Diagnostics;
using Microsoft.CodeDom.Providers.DotNetCompilerPlatform;
using fastJSON;
using MBrace.FsPickler.Json;
using Microsoft.SqlServer.Management.Common;
using Microsoft.SqlServer.Management.Smo;

public class StandalonePositive
{
    public void Run()
    {
        var compiler = new CSharpCodeProvider();
        compiler.CompileAssemblyFromSource(null, Console.ReadLine());

        JSON.ToObject(Console.ReadLine(), new JSONParameters { BadListTypeChecking = false });

        var serializer = FsPickler.CreateJsonSerializer();
        serializer.Deserialize<object>(Console.ReadLine());

        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = Console.ReadLine();
        startInfo = new ProcessStartInfo("cmd.exe", Console.ReadLine());

        var server = new Server(new ServerConnection());
        server.ConnectionContext.ExecuteNonQuery(Console.ReadLine());
    }
}
