using System.Diagnostics;
using Microsoft.CodeDom.Providers.DotNetCompilerPlatform;
using fastJSON;
using MBrace.FsPickler.Json;
using Microsoft.SqlServer.Management.Common;
using Microsoft.SqlServer.Management.Smo;

public class StandaloneSafe
{
    public void Run(string trustedPayload)
    {
        var compiler = new CSharpCodeProvider();
        compiler.CompileAssemblyFromSource(null, "public class Fixed {}");

        JSON.ToObject(trustedPayload, new JSONParameters { BadListTypeChecking = true });

        var serializer = FsPickler.CreateJsonSerializer();
        serializer.Deserialize<object>(trustedPayload);

        var startInfo = new ProcessStartInfo("fixed.exe", "--fixed");

        var server = new Server(new ServerConnection());
        server.ConnectionContext.ExecuteNonQuery("SELECT 1");
    }
}
