using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.Security.Application;
using MongoDB.Bson;
using MongoDB.Driver;

public class OriginCases : Controller
{
    private string markup;
    private string program;
    private Stream payload;
    private string document;
    private string filter;
    private string value;
    private string executable;
    private string arguments;
    private string text;

    public object TrustedHtml()
    {
        return Html.Raw(markup);
    }

    public Task<object> DynamicCode()
    {
        return CSharpScript.EvaluateAsync<object>(program);
    }

    public object ObjectGraph()
    {
        return new BinaryFormatter().Deserialize(payload);
    }

    public BsonDocument RawNoSql()
    {
        return BsonDocument.Parse(document);
    }

    public DirectorySearcher LdapFilter()
    {
        return new DirectorySearcher(filter);
    }

    public DirectorySearcher EncodedLdapFilter()
    {
        return new DirectorySearcher(Encoder.LdapFilterEncode(value));
    }

    public Process DynamicExecutable()
    {
        return Process.Start(executable);
    }

    public Process ShellText()
    {
        var startInfo = new ProcessStartInfo("cmd.exe", arguments);
        return Process.Start(startInfo);
    }

    public Task OrdinaryHtml(HttpResponse response)
    {
        return response.WriteAsync(text);
    }

    public Process StructuredArguments()
    {
        return Process.Start("tool.exe", arguments);
    }

    public object TypedMongoFilter(
        IMongoCollection<BsonDocument> collection,
        FilterDefinition<BsonDocument> filter)
    {
        return collection.Find(filter);
    }

    public DirectorySearcher FixedLdapFilter()
    {
        return new DirectorySearcher("(objectClass=user)");
    }

    public Task<object> FixedProgram()
    {
        return CSharpScript.EvaluateAsync<object>("1 + 1");
    }
}
