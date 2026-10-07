using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Http;
using System.Net.Mime;
using System.Threading.Tasks;

public class ResponseFormats
{
    public async Task Json(HttpContext context, string input)
    {
        context.Response.ContentType = MediaTypeNames.Application.Json;
        await context.Response.WriteAsync(input);
    }
    public async Task Plain(HttpResponse response, string input)
    {
        response.ContentType = "text/plain; charset=utf-8";
        await response.WriteAsync(input);
    }
    public async Task Html(HttpContext context, string input)
    {
        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync(input);
    }
    public async Task Different(HttpContext context, HttpContext other, string input)
    {
        other.Response.ContentType = "application/json";
        await context.Response.WriteAsync(input);
    }
    public async Task Conditional(HttpContext context, string input, bool json)
    {
        if (json) context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(input);
    }
    public async Task Replaced(HttpContext context, string input)
    {
        context.Response.ContentType = "application/json";
        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync(input);
    }
    public async Task Intervening(HttpContext context, string input)
    {
        context.Response.ContentType = "application/json";
        Mutate(context);
        await context.Response.WriteAsync(input);
    }
    public async Task ArgumentMutation(HttpContext context)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(Mutate(context));
    }
    private string Mutate(HttpContext context) { context.Response.ContentType = "text/html"; return "value"; }
}

public class Rendering
{
    private static readonly HtmlString Space = new(" ");
    private readonly string Literal = "constant";
    private readonly HtmlString ReplacedField = new(" ");
    private readonly TagBuilder MutableField = new("span");
    public Rendering(string input = "") { ReplacedField = new HtmlString(input); }
    public IHtmlContent ReadonlyHtml() { var b = new HtmlContentBuilder(); b.AppendHtml(Space); return b; }
    public IHtmlContent ReadonlyString() => new HtmlString(Literal);
    public IHtmlContent EmptyHtml() { var b = new HtmlContentBuilder(); b.AppendHtml(HtmlString.Empty); return b; }
    public IHtmlContent ConstructorReplacement() { var b = new HtmlContentBuilder(); b.AppendHtml(ReplacedField); return b; }
    public IHtmlContent MutableFieldHtml(string input) { MutableField.InnerHtml.AppendHtml(input); var b = new HtmlContentBuilder(); b.AppendHtml(MutableField); return b; }
    public IHtmlContent EncodedRead(string input)
    {
        var encoded = HtmlEncoder.Default.Encode(input);
        Console.WriteLine(encoded);
        var alias = encoded;
        return new HtmlString(alias);
    }
    public IHtmlContent ImmutableHtmlRead(string input)
    {
        var encoded = new HtmlString(HtmlEncoder.Default.Encode(input));
        Console.WriteLine(encoded);
        var b = new HtmlContentBuilder(); b.AppendHtml(encoded); return b;
    }
    public IHtmlContent RefEncoded(string input)
    {
        var encoded = HtmlEncoder.Default.Encode(input);
        Replace(ref encoded, input);
        return new HtmlString(encoded);
    }
    public IHtmlContent CapturedEncoded(string input)
    {
        var encoded = HtmlEncoder.Default.Encode(input);
        Action replace = () => encoded = input; replace();
        return new HtmlString(encoded);
    }
    private void Replace(ref string output, string input) => output = input;
    public IHtmlContent Encoded(string input) => new HtmlString(HtmlEncoder.Default.Encode(input));
    public IHtmlContent Raw(string input) => new HtmlString(input);
    public IHtmlContent SuppliedEncoder(HtmlEncoder encoder, string input) => new HtmlString(encoder.Encode(input));
    public IHtmlContent Replaced(string input)
    {
        var content = HtmlEncoder.Default.Encode(input);
        content = input;
        return new HtmlString(content);
    }
    public IHtmlContent Child(string input)
    {
        var child = new TagBuilder("span");
        child.InnerHtml.Append(input);
        var parent = new HtmlContentBuilder();
        parent.AppendHtml(child);
        return parent;
    }
    public IHtmlContent Fragment(string input)
    {
        var child = new TagBuilder("a");
        child.Attributes["href"] = "#" + input;
        child.InnerHtml.Append(input);
        var parent = new HtmlContentBuilder();
        parent.AppendHtml(child);
        return parent;
    }
    public IHtmlContent RawChild(string input)
    {
        var child = new TagBuilder("span");
        child.InnerHtml.AppendHtml(input);
        var parent = new HtmlContentBuilder();
        parent.AppendHtml(child);
        return parent;
    }
    public IHtmlContent LaterRawChild(string input)
    {
        var child = new TagBuilder("span");
        var parent = new HtmlContentBuilder();
        parent.AppendHtml(child);
        child.InnerHtml.AppendHtml(input);
        return parent;
    }
    public IHtmlContent AliasedChild(string input)
    {
        var child = new TagBuilder("span");
        var alias = child;
        alias.InnerHtml.AppendHtml(input);
        var parent = new HtmlContentBuilder();
        parent.AppendHtml(child);
        return parent;
    }
    public IHtmlContent Link(string input)
    {
        var child = new TagBuilder("a");
        child.Attributes["href"] = input;
        var parent = new HtmlContentBuilder();
        parent.AppendHtml(child);
        return parent;
    }
    public IHtmlContent Script(string input)
    {
        var child = new TagBuilder("script");
        child.InnerHtml.Append(input);
        var parent = new HtmlContentBuilder();
        parent.AppendHtml(child);
        return parent;
    }
}

public class Client
{
    private string _baseUrl = "/";
    private string _otherUrl = "/";
    public string BaseUrl { get => _baseUrl; set => _baseUrl = value; }
    private void PrepareRequest(StringBuilder url) { }
    private void OtherHook(StringBuilder url) { }
    public HttpRequestMessage First(string id)
    {
        var builder = new StringBuilder();
        builder.Append(_baseUrl);
        builder.Append("api/first/").Append(Uri.EscapeDataString(id));
        PrepareRequest(builder);
        var url = builder.ToString();
        var request = new HttpRequestMessage();
        request.RequestUri = new Uri(url, UriKind.RelativeOrAbsolute);
        return request;
    }
    public HttpRequestMessage Second(string id)
    {
        var builder = new StringBuilder();
        builder.Append(_baseUrl);
        builder.Append("api/second/").Append(Uri.EscapeDataString(id));
        PrepareRequest(builder);
        var url = builder.ToString();
        var request = new HttpRequestMessage();
        request.RequestUri = new Uri(url, UriKind.RelativeOrAbsolute);
        return request;
    }
    public HttpRequestMessage DifferentHook(string id)
    {
        var builder = new StringBuilder();
        builder.Append(_baseUrl);
        builder.Append("api/third/").Append(Uri.EscapeDataString(id));
        OtherHook(builder);
        var url = builder.ToString();
        var request = new HttpRequestMessage();
        request.RequestUri = new Uri(url, UriKind.RelativeOrAbsolute);
        return request;
    }
    public HttpRequestMessage DifferentRoot(string id)
    {
        var builder = new StringBuilder();
        builder.Append(_otherUrl);
        builder.Append("api/fourth/").Append(Uri.EscapeDataString(id));
        PrepareRequest(builder);
        var url = builder.ToString();
        var request = new HttpRequestMessage();
        request.RequestUri = new Uri(url, UriKind.RelativeOrAbsolute);
        return request;
    }
    public HttpRequestMessage RawSuffix(string suffix)
    {
        var builder = new StringBuilder();
        builder.Append(_baseUrl);
        builder.Append("api/").Append(suffix);
        var url = builder.ToString();
        var request = new HttpRequestMessage();
        request.RequestUri = new Uri(url, UriKind.RelativeOrAbsolute);
        return request;
    }
    public HttpRequestMessage ReplacedUrl(string input)
    {
        var builder = new StringBuilder();
        builder.Append(_baseUrl);
        builder.Append("api/");
        var url = builder.ToString();
        url = input;
        var request = new HttpRequestMessage();
        request.RequestUri = new Uri(url, UriKind.RelativeOrAbsolute);
        return request;
    }
}

public class Storage
{
    private string Physical(string path, bool bypass = false) => path;
    private string OtherPhysical(string path) => path;
    public void DeleteOne(string path) { var physical = Physical(path); File.Delete(physical); }
    public void DeleteInline(string path) { File.Delete(Physical(path)); }
    public void DeleteInlineBypass(string path) { File.Delete(Physical(path, true)); }
    public void DeleteInlineUnknownOption(string path, bool bypass) { File.Delete(Physical(path, bypass)); }
    public void DeleteInlineModified(string path) { File.Delete(Physical(path) + path); }
    public void ReadInline(string path) { File.ReadAllText(Physical(path)); }
    public void DeleteTwo(string path) { var physical = Physical(path); File.Delete(physical); }
    public void DeleteNamed(string path) { var physical = Physical(bypass: false, path: path); File.Delete(physical); }
    public void DeleteNamedBypass(string path) { var physical = Physical(bypass: true, path: path); File.Delete(physical); }
    public void DeleteBypass(string path) { var physical = Physical(path, true); File.Delete(physical); }
    public void DeleteOther(string path) { var physical = OtherPhysical(path); File.Delete(physical); }
    public void DeleteReplaced(string path, string other) { var physical = Physical(path); physical = other; File.Delete(physical); }
    public string Read(string path) { var physical = Physical(path); return File.ReadAllText(physical); }
}
