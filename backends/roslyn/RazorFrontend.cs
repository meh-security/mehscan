using System.Collections.Immutable;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

// A source frontend, not a project build or a taint backend. Only the explicitly
// selected SDK's official generator and installed framework references are loaded.
internal static class RazorFrontend
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    private sealed record Input(string Path, string Text);
    private sealed record Request(string SchemaVersion, string Root, string SdkPath, Input[] Files, Input[] Projects);
    private sealed record Mapping(int GeneratedStart, int GeneratedEnd, string Path, int OriginalStart);
    private sealed record Navigation(string Path, int Start, int End, string Value);
    private sealed record SourceRange(int Start, int End);
    private sealed record Projection(string Path, string Code, Mapping[] Mappings, Navigation[] Facts, SourceRange[] NonCode);

    internal static int Run()
    {
        try
        {
            Console.InputEncoding = new UTF8Encoding(false, true);
            Console.OutputEncoding = new UTF8Encoding(false, true);
            var request = JsonSerializer.Deserialize<Request>(Console.In.ReadToEnd(), Json)
                ?? throw new InvalidDataException("Empty Razor request");
            if (request.SchemaVersion != "1" || request.Files.Length > 4096
                || request.Files.Sum(f => (long)Encoding.UTF8.GetByteCount(f.Text)) > 32 * 1024 * 1024)
                throw new InvalidDataException("Unsupported or oversized Razor request");
            var sdk = Path.GetFullPath(request.SdkPath);
            var generatorDirectory = Path.Combine(sdk, "Sdks", "Microsoft.NET.Sdk.Razor", "source-generators");
            var generatorPath = new[] { "Microsoft.CodeAnalysis.Razor.Compiler.dll", "Microsoft.NET.Sdk.Razor.SourceGenerators.dll" }
                .Select(n => Path.Combine(generatorDirectory, n)).FirstOrDefault(File.Exists)
                ?? throw new FileNotFoundException("Selected SDK does not contain an official Razor source generator");
            var load = new SdkLoadContext(generatorDirectory);
            var assembly = load.LoadFromAssemblyPath(generatorPath);
            foreach (var dependency in assembly.GetReferencedAssemblies().Where(a => a.Name is "Microsoft.CodeAnalysis" or "Microsoft.CodeAnalysis.CSharp"))
                if (dependency.Version > typeof(Compilation).Assembly.GetName().Version)
                    throw new InvalidDataException($"Selected SDK requires Roslyn {dependency.Version}; helper hosts {typeof(Compilation).Assembly.GetName().Version}. Update the helper or select a compatible installed SDK");
            var type = assembly.GetType("Microsoft.NET.Sdk.Razor.SourceGenerators.RazorSourceGenerator", true)!;
            var instance = Activator.CreateInstance(type);
            var generator = instance is IIncrementalGenerator incremental ? incremental.AsSourceGenerator()
                : instance as ISourceGenerator ?? throw new InvalidDataException("SDK generator is incompatible with this Roslyn helper");
            var root = Path.GetFullPath(request.Root.Replace('/', Path.DirectorySeparatorChar));
            string Full(string path) => Path.GetFullPath(Path.Combine(root, path.Replace('/', Path.DirectorySeparatorChar)));
            var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
            var inputs = request.Files.ToDictionary(f => Full(f.Path), f => f, comparer);
            static string ParseText(string text) => text.StartsWith('\uFEFF') ? text[1..] : text;
            var sourceTexts = inputs.ToDictionary(p => p.Key, p => SourceText.From(ParseText(p.Value.Text)), comparer);
            var sourceOffsets = inputs.ToDictionary(p => p.Key, p => ByteOffsets(ParseText(p.Value.Text)), comparer);
            var projects = request.Projects.Select(p => (Input: p, Full: Full(p.Path), Directory: Path.GetDirectoryName(Full(p.Path))!)).ToArray();
            string? Owner(string full) => projects.Where(p => full.StartsWith(p.Directory + Path.DirectorySeparatorChar, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                .OrderByDescending(p => p.Directory.Length).Select(p => p.Full).FirstOrDefault();
            var warnings = new List<string>();
            var projections = new List<Projection>();
            var refs = FrameworkReferences(sdk, warnings);
            var razorFiles = inputs.Where(p => p.Key.EndsWith(".razor", StringComparison.OrdinalIgnoreCase) || p.Key.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase));
            foreach (var group in razorFiles.GroupBy(p => Owner(p.Key)))
            {
                var project = projects.FirstOrDefault(p => p.Full == group.Key);
                var projectRoot = group.Key == null ? root : project.Directory;
                var properties = new Dictionary<string, string>();
                string? sdkName = null;
                if (group.Key != null)
                {
                    try
                    {
                        using var xml = XmlReader.Create(new StringReader(project.Input.Text.TrimStart('\uFEFF')), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
                        var document = XDocument.Load(xml);
                        sdkName = document.Root?.Attribute("Sdk")?.Value;
                        foreach (var name in new[] { "RootNamespace", "RazorLangVersion", "LangVersion" })
                        {
                            var values = document.Descendants(name).Where(e => e.Attribute("Condition") == null && e.Parent?.Attribute("Condition") == null).Select(e => e.Value.Trim()).Distinct().ToArray();
                            if (values.Length == 1 && !values[0].Contains("$(")) properties[name] = values[0];
                        }
                        if (document.Descendants().Any(e => e.Attribute("Condition") != null || e.Name.LocalName == "Import"
                            || e.Name.LocalName is "Compile" or "RazorComponent" or "RazorGenerate"))
                            warnings.Add($"{project.Input.Path}: conditional/imported or explicit item settings are not evaluated; Razor coverage is partial");
                    }
                    catch (XmlException)
                    {
                        warnings.Add(project.Input.Path + ": project XML is unavailable or malformed; default Razor generation settings and unknown execution context used");
                    }
                }
                else warnings.Add("Razor files without project ownership use default generation settings; execution context is unknown");
                var ns = properties.GetValueOrDefault("RootNamespace", group.Key == null ? "RazorSource" : Path.GetFileNameWithoutExtension(project.Full).Replace('-', '_'));
                var parse = new CSharpParseOptions(LanguageVersion.Preview).WithFeatures(new Dictionary<string, string> { ["use-roslyn-tokenizer"] = "true" });
                if (properties.TryGetValue("LangVersion", out var version) && LanguageVersionFacts.TryParse(version, out var language)) parse = parse.WithLanguageVersion(language);
                var trees = inputs.Where(p => p.Key.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) && Owner(p.Key) == group.Key)
                    .Select(p => CSharpSyntaxTree.ParseText(ParseText(p.Value.Text), parse, p.Key)).ToArray();
                var compilation = CSharpCompilation.Create(ns, trees, refs, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
                var texts = group.Select(p => new RazorText(p.Key, ParseText(p.Value.Text))).ToArray();
                GeneratorDriver driver = CSharpGeneratorDriver.Create([generator], texts, parse,
                    new RazorOptions(projectRoot, ns, properties.GetValueOrDefault("RazorLangVersion", "Latest")));
                driver = driver.RunGenerators(compilation);
                var result = driver.GetRunResult();
                foreach (var error in result.Results.Where(r => r.Exception != null)) warnings.Add("Razor generator failed: " + error.Exception!.Message);
                foreach (var diagnostic in result.Diagnostics.Take(24))
                {
                    var mapped = diagnostic.Location.GetMappedLineSpan();
                    var where = mapped.IsValid && !string.IsNullOrEmpty(mapped.Path) && inputs.TryGetValue(Path.GetFullPath(mapped.Path), out var origin) ? origin.Path : project.Input?.Path ?? "Razor";
                    // Avoid absolute generator paths in portable scan artifacts.
                    warnings.Add($"{where}: {diagnostic.Id}: Razor generation diagnostic; inspect original markup/imports and references");
                }
                var produced = new HashSet<string>(comparer);
                foreach (var generated in result.Results.SelectMany(r => r.GeneratedSources))
                {
                    var syntax = generated.SyntaxTree.GetRoot();
                    var primary = syntax.DescendantTrivia(descendIntoTrivia: true).Select(t => t.GetStructure())
                        .OfType<PragmaChecksumDirectiveTriviaSyntax>().Select(t => Path.GetFullPath(t.File.ValueText))
                        .FirstOrDefault(inputs.ContainsKey);
                    if (primary == null) continue;
                    var code = generated.SourceText.ToString();
                    var generatedOffsets = ByteOffsets(code);
                    var bytes = Encoding.UTF8.GetBytes(code);
                    void Mask(int start, int end, bool statement = false)
                    {
                        for (var i = start; i < end; i++) if (bytes[i] is not (10 or 13)) bytes[i] = 32;
                        if (statement) { var last = end - 1; while (last >= start && bytes[last] is 10 or 13) last--; if (last >= start) bytes[last] = (byte)';'; }
                    }
                    // Tree-sitter does not understand Roslyn's enhanced #line
                    // directives. Mask compiler directives at identical UTF-8
                    // byte offsets, without interpreting strings as directives.
                    foreach (var directive in syntax.DescendantTrivia(descendIntoTrivia: true).Select(t => t.GetStructure()).OfType<DirectiveTriviaSyntax>())
                        Mask(generatedOffsets[directive.SpanStart], generatedOffsets[directive.Span.End]);
                    var mappings = new List<Mapping>();
                    var facts = new List<Navigation>();
                    var nonCode = new List<SourceRange>();
                    var visited = 0;
                    foreach (var node in syntax.DescendantNodes())
                    {
                        if (++visited > 250000) { warnings.Add(inputs[primary].Path + ": generated syntax budget exceeded; mapped C# coverage is partial"); break; }
                        var mapped = node.GetLocation().GetMappedLineSpan();
                        if (!mapped.HasMappedPath || !mapped.IsValid || !comparer.Equals(Path.GetFullPath(mapped.Path), primary)
                            || !inputs.TryGetValue(primary, out var original)) continue;
                        var originalText = sourceTexts[primary];
                        int start, end;
                        try { start = originalText.Lines.GetPosition(mapped.StartLinePosition); end = originalText.Lines.GetPosition(mapped.EndLinePosition); }
                        catch (ArgumentOutOfRangeException) { continue; }
                        if (start < 0 || start >= end || end > originalText.Length
                            || originalText.ToString(TextSpan.FromBounds(start, end)) != node.ToString()) continue;
                        var bom = original.Text.StartsWith('\uFEFF') ? 3 : 0;
                        var byteStart = sourceOffsets[primary][start] + bom;
                        var byteEnd = sourceOffsets[primary][end] + bom;
                        if (Encoding.UTF8.GetString(bytes, generatedOffsets[node.SpanStart], generatedOffsets[node.Span.End] - generatedOffsets[node.SpanStart]) != node.ToString()) continue;
                        mappings.Add(new(generatedOffsets[node.SpanStart], generatedOffsets[node.Span.End], original.Path, byteStart));
                        if (node is LiteralExpressionSyntax or InterpolatedStringTextSyntax) nonCode.Add(new(byteStart, byteEnd));
                        if (node is IdentifierNameSyntax && node.Ancestors().OfType<InvocationExpressionSyntax>().Any(call =>
                            call.Expression.ToString().Contains("global::Microsoft.AspNetCore.Components.EventCallback.Factory")
                            || call.Expression.ToString().Contains("global::Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers.CreateInferredEventCallback")
                            || call.Expression.ToString().Contains("global::Microsoft.AspNetCore.Components.BindConverter.FormatValue")))
                            facts.Add(new(original.Path, byteStart, byteEnd, "Framework-generated event/bind callback references this source expression; callback invocation, input trust and state flow require review"));
                        if (node is AttributeSyntax attribute && new[] { "Parameter", "SupplyParameterFromQuery", "SupplyParameterFromForm" }
                            .Any(name => attribute.Name.ToString().Split('.').Last() is var observed && (observed == name || observed == name + "Attribute")))
                            facts.Add(new(original.Path, byteStart, byteEnd, "Observed component input attribute spelling: " + attribute.Name
                                + "; resolve framework ownership, supplying caller and validation in original source"));
                    }
                    // Keep maximal exact regions; these are the only admissible source anchors.
                    var ordered = mappings.OrderBy(m => m.GeneratedStart).ThenByDescending(m => m.GeneratedEnd).ToArray();
                    var regions = new List<Mapping>();
                    foreach (var mapping in ordered)
                        if (regions.Count == 0 || regions[^1].GeneratedEnd < mapping.GeneratedEnd) regions.Add(mapping);
                    // Pure framework rendering statements can contain large
                    // documentation literals. They are neither source operations
                    // nor needed C# enclosing context. Keep mixed statements that
                    // contain any original expression, and all user method bodies.
                    foreach (var statement in syntax.DescendantNodes().OfType<ExpressionStatementSyntax>())
                    {
                        var start = generatedOffsets[statement.SpanStart]; var end = generatedOffsets[statement.Span.End];
                        if (!regions.Any(m => m.GeneratedStart < end && m.GeneratedEnd > start)) Mask(start, end, statement: true);
                    }
                    // Drop only whitespace-only compiler lines outside every
                    // mapped user region. Translate all byte intervals together;
                    // never compact source lines or offsets independently.
                    var translated = new int[bytes.Length + 1];
                    using var compacted = new MemoryStream();
                    for (var begin = 0; begin < bytes.Length;)
                    {
                        var end = begin; while (end < bytes.Length && bytes[end] != 10) end++;
                        if (end < bytes.Length) end++;
                        var white = true; for (var i = begin; i < end; i++) if (bytes[i] is not (9 or 10 or 13 or 32)) { white = false; break; }
                        var skip = white && !regions.Any(m => m.GeneratedStart < end && m.GeneratedEnd > begin);
                        for (var i = begin; i < end; i++) { translated[i] = (int)compacted.Length; if (!skip) compacted.WriteByte(bytes[i]); }
                        begin = end;
                    }
                    translated[bytes.Length] = (int)compacted.Length;
                    regions = regions.Select(m => m with { GeneratedStart = translated[m.GeneratedStart], GeneratedEnd = translated[m.GeneratedEnd] }).ToList();
                    code = Encoding.UTF8.GetString(compacted.ToArray());
                    foreach (var origin in regions.Select(m => m.Path).Distinct())
                    {
                        produced.Add(Full(origin));
                        var input = inputs[Full(origin)];
                        var navigation = facts.Where(f => f.Path == origin).Distinct().Take(12).ToList();
                        var offset = 0;
                        foreach (var line in input.Text.Split('\n'))
                        {
                            var trimmed = line.TrimStart('\uFEFF', ' ', '\t', '\r');
                            if (new[] { "@rendermode ", "@page ", "@inject ", "@inherits " }.Any(trimmed.StartsWith))
                                navigation.Add(new(origin, offset, offset + Encoding.UTF8.GetByteCount(line), "Observed Razor directive: " + line.Trim() + "; inherited/effective execution and reachability remain to be checked"));
                            offset += Encoding.UTF8.GetByteCount(line) + 1;
                        }
                        navigation.Insert(0, new(origin, 0, 0, "Razor source frontend; project SDK=" + (sdkName ?? "unknown")
                            + "; source-only generation does not resolve all package components, imported project settings or inherited render modes. Server/client/Auto, prerender versus callbacks, bindings and validation must be checked in original source"));
                        projections.Add(new(origin, code, regions.Where(m => m.Path == origin).ToArray(), navigation.Take(24).ToArray(), nonCode.Distinct().ToArray()));
                    }
                }
                foreach (var missing in group.Where(p => !produced.Contains(p.Key))) warnings.Add(missing.Value.Path + ": no exact mapped C# regions; markup-only coverage retained");
            }
            Console.Write(JsonSerializer.Serialize(new { schema_version = "1", projections, diagnostics = warnings.Distinct().Take(128) }, Json));
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine("Razor frontend: " + error.Message); return 2; }
    }

    private static int[] ByteOffsets(string text)
    {
        var offsets = new int[text.Length + 1];
        for (int i = 0, bytes = 0; i < text.Length;)
        {
            var width = char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            offsets[i] = bytes;
            if (width == 2) offsets[i + 1] = bytes;
            bytes += Encoding.UTF8.GetByteCount(text.AsSpan(i, width));
            i += width;
            offsets[i] = bytes;
        }
        return offsets;
    }

    private static MetadataReference[] FrameworkReferences(string sdk, List<string> warnings)
    {
        var root = Directory.GetParent(Directory.GetParent(sdk)!.FullName)!.FullName;
        var major = Path.GetFileName(sdk).Split('.')[0];
        var references = new List<MetadataReference>();
        foreach (var pack in new[] { "Microsoft.NETCore.App.Ref", "Microsoft.AspNetCore.App.Ref" })
        {
            var directory = Path.Combine(root, "packs", pack);
            var version = Directory.Exists(directory) ? Directory.GetDirectories(directory)
                .Where(d => Path.GetFileName(d).StartsWith(major + ".")).OrderBy(d => Version.TryParse(Path.GetFileName(d), out var v) ? v : new Version()).LastOrDefault() : null;
            var path = version == null ? null : Path.Combine(version, "ref", "net" + major + ".0");
            if (path == null || !Directory.Exists(path)) { warnings.Add("Installed framework reference pack unavailable: " + pack); continue; }
            references.AddRange(Directory.GetFiles(path, "*.dll").Select(p => MetadataReference.CreateFromFile(p)));
        }
        return references.ToArray();
    }

    private sealed class SdkLoadContext(string directory) : AssemblyLoadContext
    {
        protected override Assembly? Load(AssemblyName name)
        {
            if (name.Name is "Microsoft.CodeAnalysis" or "Microsoft.CodeAnalysis.CSharp") return AssemblyLoadContext.Default.LoadFromAssemblyName(name);
            var path = Path.Combine(directory, name.Name + ".dll");
            return File.Exists(path) ? LoadFromAssemblyPath(path) : null;
        }
    }
    private sealed class RazorText(string path, string text) : AdditionalText
    {
        private readonly SourceText source = SourceText.From(text, Encoding.UTF8);
        public override string Path => path;
        public override SourceText GetText(CancellationToken cancellationToken = default) => source;
    }
    private sealed class Values(Dictionary<string, string> values) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value) => values.TryGetValue(key, out value!);
    }
    private sealed class RazorOptions(string root, string ns, string version) : AnalyzerConfigOptionsProvider
    {
        public override AnalyzerConfigOptions GlobalOptions { get; } = new Values(new() { ["build_property.RazorLangVersion"] = version, ["build_property.RootNamespace"] = ns, ["build_property.MSBuildProjectDirectory"] = root });
        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => new Values(new());
        public override AnalyzerConfigOptions GetOptions(AdditionalText text) => new Values(new() { ["build_metadata.AdditionalFiles.TargetPath"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(Path.GetRelativePath(root, text.Path).Replace('\\', '/'))) });
    }
}
