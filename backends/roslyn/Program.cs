using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

// A source/reference-only semantic helper. It never evaluates a project, restores
// dependencies, emits binaries, or loads target analyzers/generators.
internal static class Program
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static int Main()
    {
        try
        {
            var request = JsonSerializer.Deserialize<Request>(Console.In.ReadToEnd(), Json)
                ?? throw new InvalidDataException("Empty semantic request");
            if (request.SchemaVersion != "1") throw new InvalidDataException("Unsupported request version");
            var contextText = File.ReadAllBytes(request.ContextPath);
            var context = JsonSerializer.Deserialize<Context>(contextText, Json)
                ?? throw new InvalidDataException("Empty semantic context");
            var sources = new SortedDictionary<string, Source>();
            var referenceHashes = new SortedDictionary<string, string>();
            var observations = new List<Observation>();
            var diagnostics = new List<DiagnosticRecord>();
            var projects = new List<ProjectRecord>();
            var ids = new HashSet<string>();
            foreach (var project in context.Projects)
            {
                if (string.IsNullOrWhiteSpace(project.Id) || !ids.Add(project.Id))
                    throw new InvalidDataException("Project IDs must be nonempty and unique");
                if (string.IsNullOrWhiteSpace(project.TargetFramework))
                    throw new InvalidDataException("An explicit target_framework is required");
                if (!LanguageVersionFacts.TryParse(project.LanguageVersion, out var language)
                    || language is LanguageVersion.Default or LanguageVersion.Latest or LanguageVersion.Preview
                    or LanguageVersion.LatestMajor)
                    throw new InvalidDataException("An explicit supported numeric language_version is required");
                var parseOptions = new CSharpParseOptions(language, preprocessorSymbols: project.Defines);
                var trees = project.Sources.Select(p => p.Replace('\\', '/')).Distinct().Order().Select(path =>
                {
                    path = path.Replace('\\', '/');
                    if (!sources.TryGetValue(path, out var source))
                    {
                        var full = SourcePath(request.Root, path);
                        var bytes = File.ReadAllBytes(full);
                        if (bytes.Length > 2 * 1024 * 1024) throw new InvalidDataException("Source exceeds 2 MiB");
                        source = new Source(path, new UTF8Encoding(false, true).GetString(bytes), Hash(bytes));
                        sources.Add(path, source);
                    }
                    return CSharpSyntaxTree.ParseText(source.Text, parseOptions, path);
                }).ToArray();
                var references = References(project).Select(path =>
                {
                    referenceHashes[path] = Hash(File.ReadAllBytes(path));
                    return MetadataReference.CreateFromFile(path);
                }).ToArray();
                var compilation = CSharpCompilation.Create(project.Id, trees, references,
                    new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
                        allowUnsafe: project.AllowUnsafe,
                        nullableContextOptions: project.Nullable ? NullableContextOptions.Enable : NullableContextOptions.Disable));
                var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
                projects.Add(new(project.Id, project.TargetFramework, project.LanguageVersion, errors.Length));
                foreach (var error in errors.Take(12))
                    diagnostics.Add(new(project.Id, error.Id, error.GetMessage(),
                        error.Location.IsInSource ? Location(sources[error.Location.SourceTree!.FilePath], error.Location.SourceSpan) : null));
                foreach (var query in request.Queries.Where(q => trees.Any(t => t.FilePath == q.Operand.Path)))
                {
                    var tree = trees.Single(t => t.FilePath == query.Operand.Path);
                    var source = sources[tree.FilePath];
                    var model = compilation.GetSemanticModel(tree);
                    var facts = new List<Fact>();
                    var root = tree.GetRoot();
                    var sinkSpan = Span(source, query.Sink);
                    var sinkNode = root.FindNode(sinkSpan, getInnermostNodeForTie: true);
                    bool Action(SyntaxNode n) => n is InvocationExpressionSyntax
                        or ObjectCreationExpressionSyntax or AssignmentExpressionSyntax;
                    var action = sinkNode.AncestorsAndSelf().FirstOrDefault(Action)
                        ?? sinkNode.DescendantNodes().Where(Action)
                            .Where(n => n.Span.Contains(Span(source, query.Operand)))
                            .OrderByDescending(n => n.Span.Length).FirstOrDefault();
                    var symbol = action == null ? null : Target(model.GetOperation(action));
                    if (symbol != null && !ErrorType(symbol))
                        facts.Add(new("sink", "semantic_identity", Location(source, action!.Span),
                            Identity(symbol, project), ["api_security_contract", "runtime_dispatch_and_replacement"]));
                    else
                        facts.Add(new(query.Role, "operand_boundary", query.Operand,
                            "Roslyn could not uniquely bind the selected operation", ["missing_or_ambiguous_symbol"]));

                    var operandSpan = Span(source, query.Operand);
                    var operand = root.FindNode(operandSpan, getInnermostNodeForTie: true);
                    if (operand.Span == operandSpan)
                        Producers(model, operand, query, project, sources, facts);
                    else
                        facts.Add(new(query.Role, "operand_boundary", query.Operand,
                            "Captured operand is not one complete C# syntax node", ["exact_operand_shape"]));
                    observations.Add(new(query.EvidenceId, project.Id, facts));
                }
            }
            var result = new Snapshot("1", "Roslyn " + typeof(CSharpCompilation).Assembly.GetName().Version,
                Hash(contextText), sources.Select(p => new FileHash(p.Key, p.Value.Hash)).ToArray(),
                referenceHashes.Select(p => new FileHash(p.Key, p.Value)).ToArray(),
                projects, observations, diagnostics);
            Console.Write(JsonSerializer.Serialize(result, Json));
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 2;
        }
    }

    private static void Producers(SemanticModel model, SyntaxNode operand, Query query,
        Project project, SortedDictionary<string, Source> sources, List<Fact> facts)
    {
        var source = sources[operand.SyntaxTree.FilePath];
        ExpressionSyntax? producer = operand as ExpressionSyntax;
        if (operand is IdentifierNameSyntax && model.GetSymbolInfo(operand).Symbol is ILocalSymbol local)
        {
            var declaration = local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
            var initializer = declaration?.Initializer?.Value;
            var owner = operand.Ancestors().FirstOrDefault(IsCallable);
            if (initializer == null || owner == null || initializer.Span.End > operand.SpanStart
                || initializer.Ancestors().FirstOrDefault(IsCallable) != owner || initializer.Span.Length > 2048)
            {
                facts.Add(new(query.Role, "operand_boundary", query.Operand,
                    "Local initializer ownership or shape is unsupported", ["local_producer_and_control_flow"]));
                return;
            }
            // Compiler symbol equality separates same-spelling shadowed locals.
            // Any intervening reference is a conservative stop, not a CFG proof.
            var intervening = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
                .FirstOrDefault(n => n.SpanStart >= initializer.Span.End && n.Span.End <= operand.SpanStart
                    && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local));
            if (intervening != null)
            {
                facts.Add(new(query.Role, "operand_boundary", Location(source, intervening.Span),
                    "Intervening reference to the compiler-resolved local", ["reaching_write_alias_or_handoff"]));
                return;
            }
            facts.Add(new(query.Role, "local_operand_origin", Location(source, initializer.Span),
                initializer.ToString(), ["reaching_assignment_and_control_flow", "producer_or_caller_control", "exact_interpretation_and_effect"]));
            producer = initializer;
        }
        if (producer is InvocationExpressionSyntax invocation)
        {
            if (model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method || ErrorType(method))
            {
                facts.Add(new(query.Role, "operand_boundary", Location(source, invocation.Span),
                    "Producer call has no unique valid compiler binding", ["missing_or_ambiguous_producer_implementation"]));
                return;
            }
            facts.Add(new(query.Role, "semantic_identity", Location(source, invocation.Span),
                Identity(method, project), ["callable_behavior", "runtime_dispatch_and_replacement"]));
            var declarations = method.DeclaringSyntaxReferences;
            if (declarations.Length == 1 && sources.TryGetValue(declarations[0].SyntaxTree.FilePath, out var helper))
            {
                var declaration = declarations[0].GetSyntax();
                // A definition location is navigation, not a return summary or trust contract.
                var name = declaration is MethodDeclarationSyntax named ? named.Identifier.Span : declaration.Span;
                facts.Add(new(query.Role, "semantic_definition", Location(helper, name),
                    method.ToDisplayString(), ["helper_return_and_effect", "runtime_dispatch_and_replacement", "producer_or_caller_control"]));
            }
        }
    }

    private static bool IsCallable(SyntaxNode n) => n is BaseMethodDeclarationSyntax
        or LocalFunctionStatementSyntax or AnonymousFunctionExpressionSyntax;

    private static ISymbol? Target(IOperation? op) => op switch
    {
        IInvocationOperation call => call.TargetMethod,
        IObjectCreationOperation creation => creation.Constructor,
        ISimpleAssignmentOperation assignment when assignment.Target is IPropertyReferenceOperation property => property.Property,
        _ => null
    };

    private static bool ErrorType(ISymbol symbol)
    {
        bool Invalid(ITypeSymbol type) => type.TypeKind == TypeKind.Error
            || type is INamedTypeSymbol named && named.TypeArguments.Any(Invalid)
            || type is IArrayTypeSymbol array && Invalid(array.ElementType);
        return symbol.ContainingType == null || Invalid(symbol.ContainingType)
            || symbol is IMethodSymbol method && (Invalid(method.ReturnType) || method.Parameters.Any(p => Invalid(p.Type)))
            || symbol is IPropertySymbol property && Invalid(property.Type);
    }

    private static string Identity(ISymbol symbol, Project project) =>
        $"{symbol.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat)} [assembly={symbol.ContainingAssembly.Identity}; target={project.TargetFramework}]";

    private static string SourcePath(string root, string path)
    {
        var directory = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(root, path.Replace('/', Path.DirectorySeparatorChar)));
        if (Path.IsPathRooted(path) || !full.StartsWith(directory, OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidDataException("Source path must stay within the scanned root");
        return full;
    }

    private static IEnumerable<string> References(Project project) => project.References
        .Concat(project.ReferenceDirectories.SelectMany(d => Directory.GetFiles(d, "*.dll")))
        .Select(Path.GetFullPath).Distinct().Order(StringComparer.Ordinal);

    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static Microsoft.CodeAnalysis.Text.TextSpan Span(Source source, SourceLocation location)
    {
        int Utf16(int offset)
        {
            var bytes = Encoding.UTF8.GetBytes(source.Text);
            if (offset < 0 || offset > bytes.Length) throw new InvalidDataException("Invalid byte offset");
            return new UTF8Encoding(false, true).GetCharCount(bytes.AsSpan(0, offset));
        }
        return Microsoft.CodeAnalysis.Text.TextSpan.FromBounds(Utf16(location.Start.ByteOffset), Utf16(location.End.ByteOffset));
    }

    private static SourceLocation Location(Source source, Microsoft.CodeAnalysis.Text.TextSpan span)
    {
        var text = Microsoft.CodeAnalysis.Text.SourceText.From(source.Text);
        Position At(int offset)
        {
            var line = text.Lines.GetLineFromPosition(offset);
            return new(line.LineNumber + 1, Encoding.UTF8.GetByteCount(source.Text.AsSpan(line.Start, offset - line.Start)) + 1,
                Encoding.UTF8.GetByteCount(source.Text.AsSpan(0, offset)));
        }
        return new(source.Path, At(span.Start), At(span.End));
    }

    private sealed record Request(string SchemaVersion, string Root, string ContextPath, Query[] Queries);
    private sealed record Context(Project[] Projects);
    private sealed record Project(string Id, string TargetFramework, string LanguageVersion, string[] Sources,
        string[] References, string[] ReferenceDirectories, string[] Defines, bool AllowUnsafe = false, bool Nullable = false);
    private sealed record Query(string EvidenceId, string Role, SourceLocation Sink, SourceLocation Operand);
    private sealed record Source(string Path, string Text, string Hash);
    private sealed record Position(int Line, int Column, int ByteOffset);
    private sealed record SourceLocation(string Path, Position Start, Position End);
    private sealed record Fact(string Role, string Kind, SourceLocation Location, string Value, string[] RemainingChecks);
    private sealed record FileHash(string Path, string Sha256);
    private sealed record ProjectRecord(string Id, string TargetFramework, string LanguageVersion, int CompilerErrors);
    private sealed record Observation(string EvidenceId, string ProjectId, List<Fact> Facts);
    private sealed record DiagnosticRecord(string ProjectId, string Code, string Message, SourceLocation? Location);
    private sealed record Snapshot(string SchemaVersion, string Backend, string ContextSha256,
        FileHash[] Sources, FileHash[] References, List<ProjectRecord> Projects,
        List<Observation> Observations, List<DiagnosticRecord> Diagnostics);
}
