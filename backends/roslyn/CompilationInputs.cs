using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

internal static partial class Program
{
    private sealed record CompilationInput(CSharpCompilation Compilation, SyntaxTree[] Trees,
        Diagnostic[] Errors, Dictionary<SyntaxTree, SemanticModel> Models, Diagnostic[] ScopeErrors,
        string[] Conflicts, bool IncompleteDependencies, bool MissingMetadata);

    // Explicit source-project contexts only. A CompilationReference shares
    // compiler symbols in memory; no target binary, task or generator is run.
    private static Dictionary<string, CompilationInput> CompileInputs(Request request, Context context,
        SortedDictionary<string, Source> sources, Dictionary<string, PortableExecutableReference> metadata,
        SortedDictionary<string, string> referenceHashes)
    {
        var declared = new Dictionary<string, Project>(StringComparer.Ordinal);
        foreach (var project in context.Projects)
            if (string.IsNullOrWhiteSpace(project.Id) || !declared.TryAdd(project.Id, project))
                throw new InvalidDataException("Project IDs must be nonempty and unique");
        // Validate the entire supplied graph, even when no requested operand
        // needs it. Skipping semantic work must not accept cycles/missing links.
        var validated = new HashSet<string>(StringComparer.Ordinal);
        var validating = new HashSet<string>(StringComparer.Ordinal);
        void ValidateGraph(string id)
        {
            if (!declared.TryGetValue(id, out var project))
                throw new InvalidDataException($"Source project reference has no supplied context: {id}");
            if (validated.Contains(id)) return;
            if (validating.Count >= 64 || validating.Contains(id))
                throw new InvalidDataException("Source project references contain a cycle or exceed 64 levels");
            validating.Add(id);
            foreach (var dependency in project.ProjectReferences ?? []) ValidateGraph(dependency);
            validating.Remove(id);
            validated.Add(id);
        }
        foreach (var id in declared.Keys) ValidateGraph(id);

        // Retain the full declared input binding. Only parsing, compilation and
        // semantic diagnostics become demand-driven; source/reference changes
        // still invalidate this snapshot, including currently unused contexts.
        foreach (var project in context.Projects)
        {
            if (string.IsNullOrWhiteSpace(project.TargetFramework))
                throw new InvalidDataException("An explicit target_framework is required");
            if (!LanguageVersionFacts.TryParse(project.LanguageVersion, out var language)
                || language is LanguageVersion.Default or LanguageVersion.Latest or LanguageVersion.Preview
                    or LanguageVersion.LatestMajor)
                throw new InvalidDataException("An explicit supported numeric language_version is required");
            if (project.OutputKind is not ("library" or "console" or "windows"))
                throw new InvalidDataException("output_kind must be library, console or windows");
            if (project.GlobalUsings is { Length: > 0 } imports
                && (imports.Length > 64 || imports.Any(n => string.IsNullOrWhiteSpace(n)
                    || n.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '_'))
                    || SyntaxFactory.ParseName(n).ContainsDiagnostics)))
                throw new InvalidDataException("global_usings must contain namespace names");
            foreach (var path in project.Sources.Select(p => p.Replace('\\', '/')).Distinct())
            {
                if (sources.ContainsKey(path)) continue;
                var bytes = File.ReadAllBytes(SourcePath(request.Root, path));
                if (bytes.Length > 2 * 1024 * 1024) throw new InvalidDataException("Source exceeds 2 MiB");
                sources[path] = new(path, new UTF8Encoding(false, true).GetString(bytes), Hash(bytes));
            }
            foreach (var path in References(project))
                if (!referenceHashes.ContainsKey(path)) referenceHashes[path] = Hash(File.ReadAllBytes(path));
        }
        var inputs = new Dictionary<string, CompilationInput>(StringComparer.Ordinal);
        var active = new HashSet<string>(StringComparer.Ordinal);
        CompilationInput Build(string id)
        {
            if (inputs.TryGetValue(id, out var existing)) return existing;
            if (!declared.TryGetValue(id, out var project))
                throw new InvalidDataException($"Source project reference has no supplied context: {id}");
            if (active.Count >= 64 || !active.Add(id))
                throw new InvalidDataException("Source project references contain a cycle or exceed 64 levels");
            var dependencies = (project.ProjectReferences ?? []).Distinct().Select(Build).ToArray();
            LanguageVersionFacts.TryParse(project.LanguageVersion, out var language);
            var options = new CSharpParseOptions(language, preprocessorSymbols: project.Defines);
            var trees = project.Sources.Select(p => p.Replace('\\', '/')).Distinct().Order().Select(path => {
                return CSharpSyntaxTree.ParseText(sources[path].Text, options, path);
            }).ToArray();
            var files = References(project).Select(path => {
                if (!metadata.TryGetValue(path, out var reference))
                {
                    metadata[path] = reference = MetadataReference.CreateFromFile(path);
                }
                return reference;
            }).ToArray();
            var compilationTrees = trees.AsEnumerable();
            if (project.GlobalUsings is { Length: > 0 } imports)
            {
                compilationTrees = compilationTrees.Append(CSharpSyntaxTree.ParseText(
                    string.Join("\n", imports.Distinct().Select(n => $"global using {n};")), options));
            }
            var leaf = Path.GetFileName(project.Id.Replace('\\', '/'));
            var assembly = project.AssemblyName ?? (leaf.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                ? Path.GetFileNameWithoutExtension(leaf) : leaf);
            var compilation = CSharpCompilation.Create(assembly, compilationTrees,
                files.Cast<MetadataReference>().Concat(dependencies.Select(d => d.Compilation.ToMetadataReference())),
                new CSharpCompilationOptions(project.OutputKind switch {
                    "library" => OutputKind.DynamicallyLinkedLibrary,
                    "console" => OutputKind.ConsoleApplication,
                    "windows" => OutputKind.WindowsApplication,
                    _ => throw new InvalidDataException("output_kind must be library, console or windows") },
                    allowUnsafe: project.AllowUnsafe,
                    nullableContextOptions: project.Nullable ? NullableContextOptions.Enable : NullableContextOptions.Disable));
            var conflicts = files.Select(r => ReferenceName(r.FilePath!))
                .Concat(dependencies.Select(d => d.Compilation.AssemblyName)).Where(n => n != null)
                .GroupBy(n => n, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key!)
                .Concat(dependencies.SelectMany(d => d.Conflicts)).Distinct().ToArray();
            var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
            var models = trees.ToDictionary(t => t, t => compilation.GetSemanticModel(t));
            foreach (var dependency in dependencies)
                foreach (var pair in dependency.Models) models.TryAdd(pair.Key, pair.Value);
            var input = new CompilationInput(compilation, trees, errors, models,
                errors.Concat(dependencies.SelectMany(d => d.ScopeErrors)).Distinct().ToArray(), conflicts,
                dependencies.Any(d => d.Errors.Length > 0 || d.IncompleteDependencies || d.MissingMetadata),
                project.UnresolvedReferences is { Length: > 0 });
            inputs[id] = input;
            active.Remove(id);
            return input;
        }
        var queriedPaths = request.Queries.Select(q => q.Operand.Path).ToHashSet(StringComparer.Ordinal);
        foreach (var project in context.Projects)
            if (project.Sources.Any(p => queriedPaths.Contains(p.Replace('\\', '/')))) Build(project.Id);
        return inputs;
    }
}
