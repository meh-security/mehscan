using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.FlowAnalysis;

// A source/reference-only semantic helper. It never evaluates a project, restores
// dependencies, emits binaries, or loads target analyzers/generators.
internal static partial class Program
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
            var timed = Environment.GetEnvironmentVariable("MEHSCAN_ROSLYN_TIMING") == "1";
            var elapsed = Stopwatch.StartNew();
            double filesystemMilliseconds = 0;
            int filesystemQueries = 0;
            double outputMilliseconds = 0, destinationMilliseconds = 0;
            int outputQueries = 0, destinationQueries = 0;
            var request = JsonSerializer.Deserialize<Request>(Console.In.ReadToEnd(), Json)
                ?? throw new InvalidDataException("Empty semantic request");
            if (request.SchemaVersion != "1") throw new InvalidDataException("Unsupported request version");
            var contextText = File.ReadAllBytes(request.ContextPath);
            var context = JsonSerializer.Deserialize<Context>(contextText, Json)
                ?? throw new InvalidDataException("Empty semantic context");
            var sources = new SortedDictionary<string, Source>();
            var referenceHashes = new SortedDictionary<string, string>();
            var metadata = new Dictionary<string, PortableExecutableReference>(StringComparer.OrdinalIgnoreCase);
            var observations = new List<Observation>();
            var diagnostics = new List<DiagnosticRecord>();
            var projects = new List<ProjectRecord>();
            var inputs = CompileInputs(request, context, sources, metadata, referenceHashes);
            foreach (var project in context.Projects)
            {
                var input = inputs[project.Id];
                var trees = input.Trees;
                var conflicts = input.Conflicts;
                if (conflicts.Length > 0)
                {
                    projects.Add(new(project.Id, project.TargetFramework, project.LanguageVersion, 0,
                        project.UnresolvedReferences?.Length ?? 0, conflicts.Length));
                    foreach (var conflict in conflicts.Take(12))
                        diagnostics.Add(new(project.Id, "MEHSCAN_REFERENCE_CONFLICT",
                            $"Multiple references define {conflict}; provide an explicit resolved reference set. Project facts withheld.", null));
                    continue;
                }
                var errors = input.Errors;
                projects.Add(new(project.Id, project.TargetFramework, project.LanguageVersion, errors.Length,
                    project.UnresolvedReferences?.Length ?? 0, 0, input.IncompleteDependencies));
                foreach (var error in errors.Take(12))
                    diagnostics.Add(new(project.Id, error.Id, error.GetMessage(),
                        error.Location.IsInSource && sources.TryGetValue(error.Location.SourceTree!.FilePath, out var errorSource)
                            ? Location(errorSource, error.Location.SourceSpan) : null));
                var models = input.Models;
                foreach (var query in request.Queries.Where(q => trees.Any(t => t.FilePath == q.Operand.Path)))
                {
                    var tree = trees.Single(t => t.FilePath == query.Operand.Path);
                    var source = sources[tree.FilePath];
                    var model = models[tree];
                    var facts = new List<Fact>();
                    var locallyCompletePathSelection = false;
                    var locallyCompleteSelectionIdentity = false;
                    var locallyCompleteOutput = false;
                    var locallyCompleteDestination = false;
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
                            Identity(symbol, project), ["api_security_contract", "runtime_dispatch_and_replacement", "caller_or_entrypoint_reachability"]));
                    else
                        facts.Add(new(query.Role, "operand_boundary", query.Operand,
                            "Roslyn could not uniquely bind the selected operation", ["missing_or_ambiguous_symbol"]));

                    if (action != null && symbol != null && !ErrorType(symbol))
                        Receiver(model, action, query, project, source, sources, facts);

                    var operandSpan = Span(source, query.Operand);
                    var operand = root.FindNode(operandSpan, getInnermostNodeForTie: true);
                    if (operand.Span == operandSpan)
                    {
                        Producers(model, operand, query, project, sources, facts);
                        if (query.Role == "path")
                        {
                            var started = timed ? Stopwatch.GetTimestamp() : 0;
                            locallyCompletePathSelection = FilesystemShape(model, operand, action, query, sources, facts, input.ScopeErrors, models);
                            locallyCompleteSelectionIdentity = FilesystemIdentity(model, operand, action, query, sources, facts, errors);
                            locallyCompleteSelectionIdentity = FilesystemProducer(model, operand, action,
                                locallyCompleteSelectionIdentity, sources, facts, errors) || locallyCompleteSelectionIdentity;
                            if (timed) { filesystemMilliseconds += Stopwatch.GetElapsedTime(started).TotalMilliseconds; filesystemQueries++; }
                        }
                        if (query.Role == "content")
                        {
                            var started = timed ? Stopwatch.GetTimestamp() : 0;
                            locallyCompleteOutput = NonHtmlResponse(model, operand, action, query, facts, errors)
                                || HtmlShape(model, operand, action, query, sources, facts, errors);
                            if (timed) { outputMilliseconds += Stopwatch.GetElapsedTime(started).TotalMilliseconds; outputQueries++; }
                        }
                        if (query.Role == "endpoint")
                        {
                            var started = timed ? Stopwatch.GetTimestamp() : 0;
                            locallyCompleteDestination = DestinationIdentity(model, operand, action, query, sources, facts, errors);
                            if (timed) { destinationMilliseconds += Stopwatch.GetElapsedTime(started).TotalMilliseconds; destinationQueries++; }
                        }
                    }
                    else
                        facts.Add(new(query.Role, "operand_boundary", query.Operand,
                            "Captured operand is not one complete C# syntax node", ["exact_operand_shape"]));
                    ValueTypes(model, root, query, source, facts);
                    observations.Add(new(query.EvidenceId, project.Id, facts, locallyCompletePathSelection, locallyCompleteSelectionIdentity,
                        locallyCompleteOutput, locallyCompleteDestination));
                }
            }
            var result = new Snapshot("1", "Roslyn " + typeof(CSharpCompilation).Assembly.GetName().Version,
                Hash(contextText), sources.Select(p => new FileHash(p.Key, p.Value.Hash)).ToArray(),
                referenceHashes.Select(p => new FileHash(p.Key, p.Value)).ToArray(),
                projects, observations, diagnostics);
            Console.Write(JsonSerializer.Serialize(result, Json));
            if (timed) Console.Error.Write(JsonSerializer.Serialize(new {
                total_ms = elapsed.Elapsed.TotalMilliseconds,
                filesystem_checks_ms = filesystemMilliseconds,
                filesystem_query_count = filesystemQueries,
                output_checks_ms = outputMilliseconds,
                output_query_count = outputQueries,
                destination_checks_ms = destinationMilliseconds,
                destination_query_count = destinationQueries
            }, Json));
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 2;
        }
    }

    private static void ValueTypes(SemanticModel model, SyntaxNode root, Query query, Source source, List<Fact> facts)
    {
        if (query.Composition == null) return;
        var span = Span(source, query.Composition);
        var composition = root.FindNode(span, getInnermostNodeForTie: true);
        if (composition.Span != span) return;
        var values = new List<ExpressionSyntax>();
        void Parts(ExpressionSyntax expression)
        {
            if (expression is BinaryExpressionSyntax binary && binary.IsKind(SyntaxKind.AddExpression))
            { Parts(binary.Left); Parts(binary.Right); }
            else if (expression is InterpolatedStringExpressionSyntax interpolation)
                values.AddRange(interpolation.Contents.OfType<InterpolationSyntax>().Select(i => i.Expression));
            else if (expression is not LiteralExpressionSyntax) values.Add(expression);
        }
        if (composition is not ExpressionSyntax expression) return;
        if (expression is IdentifierNameSyntax && model.GetSymbolInfo(expression).Symbol is ILocalSymbol local)
        {
            // A fallback composition capture can point at the SQL variable rather
            // than the inserted values. Navigate exact same-local writes from a
            // top-level reset; do not label the query string as one inserted value.
            var owner = expression.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            if (owner?.Body == null || owner.Span.Length > 32768
                || owner.DescendantNodes().Any(n => n is GotoStatementSyntax or LabeledStatementSyntax)) return;
            bool Writes(AssignmentExpressionSyntax assignment) => assignment.Left is IdentifierNameSyntax name
                && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(name).Symbol, local)
                && assignment.Ancestors().FirstOrDefault(IsCallable) == owner
                && assignment.Span.End <= expression.SpanStart;
            var writes = owner.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(Writes).ToArray();
            var reset = writes.LastOrDefault(a => a.IsKind(SyntaxKind.SimpleAssignmentExpression)
                && a.Parent is ExpressionStatementSyntax { Parent: BlockSyntax block } && block == owner.Body);
            var declaration = local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
            var initializer = declaration?.Initializer?.Value;
            if (reset != null)
                foreach (var write in writes.Where(a => a.SpanStart >= reset.SpanStart)) Parts(write.Right);
            else if (initializer != null && declaration?.Parent?.Parent is LocalDeclarationStatementSyntax { Parent: BlockSyntax block }
                && block == owner.Body && initializer.Span.End <= expression.SpanStart)
            {
                Parts(initializer);
                foreach (var write in writes) Parts(write.Right);
            }
            else return;
        }
        else Parts(expression);
        foreach (var value in values.Take(16))
        {
            var type = model.GetTypeInfo(value).Type;
            if (type == null || type.TypeKind == TypeKind.Error) continue;
            facts.Add(new("query_value", "semantic_identity", Location(source, value.Span),
                $"Observed SQL construction value has compiler type {type.ToDisplayString()}; observed terms do not exhaust or prove the reaching query",
                ["format_and_sql_grammar", "reaching_query_and_remaining_terms", "producer_or_caller_control"]));
        }
        if (values.Count > 16)
            facts.Add(new("query_value", "operand_boundary", query.Composition,
                "SQL construction value type window exceeded sixteen expressions; inspect the remaining terms",
                ["remaining_value_types", "reaching_query_and_remaining_terms"]));
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
            var captured = owner.DescendantNodes().OfType<IdentifierNameSyntax>().FirstOrDefault(n =>
                n.Ancestors().FirstOrDefault(IsCallable) != owner
                && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local));
            if (captured != null)
            {
                facts.Add(new(query.Role, "operand_boundary", Location(source, captured.Span),
                    "Compiler-resolved local is captured by a nested callable; reaching value not inferred",
                    ["capture_invocation_and_reaching_value", "producer_or_caller_control"]));
                return;
            }
            // Compiler symbol equality separates same-spelling shadowed locals.
            // Any intervening reference is a conservative stop, not a CFG proof.
            var intervening = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
                .Where(n => n.SpanStart >= initializer.Span.End && n.Span.End <= operand.SpanStart
                    && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local))
                .ToArray();
            if (intervening.Length != 0)
            {
                if (LocalFlow(model, operand, local, owner, query, sources, facts)) return;
                // Prefer a replacement over a later append/read so a reviewer can
                // see resets such as sql = ... after an earlier command. Textual
                // proximity is navigation only: a conditional write need not run,
                // and other references may alias, capture or mutate the value.
                var writes = intervening
                    .Where(n => n.Ancestors().FirstOrDefault(IsCallable) == owner)
                    .Select(n => n.Parent is AssignmentExpressionSyntax assignment && assignment.Left == n
                        ? assignment : null)
                    .OfType<AssignmentExpressionSyntax>()
                    // A write whose RHS contains this operand has not completed.
                    .Where(n => n.Span.End <= operand.SpanStart)
                    .OrderBy(n => n.SpanStart).ToArray();
                var write = writes.LastOrDefault(n => n.IsKind(SyntaxKind.SimpleAssignmentExpression))
                    ?? writes.LastOrDefault();
                var span = write == null ? intervening[0].Span
                    : write.Span.Length <= 2048 ? write.Span : write.Left.Span;
                var detail = write == null ? "Intervening reference to the compiler-resolved local"
                    : write.IsKind(SyntaxKind.SimpleAssignmentExpression)
                        ? "Observed local replacement before this operand; reaching value not inferred"
                        : "Observed compound local write before this operand; reaching value not inferred";
                facts.Add(new(query.Role, "operand_boundary", Location(source, span), detail,
                    ["reaching_write_alias_or_handoff", "branch_and_execution_order"]));
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
                // One exact source return, with call-site arguments left explicit.
                // No substitution, recursive summary or inferred security contract.
                if (method.IsStatic && declaration is MethodDeclarationSyntax body)
                {
                    var expression = body.ExpressionBody?.Expression
                        ?? (body.Body?.Statements is { Count: 1 } statements
                            && statements[0] is ReturnStatementSyntax returned ? returned.Expression : null);
                    if (expression != null && expression.Span.Length <= 2048)
                        facts.Add(new(query.Role, "local_operand_origin", Location(helper, expression.Span),
                            expression.ToString(), ["helper_argument_mapping", "producer_or_caller_control", "exact_interpretation_and_effect"]));
                }
            }
        }
    }

    // Possible producers of one immutable string local in the selected method.
    // Joins union alternatives; resets kill predecessors; appends retain them.
    // This is deliberately not path feasibility, global taint or a safe verdict.
    private static bool LocalFlow(SemanticModel model, SyntaxNode operand, ILocalSymbol local,
        SyntaxNode owner, Query query, SortedDictionary<string, Source> sources, List<Fact> facts,
        List<ExpressionSyntax>? reaching = null)
    {
        if (local.Type.SpecialType != SpecialType.System_String || owner is not BaseMethodDeclarationSyntax
            || owner.Span.Length > 32768 || owner.DescendantNodes().Any(n => n is TryStatementSyntax)) return false;
        var references = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
            .Where(n => SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local)).ToArray();
        if (references.Any(n => n.Ancestors().FirstOrDefault(IsCallable) != owner)) return false;
        foreach (var reference in references.Where(n => n.SpanStart < operand.SpanStart))
        {
            if (reference.Parent is RefExpressionSyntax
                || reference.Parent is ArgumentSyntax argument && !argument.RefKindKeyword.IsKind(SyntaxKind.None)) return false;
            var write = reference.Ancestors().OfType<AssignmentExpressionSyntax>()
                .FirstOrDefault(a => a.Left.Span.Contains(reference.Span));
            if (write != null && (write.Left != reference
                || !write.IsKind(SyntaxKind.SimpleAssignmentExpression) && !write.IsKind(SyntaxKind.AddAssignmentExpression))) return false;
        }
        ControlFlowGraph? graph;
        try { graph = ControlFlowGraph.Create(owner, model); }
        catch (ArgumentException) { return false; }
        if (graph == null || graph.Blocks.Length > 64) return false;
        var events = new List<(SyntaxNode Node, bool Keep, bool Selected)>[graph.Blocks.Length];
        var definitions = new Dictionary<int, SyntaxNode>();
        var selectedBlock = -1;
        void Visit(IOperation operation, List<(SyntaxNode, bool, bool)> list, int block)
        {
            foreach (var child in operation.ChildOperations) Visit(child, list, block);
            if (operation is ILocalReferenceOperation read && !read.IsDeclaration
                && SymbolEqualityComparer.Default.Equals(read.Local, local) && read.Syntax.Span == operand.Span)
            {
                list.Add((read.Syntax, false, true)); selectedBlock = block;
            }
            IOperation? value = operation switch {
                ISimpleAssignmentOperation { Target: ILocalReferenceOperation target } write
                    when SymbolEqualityComparer.Default.Equals(target.Local, local) => write.Value,
                ICompoundAssignmentOperation { Target: ILocalReferenceOperation target } write
                    when SymbolEqualityComparer.Default.Equals(target.Local, local) => write.Value,
                _ => null
            };
            if (value == null) return;
            var node = value.Syntax;
            bool Refers(IOperation op) => op is ILocalReferenceOperation reference
                && SymbolEqualityComparer.Default.Equals(reference.Local, local) || op.ChildOperations.Any(Refers);
            var keep = operation is ICompoundAssignmentOperation || Refers(value);
            definitions[node.SpanStart] = node;
            list.Add((node, keep, false));
        }
        foreach (var block in graph.Blocks)
        {
            var list = events[block.Ordinal] = new();
            foreach (var operation in block.Operations) Visit(operation, list, block.Ordinal);
            if (block.BranchValue != null) Visit(block.BranchValue, list, block.Ordinal);
        }
        if (selectedBlock < 0 || !graph.Blocks[selectedBlock].IsReachable) return false;
        var outgoing = graph.Blocks.Select(_ => new HashSet<int>()).ToArray();
        HashSet<int> Incoming(BasicBlock block) => block.Predecessors
            .Where(p => p.Source.IsReachable).SelectMany(p => outgoing[p.Source.Ordinal]).ToHashSet();
        bool Transfer(BasicBlock block, HashSet<int> state, bool stop)
        {
            foreach (var item in events[block.Ordinal])
            {
                if (item.Selected && stop) break;
                if (item.Selected) continue;
                if (!item.Keep) state.Clear();
                state.Add(item.Node.SpanStart);
                if (state.Count > 8 || item.Node.Span.Length > 2048) return false;
            }
            return true;
        }
        bool changed = true;
        for (int pass = 0; changed && pass < 128; pass++)
        {
            changed = false;
            foreach (var block in graph.Blocks.Where(b => b.IsReachable))
            {
                var state = Incoming(block);
                if (!Transfer(block, state, false)) return false;
                if (!state.SetEquals(outgoing[block.Ordinal])) { outgoing[block.Ordinal] = state; changed = true; }
            }
        }
        if (changed) return false;
        var possible = Incoming(graph.Blocks[selectedBlock]);
        if (!Transfer(graph.Blocks[selectedBlock], possible, true) || possible.Count == 0 || possible.Count > 8) return false;
        var source = sources[operand.SyntaxTree.FilePath];
        facts.Add(new(query.Role, "operand_boundary", query.Operand,
            $"CFG possible local producer set: {possible.Count} source expressions; alternatives and accumulation are not a safe-value proof",
            ["branch_feasibility_and_accumulation", "producer_or_caller_control", "exact_interpretation_and_effect"]));
        foreach (var offset in possible.Order())
        {
            var expression = definitions[offset];
            facts.Add(new(query.Role, "local_operand_origin", Location(source, expression.Span),
                expression.ToString(), ["branch_feasibility_and_accumulation", "producer_or_caller_control", "exact_interpretation_and_effect"]));
        }
        // Do not reinterpret append/input sets as complete reaching expressions.
        if (reaching != null && !events.SelectMany(e => e).Any(e => e.Keep))
            reaching.AddRange(possible.Order().Select(offset => definitions[offset]).OfType<ExpressionSyntax>());
        return true;
    }

    private enum PathShape { Unknown, Fixed, TemporaryRoot, GeneratedName, TemporaryPath }

    private static bool FilesystemIdentity(SemanticModel model, SyntaxNode operand, SyntaxNode? action,
        Query query, SortedDictionary<string, Source> sources, List<Fact> facts, Diagnostic[] errors)
    {
        if (action == null || Target(model.GetOperation(action)) is not IMethodSymbol sink || !FrameworkMethod(sink)
            || sink.ContainingNamespace.ToDisplayString() != "System.IO"
            || sink.ContainingType.Name is not ("File" or "Directory" or "FileStream")
            || errors.Any(d => d.Location.IsInSource && d.Location.SourceTree == action.SyntaxTree
                && d.Location.SourceSpan.IntersectsWith(action.Span))) return false;
        var node = operand is PostfixUnaryExpressionSyntax postfix && postfix.IsKind(SyntaxKind.SuppressNullableWarningExpression)
            ? postfix.Operand : operand;
        if (node is not IdentifierNameSyntax name || model.GetTypeInfo(node).Type?.SpecialType != SpecialType.System_String) return false;
        var symbol = model.GetSymbolInfo(node).Symbol;
        if (symbol is not (ILocalSymbol or IParameterSymbol or IFieldSymbol { IsReadOnly: true })
            || symbol is IParameterSymbol { RefKind: not RefKind.None }) return false;
        var owner = node.Ancestors().FirstOrDefault(IsCallable);
        var declaration = symbol.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax();
        if (owner == null || owner.Span.Length > 32768 || declaration == null || declaration.SyntaxTree != node.SyntaxTree
            || !sources.TryGetValue(declaration.SyntaxTree.FilePath, out var source)) return false;
        var references = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
            .Where(n => n.Identifier.ValueText == name.Identifier.ValueText).ToArray();
        foreach (var reference in references)
        {
            var bound = model.GetSymbolInfo(reference).Symbol;
            if (bound == null) return false;
            if (!SymbolEqualityComparer.Default.Equals(bound, symbol)) continue;
            if (reference.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => a.Left.Span.Contains(reference.Span))
                || reference.Parent is PrefixUnaryExpressionSyntax prefix && prefix.Kind() is SyntaxKind.PreIncrementExpression or SyntaxKind.PreDecrementExpression
                || reference.Parent is PostfixUnaryExpressionSyntax postfixUse && postfixUse.Kind() is SyntaxKind.PostIncrementExpression or SyntaxKind.PostDecrementExpression
                || reference.Parent is RefExpressionSyntax
                || reference.Parent is ArgumentSyntax argument && !argument.RefKindKeyword.IsKind(SyntaxKind.None)) return false;
        }
        // Same whole string value within this exact callable. Root authority,
        // guards and effects remain open; this enables conditional context reuse.
        var location = Location(source, declaration.Span);
        var ownerLocation = Location(sources[node.SyntaxTree.FilePath], owner.Span);
        facts.Add(new("path", "immutable_filesystem_operand", location,
            $"{location.Path}:{location.Start.ByteOffset}:{location.End.ByteOffset}:{ownerLocation.Start.ByteOffset}",
            ["root_origin_and_authority", "per_operation_guards_and_effects"]));
        return true;
    }

    private static bool FilesystemShape(SemanticModel model, SyntaxNode operand, SyntaxNode? action,
        Query query, SortedDictionary<string, Source> sources, List<Fact> facts, Diagnostic[] errors,
        Dictionary<SyntaxTree, SemanticModel> models)
    {
        // Reuse project diagnostics/models for cross-file producers as well.
        bool HasError(SyntaxNode node) => errors.Any(d => d.Location.IsInSource
            && d.Location.SourceTree == node.SyntaxTree && d.Location.SourceSpan.IntersectsWith(node.Span));
        // A narrow path-selection fact, not a filesystem or authorization contract.
        if (action == null || Target(model.GetOperation(action)) is not IMethodSymbol sink
            || !FrameworkMethod(sink) || sink.ContainingNamespace.ToDisplayString() != "System.IO"
            || sink.ContainingType.Name is not ("File" or "Directory" or "FileStream")
            || HasError(action)) return false;
        var visited = new HashSet<ILocalSymbol>(SymbolEqualityComparer.Default);
        var members = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
        var arguments = new Dictionary<IParameterSymbol, (SemanticModel Model, ExpressionSyntax Value)>(SymbolEqualityComparer.Default);
        bool Closed(PathShape s) => s != PathShape.Unknown;
        PathShape Merge(IEnumerable<PathShape> values)
        {
            var shapes = values.ToArray();
            if (shapes.Length == 0 || shapes.Any(s => !Closed(s))) return PathShape.Unknown;
            return shapes.All(s => s == shapes[0]) ? shapes[0] : PathShape.Fixed;
        }
        bool Integral(ITypeSymbol? t) => t?.SpecialType is SpecialType.System_Int32 or SpecialType.System_Int64
            or SpecialType.System_UInt32 or SpecialType.System_UInt64 or SpecialType.System_Int16
            or SpecialType.System_UInt16 or SpecialType.System_Byte or SpecialType.System_SByte
            or SpecialType.System_IntPtr or SpecialType.System_UIntPtr;
        bool Numeric(ITypeSymbol? t) => Integral(t) || t?.SpecialType is SpecialType.System_Single
            or SpecialType.System_Double or SpecialType.System_Decimal;
        PathShape Scalar(ITypeSymbol? type, string? format)
        {
            if (type is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T } nullable)
                type = nullable.TypeArguments[0];
            if (type?.ToDisplayString() == "System.Guid" && type.DeclaringSyntaxReferences.Length == 0
                    && type.ContainingAssembly.Identity.PublicKeyToken.Length > 0
                || type?.SpecialType == SpecialType.System_Boolean
                || type?.TypeKind == TypeKind.Enum) return PathShape.GeneratedName;
            // Practical primitive normalization, as in Dotnetarium. Ordinary
            // framework formatting does not preserve arbitrary input path text.
            // Date separators and fixed custom formats are not traversal evidence.
            // Fixed here closes only path selection, not ownership or effects.
            if (Numeric(type)) return string.IsNullOrEmpty(format)
                || "cCdDeEfFgGnNpPrRxXbB".Contains(format[0]) && format.Skip(1).All(char.IsAsciiDigit)
                    ? PathShape.GeneratedName : PathShape.Fixed;
            if (type?.SpecialType == SpecialType.System_Char) return PathShape.Fixed;
            if (type?.ToDisplayString() is "System.DateTime" or "System.DateTimeOffset"
                    or "System.DateOnly" or "System.TimeOnly" or "System.TimeSpan"
                && type.DeclaringSyntaxReferences.Length == 0
                && type.ContainingAssembly.Identity.PublicKeyToken.Length > 0) return PathShape.Fixed;
            return PathShape.Unknown;
        }
        PathShape InModel(SemanticModel target, ExpressionSyntax value, int depth)
        {
            var previous = model;
            try { model = target; return Shape(value, depth); }
            finally { model = previous; }
        }
        ExpressionSyntax? ReturnValue(SyntaxNode declaration)
        {
            var (arrow, body) = declaration switch {
                MethodDeclarationSyntax m => (m.ExpressionBody, m.Body),
                PropertyDeclarationSyntax p => (p.ExpressionBody, p.AccessorList?.Accessors
                    .SingleOrDefault(a => a.IsKind(SyntaxKind.GetAccessorDeclaration))?.Body),
                AccessorDeclarationSyntax a => (a.ExpressionBody, a.Body),
                _ => ((ArrowExpressionClauseSyntax?)null, (BlockSyntax?)null)
            };
            if (arrow != null) return arrow.Expression;
            if (body?.Statements.LastOrDefault() is not ReturnStatementSyntax returned
                || body.Statements.Take(body.Statements.Count - 1).Any(s => s is not LocalDeclarationStatementSyntax)) return null;
            return returned.Expression;
        }
        PathShape Member(ISymbol symbol, SyntaxNode declaration, int depth, IInvocationOperation? call = null)
        {
            if (depth > 6 || declaration.Span.Length > 8192 || members.Count >= 4
                || !sources.ContainsKey(declaration.SyntaxTree.FilePath) || !members.Add(symbol)) return PathShape.Unknown;
            var added = new List<IParameterSymbol>();
            try
            {
                var target = models[declaration.SyntaxTree];
                if (HasError(declaration) || ReturnValue(declaration) is not ExpressionSyntax value) return PathShape.Unknown;
                if (call != null)
                {
                    var declaredMethod = declaration is MethodDeclarationSyntax methodDeclaration
                        ? target.GetDeclaredSymbol(methodDeclaration) : null;
                    foreach (var argument in call.Arguments)
                    {
                        if (argument.Parameter is not { RefKind: RefKind.None } calledParameter || declaredMethod == null
                            || argument.Value is IConversionOperation { OperatorMethod: not null }
                            || argument.Value.Syntax is not ExpressionSyntax input) return PathShape.Unknown;
                        // CompilationReference may retarget symbols; substitute
                        // the parameter belonging to the declaration's model.
                        var parameter = declaredMethod.Parameters[calledParameter.Ordinal];
                        // No substitution through mutation or capture of a parameter.
                        if (declaration.DescendantNodes().OfType<IdentifierNameSyntax>().Any(n =>
                            SymbolEqualityComparer.Default.Equals(target.GetSymbolInfo(n).Symbol, parameter)
                            && (n.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => a.Left.Span.Contains(n.Span))
                                || n.Parent is RefExpressionSyntax
                                || n.Parent is ArgumentSyntax a && !a.RefKindKeyword.IsKind(SyntaxKind.None)
                                || n.Ancestors().FirstOrDefault(IsCallable) != declaration))) return PathShape.Unknown;
                        arguments.Add(parameter, (model, input));
                        added.Add(parameter);
                    }
                }
                return InModel(target, value, depth + 1);
            }
            finally
            {
                foreach (var parameter in added) arguments.Remove(parameter);
                members.Remove(symbol);
            }
        }
        PathShape Collection(ExpressionSyntax expression, int depth)
        {
            if (depth > 6 || HasError(expression)) return PathShape.Unknown;
            if (expression is IdentifierNameSyntax && model.GetSymbolInfo(expression).Symbol is ILocalSymbol list)
            {
                if (!visited.Add(list)) return PathShape.Unknown;
                try
                {
                    var declaration = list.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
                    var owner = expression.Ancestors().FirstOrDefault(IsCallable);
                    if (declaration?.Initializer?.Value is not ExpressionSyntax initial || owner == null
                        || initial.Span.End > expression.SpanStart) return PathShape.Unknown;
                    // Arrays/lists are mutable: only direct enumeration and reads
                    // through known LINQ operators may reuse this producer.
                    var references = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
                        .Where(n => SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, list));
                    foreach (var reference in references)
                    {
                        if (reference.Parent is ForEachStatementSyntax loop && loop.Expression == reference) continue;
                        var invoke = reference.Ancestors().OfType<InvocationExpressionSyntax>().FirstOrDefault();
                        if (invoke == null || model.GetOperation(invoke) is not IInvocationOperation use
                            || !FrameworkMethod(use.TargetMethod)
                            || use.TargetMethod.ContainingType.ToDisplayString() != "System.Linq.Enumerable"
                            || use.TargetMethod.Name is not ("Where" or "OrderBy" or "OrderByDescending" or "ToArray" or "ToList"
                                or "First" or "FirstOrDefault" or "Single" or "SingleOrDefault")
                            || use.Arguments.FirstOrDefault()?.Value.Syntax != reference) return PathShape.Unknown;
                    }
                    return Collection(initial, depth + 1);
                }
                finally { visited.Remove(list); }
            }
            if (model.GetOperation(expression) is not IInvocationOperation call || !FrameworkMethod(call.TargetMethod)) return PathShape.Unknown;
            var type = call.TargetMethod.ContainingType.ToDisplayString();
            if (type == "System.Linq.Enumerable" && call.TargetMethod.Name is "Where" or "OrderBy" or "OrderByDescending" or "ToArray" or "ToList")
                return call.Arguments.FirstOrDefault()?.Value.Syntax is ExpressionSyntax inputList ? Collection(inputList, depth + 1) : PathShape.Unknown;
            if (type != "System.IO.Directory" || call.TargetMethod.Name is not ("GetFiles" or "EnumerateFiles" or "GetDirectories"
                or "EnumerateDirectories" or "GetFileSystemEntries" or "EnumerateFileSystemEntries")) return PathShape.Unknown;
            var root = call.Arguments.FirstOrDefault(a => a.Parameter?.Name == "path");
            if (root?.Value.Syntax is not ExpressionSyntax path) return PathShape.Unknown;
            if (call.Arguments.Any(a => a.Parameter?.Name == "searchPattern" && !a.Value.ConstantValue.HasValue)) return PathShape.Unknown;
            return Shape(path, depth + 1);
        }
        PathShape Shape(ExpressionSyntax expression, int depth)
        {
            if (depth > 6 || expression.Span.Length > 2048) return PathShape.Unknown;
            if (HasError(expression)) return PathShape.Unknown;
            if (expression.IsKind(SyntaxKind.NullLiteralExpression)) return PathShape.Fixed;
            // Never substitute a string initializer through a user-defined conversion.
            if (model.GetTypeInfo(expression).Type?.SpecialType != SpecialType.System_String) return PathShape.Unknown;
            if (model.GetConstantValue(expression) is { HasValue: true, Value: string }) return PathShape.Fixed;
            if (model.GetSymbolInfo(expression).Symbol is IParameterSymbol mappedParameter
                && arguments.TryGetValue(mappedParameter, out var argument))
                return InModel(argument.Model, argument.Value, depth + 1);
            if (expression is ParenthesizedExpressionSyntax parenthesized) return Shape(parenthesized.Expression, depth + 1);
            if (expression is PostfixUnaryExpressionSyntax postfix && postfix.IsKind(SyntaxKind.SuppressNullableWarningExpression))
                return Shape(postfix.Operand, depth + 1);
            if (expression is ConditionalExpressionSyntax conditional)
                return Merge([Shape(conditional.WhenTrue, depth + 1), Shape(conditional.WhenFalse, depth + 1)]);
            if (expression is SwitchExpressionSyntax choose)
                return Merge(choose.Arms.Select(a => Shape(a.Expression, depth + 1)));
            if (expression is BinaryExpressionSyntax coalesce && coalesce.IsKind(SyntaxKind.CoalesceExpression))
                return Merge([Shape(coalesce.Left, depth + 1), Shape(coalesce.Right, depth + 1)]);
            if (expression is InterpolatedStringExpressionSyntax interpolation)
            {
                foreach (var value in interpolation.Contents.OfType<InterpolationSyntax>())
                {
                    var valueType = model.GetTypeInfo(value.Expression).Type;
                    var shape = valueType?.SpecialType == SpecialType.System_String ? Shape(value.Expression, depth + 1)
                        : Scalar(valueType, value.FormatClause?.FormatStringToken.ValueText);
                    if (!Closed(shape)) return PathShape.Unknown;
                }
                // No arbitrary formatter participates in an ordinary string interpolation.
                return PathShape.Fixed;
            }
            if (model.GetOperation(expression) is IPropertyReferenceOperation selected
                && !selected.Property.IsVirtual && !selected.Property.IsAbstract && !selected.Property.IsOverride
                && selected.Property.Parameters.Length == 0 && selected.Property.GetMethod != null
                && selected.Property.RefKind == RefKind.None && selected.Property.DeclaringSyntaxReferences.Length == 1
                && selected.Property.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() is PropertyDeclarationSyntax definition)
            {
                if (HasError(definition)) return PathShape.Unknown;
                // Computed getters retain their actual producers; a writable
                // auto-property or unknown record field is never a closed path.
                if (definition.ExpressionBody != null) return Member(selected.Property, definition, depth);
                var getter = definition.AccessorList?.Accessors.SingleOrDefault(a => a.IsKind(SyntaxKind.GetAccessorDeclaration));
                if (getter?.Body != null || getter?.ExpressionBody != null) return Member(selected.Property, getter, depth);
                if (selected.Property.SetMethod == null && definition.Initializer?.Value is ExpressionSyntax initial)
                {
                    var target = models[definition.SyntaxTree];
                    var owner = definition.Parent;
                    if (owner == null || selected.Property.ContainingType.DeclaringSyntaxReferences.Length != 1
                        || owner is TypeDeclarationSyntax t && t.Modifiers.Any(SyntaxKind.PartialKeyword)
                        || owner.DescendantNodes().OfType<AssignmentExpressionSyntax>().Any(a =>
                            SymbolEqualityComparer.Default.Equals(target.GetSymbolInfo(a.Left).Symbol, selected.Property))) return PathShape.Unknown;
                    return InModel(target, initial, depth + 1);
                }
            }
            if (model.GetOperation(expression) is IPropertyReferenceOperation property
                && property.Property.DeclaringSyntaxReferences.Length == 0
                && property.Property.ContainingAssembly.Identity.PublicKeyToken.Length > 0)
            {
                var propertyType = property.Property.ContainingType.ToDisplayString();
                if (propertyType == "System.AppContext" && property.Property.Name == "BaseDirectory"
                    || propertyType == "System.Environment" && property.Property.Name == "CurrentDirectory") return PathShape.Fixed;
                if (propertyType == "System.AppDomain" && property.Property.Name == "BaseDirectory"
                    && property.Instance is IPropertyReferenceOperation domain && domain.Property.Name == "CurrentDomain"
                    && domain.Property.ContainingType.ToDisplayString() == "System.AppDomain") return PathShape.Fixed;
                if (propertyType == "System.Diagnostics.ProcessModule" && property.Property.Name == "FileName"
                    && property.Instance is IPropertyReferenceOperation module && module.Property.Name == "MainModule"
                    && module.Instance is IInvocationOperation process && FrameworkMethod(process.TargetMethod)
                    && process.TargetMethod.ContainingType.ToDisplayString() == "System.Diagnostics.Process"
                    && process.TargetMethod.Name == "GetCurrentProcess") return PathShape.Fixed;
                if (propertyType is "System.IO.FileInfo" or "System.IO.DirectoryInfo" or "System.IO.FileSystemInfo" && property.Property.Name == "FullName"
                    && property.Instance is IObjectCreationOperation file && FrameworkMethod(file.Constructor!)
                    && file.Type?.ToDisplayString() is "System.IO.FileInfo" or "System.IO.DirectoryInfo"
                    && file.Arguments.FirstOrDefault()?.Value.Syntax is ExpressionSyntax source)
                    return Shape(source, depth + 1);
            }
            if (model.GetOperation(expression) is IFieldReferenceOperation field && field.Field.IsReadOnly
                && field.Field.ContainingType.DeclaringSyntaxReferences.Length == 1
                && field.Field.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() is VariableDeclaratorSyntax fieldDeclaration
                && fieldDeclaration.SyntaxTree == model.SyntaxTree)
            {
                var declaringType = field.Field.ContainingType.DeclaringSyntaxReferences[0].GetSyntax();
                if (declaringType is TypeDeclarationSyntax fieldType && fieldType.Modifiers.Any(SyntaxKind.PartialKeyword))
                    return PathShape.Unknown;
                var assignments = declaringType.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(a =>
                    SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(a.Left).Symbol, field.Field)).ToArray();
                if (declaringType.DescendantNodes().OfType<ArgumentSyntax>().Any(a =>
                        !a.RefKindKeyword.IsKind(SyntaxKind.None)
                        && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(a.Expression).Symbol, field.Field))) return PathShape.Unknown;
                if (assignments.Length == 0 && fieldDeclaration.Initializer?.Value is ExpressionSyntax initial)
                    return Shape(initial, depth + 1);
                // Private immutable wrappers often own a generated temporary path.
                // Bind the single constructor assignment and every accessible
                // construction in this complete source type, not caller spelling.
                if (!field.Field.ContainingType.IsSealed || assignments.Length != 1
                    || assignments[0] is not { RawKind: (int)SyntaxKind.SimpleAssignmentExpression,
                        Parent: ExpressionStatementSyntax { Parent: BlockSyntax constructorBody } } assignment
                    || constructorBody.Parent is not ConstructorDeclarationSyntax constructor
                    || model.GetDeclaredSymbol(constructor) is not IMethodSymbol ctor
                    || model.GetSymbolInfo(assignment.Right).Symbol is not IParameterSymbol parameter
                    || !SymbolEqualityComparer.Default.Equals(parameter.ContainingSymbol, ctor)
                    || parameter.RefKind != RefKind.None
                    || parameter.Type.SpecialType != SpecialType.System_String
                    || declaringType.DescendantNodes().OfType<ConstructorDeclarationSyntax>()
                        .Count(c => c.Parent == declaringType && !c.Modifiers.Any(SyntaxKind.StaticKeyword)) != 1)
                    return PathShape.Unknown;
                if (ctor.DeclaredAccessibility != Accessibility.Private
                    && field.Field.ContainingType.DeclaredAccessibility != Accessibility.Private) return PathShape.Unknown;
                var accessibleType = field.Field.ContainingType;
                while (accessibleType.ContainingType != null)
                {
                    if (accessibleType.DeclaringSyntaxReferences.Length != 1
                        || accessibleType.DeclaringSyntaxReferences[0].GetSyntax() is TypeDeclarationSyntax nestedType
                            && nestedType.Modifiers.Any(SyntaxKind.PartialKeyword)) return PathShape.Unknown;
                    accessibleType = accessibleType.ContainingType;
                }
                if (accessibleType.DeclaringSyntaxReferences.Length != 1) return PathShape.Unknown;
                var scope = accessibleType.DeclaringSyntaxReferences[0].GetSyntax();
                if (scope.SyntaxTree != model.SyntaxTree || scope.Span.Length > 32768
                    || scope is TypeDeclarationSyntax outerType && outerType.Modifiers.Any(SyntaxKind.PartialKeyword)) return PathShape.Unknown;
                if (constructor.DescendantNodes().OfType<IdentifierNameSyntax>().Any(n =>
                    SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, parameter)
                    && (n.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => a.Left.Span.Contains(n.Span))
                        || n.Parent is RefExpressionSyntax
                        || n.Parent is ArgumentSyntax a && !a.RefKindKeyword.IsKind(SyntaxKind.None)))) return PathShape.Unknown;
                var origins = new List<PathShape>();
                foreach (var creation in scope.DescendantNodes().Where(n => n is ObjectCreationExpressionSyntax or ImplicitObjectCreationExpressionSyntax))
                {
                    if (!SymbolEqualityComparer.Default.Equals(model.GetTypeInfo(creation).Type, field.Field.ContainingType)) continue;
                    if (HasError(creation) || model.GetOperation(creation) is not IObjectCreationOperation callSite
                        || !SymbolEqualityComparer.Default.Equals(callSite.Constructor, ctor)
                        || callSite.Arguments.FirstOrDefault(a => a.Parameter?.Ordinal == parameter.Ordinal)?.Value.Syntax is not ExpressionSyntax input)
                        return PathShape.Unknown;
                    origins.Add(Shape(input, depth + 1));
                }
                return Merge(origins);
            }
            if (expression is IdentifierNameSyntax && model.GetSymbolInfo(expression).Symbol is ILocalSymbol local)
            {
                if (!visited.Add(local)) return PathShape.Unknown;
                try
                {
                    var declared = local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax();
                    if (declared is ForEachStatementSyntax loop) return Collection(loop.Expression, depth + 1);
                    var declaration = declared as VariableDeclaratorSyntax;
                    var initializer = declaration?.Initializer?.Value;
                    var owner = expression.Ancestors().FirstOrDefault(IsCallable);
                    if (initializer == null || owner == null || initializer.Span.End > expression.SpanStart
                        || initializer.Ancestors().FirstOrDefault(IsCallable) != owner) return PathShape.Unknown;
                    if (owner.DescendantNodes().Any(n => n is GotoStatementSyntax or LabeledStatementSyntax)) return PathShape.Unknown;
                    // Unrelated missing application dependencies need not invalidate
                    // this local. Unbound uses of its name cannot establish a closed
                    // producer set, however.
                    if (owner.DescendantNodes().OfType<IdentifierNameSyntax>().Any(n =>
                        n.Identifier.ValueText == local.Name && model.GetSymbolInfo(n).Symbol == null)) return PathShape.Unknown;
                    var references = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
                        .Where(n => SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local)).ToArray();
                    bool Writes(IdentifierNameSyntax n) => n.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => a.Left.Span.Contains(n.Span))
                        || n.Parent is PrefixUnaryExpressionSyntax prefix && prefix.Kind() is SyntaxKind.PreIncrementExpression or SyntaxKind.PreDecrementExpression
                        || n.Parent is PostfixUnaryExpressionSyntax postfix && postfix.Kind() is SyntaxKind.PostIncrementExpression or SyntaxKind.PostDecrementExpression;
                    var loops = expression.Ancestors().Where(n => n is WhileStatementSyntax or DoStatementSyntax
                        or ForStatementSyntax or ForEachStatementSyntax).ToArray();
                    if (references.Any(n => n.SpanStart > expression.SpanStart && Writes(n)
                        && loops.Any(loop => loop.Span.Contains(n.Span)))) return PathShape.Unknown;
                    if (references.Any(n => n.Ancestors().FirstOrDefault(IsCallable) != owner && Writes(n)
                        || n.Parent is RefExpressionSyntax
                        || n.Parent is ArgumentSyntax argument && !argument.RefKindKeyword.IsKind(SyntaxKind.None))) return PathShape.Unknown;
                    var writes = references.Where(n => n.SpanStart >= initializer.Span.End && n.Span.End <= expression.SpanStart)
                        .Where(Writes)
                        .ToArray();
                    // Reads of immutable strings do not require a CFG, including inside try/catch.
                    if (writes.Length == 0) return Shape(initializer, depth + 1);
                    // A same-block unconditional reset before this use also works
                    // inside try/catch. A nested/conditional final write falls back
                    // to the existing bounded CFG instead of being assumed away.
                    var lastWrite = writes.OrderBy(n => n.SpanStart).Last();
                    var reset = lastWrite.Parent as AssignmentExpressionSyntax;
                    if (reset is { RawKind: (int)SyntaxKind.SimpleAssignmentExpression,
                            Parent: ExpressionStatementSyntax { Parent: BlockSyntax resetBlock } }
                        && reset.Left == lastWrite && resetBlock == expression.Ancestors().OfType<BlockSyntax>().FirstOrDefault())
                    {
                        var value = Shape(reset.Right, depth + 1);
                        if (Closed(value)) return value;
                    }
                    // If every initializer/possible write is independently closed,
                    // exceptional/branch order cannot introduce an unknown string.
                    // This deliberately proves less than a full reaching-value CFG.
                    var all = new List<PathShape> { Shape(initializer, depth + 1) };
                    foreach (var write in writes)
                    {
                        if (write.Parent is not AssignmentExpressionSyntax assignment
                            || !assignment.IsKind(SyntaxKind.SimpleAssignmentExpression) || assignment.Left != write)
                        { all.Add(PathShape.Unknown); break; }
                        if (assignment.Right is BinaryExpressionSyntax append && append.IsKind(SyntaxKind.AddExpression)
                            && append.Left is IdentifierNameSyntax name
                            && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(name).Symbol, local)
                            && model.GetConstantValue(append.Right) is { HasValue: true, Value: string suffix }
                            && suffix.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')) continue;
                        all.Add(Shape(assignment.Right, depth + 1));
                    }
                    var closed = Merge(all);
                    if (Closed(closed)) return closed;
                    var reaching = new List<ExpressionSyntax>();
                    if (!LocalFlow(model, expression, local, owner, query, sources, new(), reaching)
                        || reaching.Count == 0) return PathShape.Unknown;
                    var shapes = reaching.Select(e => Shape(e, depth + 1)).Distinct().ToArray();
                    return Merge(shapes);
                }
                finally { visited.Remove(local); }
            }
            if (expression is BinaryExpressionSyntax binary && binary.IsKind(SyntaxKind.AddExpression))
            {
                PathShape Part(ExpressionSyntax value) => model.GetTypeInfo(value).Type is { } type
                    && type.SpecialType != SpecialType.System_String ? Scalar(type, null) : Shape(value, depth + 1);
                var left = Part(binary.Left);
                var right = Part(binary.Right);
                bool BasenameLiteral(ExpressionSyntax e) => model.GetConstantValue(e) is { HasValue: true, Value: string text }
                    && text.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
                if (left == PathShape.TemporaryPath && BasenameLiteral(binary.Right)) return PathShape.TemporaryPath;
                if (left == PathShape.GeneratedName && BasenameLiteral(binary.Right)
                    || right == PathShape.GeneratedName && BasenameLiteral(binary.Left)) return PathShape.GeneratedName;
                if ((left is PathShape.Fixed or PathShape.GeneratedName) && (right is PathShape.Fixed or PathShape.GeneratedName))
                    return PathShape.Fixed;
                return PathShape.Unknown;
            }
            if (model.GetOperation(expression) is not IInvocationOperation call) return PathShape.Unknown;
            if (!FrameworkMethod(call.TargetMethod))
            {
                var helper = call.TargetMethod;
                if (ErrorType(helper) || helper.IsVirtual || helper.IsAbstract || helper.IsOverride || helper.IsGenericMethod
                    || helper.ReturnType.SpecialType != SpecialType.System_String
                    || helper.RefKind != RefKind.None || helper.DeclaringSyntaxReferences.Length != 1
                    || helper.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() is not MethodDeclarationSyntax helperDefinition)
                    return PathShape.Unknown;
                return Member(helper, helperDefinition, depth, call);
            }
            var type = call.TargetMethod.ContainingType.ToDisplayString();
            var method = call.TargetMethod.Name;
            if (method == "ToString" && call.Instance != null)
            {
                var format = call.Arguments.FirstOrDefault(a => a.Parameter?.Name == "format");
                bool KnownProvider(IArgumentOperation argument)
                {
                    if (argument.Parameter?.Type.ToDisplayString().TrimEnd('?') != "System.IFormatProvider") return false;
                    var value = argument.Value;
                    while (value is IConversionOperation { OperatorMethod: null } conversion) value = conversion.Operand;
                    return value.ConstantValue is { HasValue: true, Value: null }
                        || value.Type?.ToDisplayString() == "System.Globalization.CultureInfo"
                            && value.Type.DeclaringSyntaxReferences.Length == 0;
                }
                if (call.Arguments.All(a => a == format || KnownProvider(a))
                    && (format == null || format.Value.ConstantValue is { HasValue: true }))
                {
                    var shape = Scalar(call.Instance.Type, format?.Value.ConstantValue.Value as string);
                    if (Closed(shape)) return shape;
                }
            }
            if (type == "System.Convert" && method == "ToString" && call.Arguments.Length == 1)
            {
                var value = call.Arguments[0].Value;
                while (value is IConversionOperation { OperatorMethod: null } conversion) value = conversion.Operand;
                return Scalar(value.Type, null);
            }
            if (type == "System.Convert" && method == "ToHexString") return PathShape.GeneratedName;
            if (type == "System.Environment" && method == "GetFolderPath" && call.Arguments.FirstOrDefault()?.Value.Type?.TypeKind == TypeKind.Enum)
                return PathShape.Fixed;
            if (type == "System.IO.Directory" && method == "GetCurrentDirectory" && call.Arguments.Length == 0) return PathShape.Fixed;
            if (type == "System.Linq.Enumerable" && method is "First" or "FirstOrDefault" or "Single" or "SingleOrDefault"
                && call.Arguments.FirstOrDefault()?.Value.Syntax is ExpressionSyntax list) return Collection(list, depth + 1);
            if (type == "System.IO.Path" && method == "GetTempPath" && call.Arguments.Length == 0)
                return PathShape.TemporaryRoot;
            if (type == "System.IO.Path" && method == "GetRandomFileName" && call.Arguments.Length == 0)
                return PathShape.GeneratedName;
            if (type == "System.IO.Path" && method == "GetTempFileName" && call.Arguments.Length == 0)
                return PathShape.TemporaryPath;
            // Every successful Guid.ToString result uses a closed alphabet, even
            // for a caller-controlled GUID or format. Invalid formats throw;
            // the provider is ignored by this framework API. This is a safe
            // path segment, not an authorization proof for the selected object.
            if (type == "System.Guid" && method == "ToString" && call.Instance?.Type?.ToDisplayString() == "System.Guid")
                return PathShape.GeneratedName;
            if (type == "System.IO.Path" && method is "GetDirectoryName" or "GetFullPath"
                && call.Arguments.Length == 1 && call.Arguments[0].Value.Syntax is ExpressionSyntax original)
                return Shape(original, depth + 1);
            if (type != "System.IO.Path" || method is not ("Combine" or "Join")) return PathShape.Unknown;
            var values = call.Arguments.OrderBy(a => a.Parameter!.Ordinal).SelectMany<IArgumentOperation, IOperation>(a =>
                a.Value is IArrayCreationOperation { Initializer: { } array } ? array.ElementValues : new[] { a.Value }).ToArray();
            var parts = values.Select(v => v.Syntax as ExpressionSyntax).ToArray();
            if (parts.Any(p => p == null)) return PathShape.Unknown;
            var shapesOfParts = parts.Select(p => Shape(p!, depth + 1)).ToArray();
            return !shapesOfParts.All(Closed) ? PathShape.Unknown
                : shapesOfParts.Any(s => s is PathShape.TemporaryPath or PathShape.TemporaryRoot)
                    ? PathShape.TemporaryPath : PathShape.Fixed;
        }
        if (operand is not ExpressionSyntax path) return false;
        var shape = Shape(path, 0);
        if (shape is PathShape.GeneratedName or PathShape.TemporaryRoot) shape = PathShape.Fixed;
        if (shape is PathShape.Fixed or PathShape.TemporaryPath)
            facts.Add(new(query.Role, shape == PathShape.Fixed ? "fixed_filesystem_path" : "temporary_filesystem_path",
                query.Operand, path.ToString(), shape == PathShape.Fixed
                    ? ["resource_authorization_and_sensitive_effect"]
                    : ["temporary_root_authority_and_symlinks", "resource_authorization_and_sensitive_effect"]));
        return shape is PathShape.Fixed or PathShape.TemporaryPath;
    }

    private static bool FrameworkMethod(IMethodSymbol method) => !ErrorType(method)
        && method.DeclaringSyntaxReferences.Length == 0
        && method.ContainingAssembly.Identity.PublicKeyToken.Length > 0
        && (method.ContainingAssembly.Name is "mscorlib" or "netstandard"
            || method.ContainingAssembly.Name.StartsWith("System.", StringComparison.Ordinal));

    private static bool IsCallable(SyntaxNode n) => n is BaseMethodDeclarationSyntax
        or LocalFunctionStatementSyntax or AnonymousFunctionExpressionSyntax;

    // Navigation around one compiler-resolved local, not a receiver-state or CFG
    // summary. In particular an absent Connection reference is not a safe verdict.
    private static void Receiver(SemanticModel model, SyntaxNode action, Query query,
        Project project, Source source, SortedDictionary<string, Source> sources, List<Fact> facts)
    {
        var operation = model.GetOperation(action);
        IOperation? instance = operation switch {
            ISimpleAssignmentOperation { Target: IPropertyReferenceOperation property } => property.Instance,
            IInvocationOperation call => call.Instance,
            _ => null
        };
        var creation = action as ExpressionSyntax;
        if (instance is IInstanceReferenceOperation)
            creation = action.Ancestors().OfType<ObjectCreationExpressionSyntax>().FirstOrDefault();
        var local = instance is ILocalReferenceOperation reference ? reference.Local
            : creation?.Parent is EqualsValueClauseSyntax { Parent: VariableDeclaratorSyntax variable }
                ? model.GetDeclaredSymbol(variable) as ILocalSymbol : null;
        var type = instance?.Type ?? model.GetTypeInfo(creation ?? action).Type;
        bool Command(ITypeSymbol? candidate) {
            if (candidate is INamedTypeSymbol named && named.Name == "IDbCommand"
                && named.ContainingNamespace.ToDisplayString() == "System.Data"
                && named.DeclaringSyntaxReferences.Length == 0) return true;
            for (var current = candidate as INamedTypeSymbol; current != null; current = current.BaseType)
                if (current.Name == "DbCommand" && current.ContainingNamespace.ToDisplayString() == "System.Data.Common"
                    && current.DeclaringSyntaxReferences.Length == 0) return true;
            return false;
        }
        if (!Command(type)) return;
        var receiverSymbol = instance switch {
            IFieldReferenceOperation field => (ISymbol)field.Field,
            IParameterReferenceOperation parameter => parameter.Parameter,
            _ => null
        };
        if (receiverSymbol?.DeclaringSyntaxReferences is { Length: 1 } references
            && sources.TryGetValue(references[0].SyntaxTree.FilePath, out var declaredSource))
        {
            var declared = references[0].GetSyntax();
            var name = declared switch {
                VariableDeclaratorSyntax field => field.Identifier.Span,
                ParameterSyntax parameter => parameter.Identifier.Span,
                _ => declared.Span
            };
            facts.Add(new("receiver", "semantic_definition", Location(declaredSource, name),
                receiverSymbol.ToDisplayString(), ["receiver_origin_and_lifecycle", "effective_execution_and_connection"]));
        }
        var owner = action.Ancestors().FirstOrDefault(IsCallable);
        var declaration = local?.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
        var initializer = declaration?.Initializer?.Value;
        if (local == null || owner == null || owner.Span.Length > 32768 || initializer == null
            || initializer.Ancestors().FirstOrDefault(IsCallable) != owner || initializer.Span.Length > 2048)
        {
            facts.Add(new("receiver", "operand_boundary", Location(source, action.Span),
                "Command receiver is not a bounded initialized local in this callable",
                ["receiver_origin_and_lifecycle", "effective_execution_and_connection"]));
            return;
        }
        facts.Add(new("receiver", "local_operand_origin", Location(source, initializer.Span),
            initializer.ToString(), ["control_flow_and_reaching_receiver_state", "effective_execution_and_connection"]));
        var origin = model.GetOperation(initializer);
        while (origin is IConversionOperation conversion) origin = conversion.Operand;
        if (origin is ILocalReferenceOperation or IParameterReferenceOperation or IFieldReferenceOperation or IPropertyReferenceOperation)
        {
            facts.Add(new("receiver", "operand_boundary", Location(source, initializer.Span),
                "Receiver initializer aliases an existing receiver; navigation stops here",
                ["receiver_origin_alias_or_factory", "effective_execution_and_connection"]));
            return;
        }
        if (Target(origin) is IMethodSymbol constructor && !ErrorType(constructor))
            facts.Add(new("receiver", "semantic_identity", Location(source, initializer.Span),
                Identity(constructor, project), ["constructor_or_factory_contract", "effective_execution_and_connection"]));
        var uses = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
            .Where(n => SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local))
            .OrderBy(n => n.SpanStart).ToArray();
        var seen = new HashSet<Microsoft.CodeAnalysis.Text.TextSpan>();
        foreach (var use in uses)
        {
            var direct = use.Parent is MemberAccessExpressionSyntax member && member.Expression == use;
            var window = use.AncestorsAndSelf().TakeWhile(n => n != owner && n is not StatementSyntax)
                .LastOrDefault(n => n is ExpressionSyntax or VariableDeclaratorSyntax) ?? use;
            if (seen.Contains(window.Span)) continue;
            if (seen.Count == 8 || window.Span.Length > 256)
            {
                facts.Add(new("receiver", "operand_boundary", Location(source, use.Span),
                    "Receiver reference window exceeded eight uses or 256 characters",
                    ["remaining_receiver_references", "effective_execution_and_connection"]));
                return;
            }
            seen.Add(window.Span);
            facts.Add(new("receiver", "receiver_reference", Location(source, window.Span),
                window.ToString(), ["control_flow_and_reaching_receiver_state", "member_contract_and_effect"]));
            if (!direct || use.Ancestors().FirstOrDefault(IsCallable) != owner)
            {
                facts.Add(new("receiver", "operand_boundary", Location(source, use.Span),
                    "Receiver reference leaves direct local member use; navigation stops here",
                    ["receiver_replacement_alias_capture_or_handoff", "effective_execution_and_connection"]));
                return;
            }
        }
        facts.Add(new("receiver", "operand_boundary", Location(source, declaration!.Identifier.Span),
            $"Receiver navigation covers {seen.Count} distinct reference windows in this callable; no runtime state inferred",
            ["control_flow_and_reaching_receiver_state", "member_contract_and_effect", "caller_or_entrypoint_reachability"]));
    }

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

    private static string? ReferenceName(string path)
    {
        try { return System.Reflection.AssemblyName.GetAssemblyName(path).Name; }
        // Some Framework reference directories also contain native PE files.
        // Roslyn reports their metadata errors; keep valid sibling bindings.
        catch (BadImageFormatException) { return null; }
    }

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
        string[] References, string[] ReferenceDirectories, string[] Defines, bool AllowUnsafe = false, bool Nullable = false,
        string[]? UnresolvedReferences = null, string OutputKind = "library", string[]? GlobalUsings = null,
        string[]? ProjectReferences = null, string? AssemblyName = null);
    private sealed record Query(string EvidenceId, string Role, SourceLocation Sink, SourceLocation Operand, SourceLocation? Composition = null);
    private sealed record Source(string Path, string Text, string Hash);
    private sealed record Position(int Line, int Column, int ByteOffset);
    private sealed record SourceLocation(string Path, Position Start, Position End);
    private sealed record Fact(string Role, string Kind, SourceLocation Location, string Value, string[] RemainingChecks);
    private sealed record FileHash(string Path, string Sha256);
    private sealed record ProjectRecord(string Id, string TargetFramework, string LanguageVersion, int CompilerErrors,
        int UnresolvedReferences, int ReferenceConflicts, bool IncompleteDependencies = false);
    private sealed record Observation(string EvidenceId, string ProjectId, List<Fact> Facts, bool LocallyCompletePathSelection, bool LocallyCompleteSelectionIdentity,
        bool LocallyCompleteOutput, bool LocallyCompleteDestination);
    private sealed record DiagnosticRecord(string ProjectId, string Code, string Message, SourceLocation? Location);
    private sealed record Snapshot(string SchemaVersion, string Backend, string ContextSha256,
        FileHash[] Sources, FileHash[] References, List<ProjectRecord> Projects,
        List<Observation> Observations, List<DiagnosticRecord> Diagnostics);
}
