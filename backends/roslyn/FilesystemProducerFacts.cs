using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

internal static partial class Program
{
    // Reuse a private helper's research, never its safety verdict. The caller's
    // complete unchanged selector is established separately by FilesystemIdentity.
    private static void FilesystemProducer(SemanticModel model, SyntaxNode operand,
        SortedDictionary<string, Source> sources, List<Fact> facts)
    {
        if (operand is not IdentifierNameSyntax name || model.GetSymbolInfo(name).Symbol is not ILocalSymbol local) return;
        var declaration = local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
        if (declaration?.Initializer?.Value is not InvocationExpressionSyntax invocation
            || model.GetOperation(invocation) is not IInvocationOperation call) return;
        var method = call.TargetMethod;
        if (ErrorType(method) || method.IsVirtual || method.IsAbstract || method.IsGenericMethod
            || method.DeclaredAccessibility != Accessibility.Private || method.ReturnType.SpecialType != SpecialType.System_String
            || !SymbolEqualityComparer.Default.Equals(method.ContainingType, local.ContainingSymbol.ContainingType) || call.Arguments.Length > 3
            || call.Arguments.Any(a => a.Parameter?.RefKind != RefKind.None)) return;
        if (!method.IsStatic && call.Instance is not IInstanceReferenceOperation) return;
        var helper = method.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as MethodDeclarationSyntax;
        var owner = helper?.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
        if (helper == null || helper.Span.Length > 8192 || helper.SyntaxTree != operand.SyntaxTree
            || owner == null || !sources.TryGetValue(helper.SyntaxTree.FilePath, out var source)) return;
        // Only the first string operand can vary. Options/defaults distinguish
        // containment policies instead of collapsing bypass=true and bypass=false.
        var arguments = call.Arguments.OrderBy(a => a.Parameter?.Ordinal).ToArray();
        if (arguments.Length > 0 && (arguments[0].Parameter?.Ordinal != 0
            || arguments[0].Parameter?.Type.SpecialType != SpecialType.System_String)) return;
        var options = new List<string>();
        foreach (var argument in arguments.Skip(1))
        {
            if (!argument.Value.ConstantValue.HasValue) return;
            options.Add($"{argument.Parameter!.Ordinal}:{argument.Value.Type?.ToDisplayString()}:{argument.Value.ConstantValue.Value}");
        }
        var location = Location(source, helper.Identifier.Span);
        facts.Add(new("path", "shared_filesystem_producer", location,
            $"{location.Path}:{location.Start.ByteOffset}:{location.End.ByteOffset}:{Location(source, owner.Span).Start.ByteOffset}:{Hash(System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(options, Json)))}",
            ["helper_return_and_containment_policy", "per_call_input_guards_and_resource_effects"]));
    }
}
