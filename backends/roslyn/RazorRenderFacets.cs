using System.Text;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using System.Security.Cryptography;
using System.Text.Json;

internal static partial class RazorFrontend
{
    private sealed record RenderSite(string Path, int Start, int End, string Operand, string Binding, string Mode);
    private sealed record RenderUse(string Path, string Target);

    private static IEnumerable<RenderUse> RenderUses(SyntaxNode syntax, SemanticModel model,
        string path, IReadOnlyDictionary<SyntaxTree, string> origins)
    {
        foreach (var call in syntax.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var name = call.Expression switch
            {
                MemberAccessExpressionSyntax access => access.Name.Identifier.ValueText,
                MemberBindingExpressionSyntax binding => binding.Name.Identifier.ValueText,
                SimpleNameSyntax simple => simple.Identifier.ValueText,
                _ => null
            };
            if (name is not ("OpenComponent" or "OpenElement")) continue;
            if (model.GetSymbolInfo(call).Symbol is not IMethodSymbol method
                || method.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder"
                || method.ContainingType.Locations.Any(l => l.IsInSource)) continue;
            if (method.Name == "OpenElement" && call.ArgumentList.Arguments.Count == 2
                && model.GetConstantValue(call.ArgumentList.Arguments[1].Expression) is { HasValue: true, Value: string tag }
                && tag.Length > 0 && char.IsUpper(tag[0]))
                yield return new(path, "component:" + tag);
            if (method.Name != "OpenComponent") continue;
            ITypeSymbol? target = method.TypeArguments.FirstOrDefault();
            if (target == null && call.ArgumentList.Arguments.Count == 2)
                target = (model.GetOperation(call.ArgumentList.Arguments[1].Expression) as ITypeOfOperation)?.TypeOperand;
            if (target == null || target.TypeKind is TypeKind.TypeParameter or TypeKind.Error
                || target.ToDisplayString() == "Microsoft.AspNetCore.Components.DynamicComponent")
            { yield return new(path, "*"); continue; }
            foreach (var declaration in target.DeclaringSyntaxReferences)
                if (origins.TryGetValue(declaration.SyntaxTree, out var source)) yield return new(path, source);
        }
    }

    // A bounded effect fact, not component-wide semantic equivalence. Only the
    // framework's AddContent of a string expression is admitted. The operand
    // and its bound operations remain part of the ordinary input surface; only
    // its output-interpretation wrapper becomes an independently consumed fact.
    private static IEnumerable<RenderSite> RenderSites(SyntaxNode syntax, SemanticModel model,
        List<Mapping> mappings, Input original, int[] offsets)
    {
        if (!original.Path.EndsWith(".razor", StringComparison.OrdinalIgnoreCase)
            || syntax.GetDiagnostics().Any(d => d.Severity == DiagnosticSeverity.Error)) yield break;
        var builder = model.Compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder");
        var markup = model.Compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Components.MarkupString");
        if (builder == null || markup == null || builder.Locations.Any(l => l.IsInSource) || markup.Locations.Any(l => l.IsInSource)) yield break;
        var calls = syntax.DescendantNodes().OfType<InvocationExpressionSyntax>().ToArray();
        // Do not certify an HTML-text-local boundary for active-content contexts.
        // Framework-emitted literal markup excludes C# string examples/comments.
        foreach (var call in calls)
            if (model.GetSymbolInfo(call).Symbol is IMethodSymbol literal && literal.Name is "AddMarkupContent" or "OpenElement"
                && SymbolEqualityComparer.Default.Equals(literal.ContainingType, builder)
                && call.ArgumentList.Arguments.Count == 2
                && model.GetConstantValue(call.ArgumentList.Arguments[1].Expression) is { HasValue: true, Value: string text }
                && (literal.Name == "OpenElement"
                    ? Regex.IsMatch(text, @"^(script|style|svg|math|textarea|iframe|object)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
                    : Regex.IsMatch(text, @"<\s*(script|style|svg|math|textarea|iframe|object)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)))
                yield break;
        var bytes = Encoding.UTF8.GetBytes(original.Text);
        foreach (var call in calls)
        {
            if (model.GetSymbolInfo(call).Symbol is not IMethodSymbol method || method.Name != "AddContent"
                || !SymbolEqualityComparer.Default.Equals(method.ContainingType, builder)
                || call.ArgumentList.Arguments.Count != 2
                || !call.Ancestors().OfType<MethodDeclarationSyntax>().Any(m => m.Identifier.ValueText == "BuildRenderTree")) continue;
            var expression = call.ArgumentList.Arguments[1].Expression;
            var value = Unwrap(expression); var mode = "encoded";
            if (value is CastExpressionSyntax cast && SymbolEqualityComparer.Default.Equals(model.GetTypeInfo(cast.Type).Type, markup))
            { value = Unwrap(cast.Expression); mode = "raw"; }
            else if (value is ObjectCreationExpressionSyntax creation && creation.ArgumentList?.Arguments.Count == 1
                && SymbolEqualityComparer.Default.Equals(model.GetTypeInfo(creation).Type, markup))
            { value = Unwrap(creation.ArgumentList.Arguments[0].Expression); mode = "raw"; }
            var type = model.GetTypeInfo(value).Type;
            if (type?.SpecialType != SpecialType.System_String || type.Locations.Any(l => l.IsInSource)
                || model.GetOperation(value) is not { } operation) continue;
            var binding = OperationBinding(operation);
            if (binding == null) continue;
            var map = mappings.FirstOrDefault(m => m.GeneratedStart == offsets[expression.SpanStart]
                && m.GeneratedEnd == offsets[expression.Span.End]);
            if (map == null) continue;
            var begin = map.OriginalStart; var end = begin + map.GeneratedEnd - map.GeneratedStart;
            // A mapping must name the entire direct Razor output expression.
            if (begin > 0 && bytes[begin - 1] == (byte)'@') begin--;
            else if (begin > 1 && bytes[begin - 2] == (byte)'@' && bytes[begin - 1] == (byte)'('
                && end < bytes.Length && bytes[end] == (byte)')') { begin -= 2; end++; }
            else continue;
            if (begin > 0 && bytes[begin - 1] == (byte)'@') continue; // escaped text
            yield return new(original.Path, begin, end, value.ToString(), binding, mode);
        }
    }

    private static ExpressionSyntax Unwrap(ExpressionSyntax expression)
    {
        while (expression is ParenthesizedExpressionSyntax parenthesized) expression = parenthesized.Expression;
        return expression;
    }

    private static string? OperationBinding(IOperation root)
    {
        var values = new List<string>(); var pending = new Stack<IOperation>(); pending.Push(root);
        while (pending.Count > 0)
        {
            var operation = pending.Pop();
            if (values.Count > 1024 || operation.Kind == OperationKind.Invalid || operation.Type?.TypeKind == TypeKind.Error) return null;
            ISymbol? symbol = operation switch
            {
                IInvocationOperation call => call.TargetMethod,
                IMemberReferenceOperation member => member.Member,
                IObjectCreationOperation creation => creation.Constructor,
                IConversionOperation conversion => conversion.OperatorMethod,
                IBinaryOperation binary => binary.OperatorMethod,
                IUnaryOperation unary => unary.OperatorMethod,
                IParameterReferenceOperation parameter => parameter.Parameter,
                ILocalReferenceOperation local => local.Local,
                _ => null
            };
            values.Add(operation.Kind + ":" + operation.Type?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
                + ":" + operation.IsImplicit + ":" + symbol?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
                + ":" + symbol?.ContainingAssembly?.Identity);
            foreach (var child in operation.ChildOperations.Reverse()) pending.Push(child);
        }
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(values))).ToLowerInvariant();
    }
}
