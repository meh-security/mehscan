using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

internal static partial class Program
{
    // Descriptive shared construction, never an SSRF/authority safety proof.
    // Bound base field, append-only URI construction and same-owner hooks remain
    // explicit; source-controlled authority/path replacements do not qualify.
    private static bool DestinationIdentity(SemanticModel model, SyntaxNode operand, SyntaxNode? action,
        Query query, SortedDictionary<string, Source> sources, List<Fact> facts, Diagnostic[] errors)
    {
        bool HasError(SyntaxNode node) => errors.Any(d => d.Location.IsInSource
            && d.Location.SourceTree == node.SyntaxTree && d.Location.SourceSpan.IntersectsWith(node.Span));
        bool Equal(ISymbol? a, ISymbol? b) => SymbolEqualityComparer.Default.Equals(a, b);
        if (action == null || HasError(action) || model.GetOperation(action) is not ISimpleAssignmentOperation assignment
            || assignment.Target is not IPropertyReferenceOperation destination || destination.Property.Name != "RequestUri"
            || destination.Property.ContainingType.ToDisplayString() != "System.Net.Http.HttpRequestMessage"
            || destination.Property.DeclaringSyntaxReferences.Length != 0
            || destination.Property.ContainingAssembly.Identity.PublicKeyToken.Length == 0
            || destination.Property.ContainingAssembly.Name != "System.Net.Http") return false;
        if (operand is not IdentifierNameSyntax url || model.GetSymbolInfo(url).Symbol is not ILocalSymbol urlLocal
            || urlLocal.Type.SpecialType != SpecialType.System_String) return false;
        var owner = operand.Ancestors().FirstOrDefault(IsCallable);
        var urlDeclaration = urlLocal.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
        if (owner is not MethodDeclarationSyntax || owner.Span.Length > 32768
            || urlDeclaration?.Initializer?.Value is not InvocationExpressionSyntax stringify
            || model.GetOperation(stringify) is not IInvocationOperation toString
            || !FrameworkMethod(toString.TargetMethod) || toString.TargetMethod.ContainingType.ToDisplayString() != "System.Text.StringBuilder"
            || toString.TargetMethod.Name != "ToString" || toString.Arguments.Length != 0
            || toString.Instance is not ILocalReferenceOperation builder || stringify.Span.End > url.SpanStart) return false;
        if (owner.DescendantNodes().OfType<IdentifierNameSyntax>().Where(n => Equal(model.GetSymbolInfo(n).Symbol, urlLocal))
            .Any(n => n.Ancestors().FirstOrDefault(IsCallable) != owner
                || n.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => a.Left.Span.Contains(n.Span))
                || n.Parent is ArgumentSyntax arg && !arg.RefKindKeyword.IsKind(SyntaxKind.None))) return false;
        var builderDeclaration = builder.Local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
        if (builderDeclaration?.Initializer?.Value is not ObjectCreationExpressionSyntax creation
            || model.GetOperation(creation) is not IObjectCreationOperation allocation
            || allocation.Constructor == null || !FrameworkMethod(allocation.Constructor)
            || allocation.Constructor.ContainingType.ToDisplayString() != "System.Text.StringBuilder"
            || allocation.Arguments.Length != 0 || allocation.Initializer != null
            || creation.Ancestors().FirstOrDefault(IsCallable) != owner) return false;
        var uses = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
            .Where(n => Equal(model.GetSymbolInfo(n).Symbol, builder.Local)).OrderBy(n => n.SpanStart).ToArray();
        if (uses.Length > 128) return false;
        IFieldSymbol? baseField = null;
        bool pathStarted = false;
        foreach (var use in uses.Where(n => n.SpanStart < stringify.SpanStart))
        {
            if (HasError(use) || use.Ancestors().FirstOrDefault(IsCallable) != owner) return false;
            if (use.Parent is ArgumentSyntax argument)
            {
                var hook = argument.Parent?.Parent as InvocationExpressionSyntax;
                if (hook == null || !argument.RefKindKeyword.IsKind(SyntaxKind.None)
                    || model.GetSymbolInfo(hook).Symbol is not IMethodSymbol method
                    || method.IsStatic || method.IsVirtual || method.DeclaredAccessibility != Accessibility.Private
                    || !Equal(method.ContainingType, urlLocal.ContainingSymbol.ContainingType)) return false;
                continue; // Same class's private hook is a remaining review obligation.
            }
            if (use.Parent is not MemberAccessExpressionSyntax member || member.Expression != use) return false;
            if (member.Name.Identifier.ValueText == "Length" && member.Parent is PostfixUnaryExpressionSyntax decrement
                && decrement.IsKind(SyntaxKind.PostDecrementExpression) && pathStarted) continue;
            var invocation = member.Parent as InvocationExpressionSyntax;
            if (invocation == null || model.GetOperation(invocation) is not IInvocationOperation call) return false;
            while (true)
            {
                if (!FrameworkMethod(call.TargetMethod) || call.TargetMethod.ContainingType.ToDisplayString() != "System.Text.StringBuilder"
                    || call.TargetMethod.Name != "Append" || call.Arguments.Length != 1) return false;
                var part = call.Arguments[0].Value;
                while (part is IConversionOperation conversion) part = conversion.Operand;
                if (part is IFieldReferenceOperation field && field.Field.Type.SpecialType == SpecialType.System_String
                    && field.Field.DeclaredAccessibility == Accessibility.Private && !field.Field.IsStatic
                    && field.Instance is IInstanceReferenceOperation
                    && Equal(field.Field.ContainingType, urlLocal.ContainingSymbol.ContainingType))
                {
                    if (baseField != null || pathStarted) return false;
                    baseField = field.Field;
                }
                else if (part.ConstantValue.HasValue && part.ConstantValue.Value is string or char)
                {
                    if (baseField == null) return false;
                    if (!pathStarted)
                    {
                        var prefix = part.ConstantValue.Value.ToString()!;
                        if (prefix.Length == 0 || prefix.Contains(':') || prefix.StartsWith('/') || prefix.StartsWith('\\')) return false;
                        pathStarted = true;
                    }
                }
                else if (!pathStarted || part is not IInvocationOperation escape || !FrameworkMethod(escape.TargetMethod)
                    || escape.TargetMethod.ContainingType.ToDisplayString() != "System.Uri" || escape.TargetMethod.Name != "EscapeDataString"
                    || escape.Arguments.Length != 1) return false;
                var next = invocation.Parent is MemberAccessExpressionSyntax chained ? chained.Parent as InvocationExpressionSyntax : null;
                if (next == null) break;
                invocation = next;
                if (model.GetOperation(invocation) is not IInvocationOperation nextCall) return false;
                call = nextCall;
            }
        }
        if (baseField == null || !pathStarted) return false;
        var hooks = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var invocation in owner.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (model.GetOperation(invocation) is not IInvocationOperation call) continue;
            bool Carries(IOperation value)
            {
                while (value is IConversionOperation conversion) value = conversion.Operand;
                return value is ILocalReferenceOperation local && (Equal(local.Local, builder.Local) || Equal(local.Local, urlLocal));
            }
            if (!call.Arguments.Any(a => Carries(a.Value))) continue;
            var method = call.TargetMethod;
            if (method.IsStatic || method.IsVirtual || method.DeclaredAccessibility != Accessibility.Private
                || !Equal(method.ContainingType, urlLocal.ContainingSymbol.ContainingType)
                || call.Arguments.Any(a => a.Parameter?.RefKind != RefKind.None)) return false;
            hooks.Add(method.GetDocumentationCommentId() ?? method.ToDisplayString());
        }
        var fieldDeclaration = baseField.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax();
        var typeDeclaration = owner.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
        if (fieldDeclaration == null || HasError(fieldDeclaration) || typeDeclaration == null
            || fieldDeclaration.SyntaxTree != operand.SyntaxTree
            || !sources.TryGetValue(fieldDeclaration.SyntaxTree.FilePath, out var source)) return false;
        var location = Location(source, fieldDeclaration.Span);
        facts.Add(new("endpoint", "shared_outbound_destination", location,
            $"{location.Path}:{location.Start.ByteOffset}:{location.End.ByteOffset}:{Location(source, typeDeclaration.Span).Start.ByteOffset}:{Hash(System.Text.Encoding.UTF8.GetBytes(string.Join("|", hooks)))}",
            ["destination_producer_and_same_owner_hooks", "per_operation_uri_authority_and_request_effects"]));
        return true;
    }
}
