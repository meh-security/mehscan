using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

internal static partial class Program
{
    private static bool AspNetApi(ISymbol symbol, string type) => !ErrorType(symbol)
        && symbol.ContainingType.ToDisplayString() == type
        && symbol.DeclaringSyntaxReferences.Length == 0
        && symbol.ContainingAssembly.Identity.PublicKeyToken.Length > 0
        && symbol.ContainingAssembly.Name.StartsWith("Microsoft.AspNetCore.", StringComparison.Ordinal);

    private static bool HtmlSink(ISymbol? symbol) => symbol != null && (
        symbol is IMethodSymbol { MethodKind: MethodKind.Constructor }
            && AspNetApi(symbol, "Microsoft.AspNetCore.Html.HtmlString")
        || symbol.Name == "AppendHtml" && (
            AspNetApi(symbol, "Microsoft.AspNetCore.Html.HtmlContentBuilder")
            || AspNetApi(symbol, "Microsoft.AspNetCore.Html.IHtmlContentBuilder"))
        || symbol.Name == "Raw" && (
            AspNetApi(symbol, "Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper")
            || AspNetApi(symbol, "Microsoft.AspNetCore.Mvc.ViewFeatures.HtmlHelper")));

    // HTML-text only. No blanket trust for IHtmlContent, cached markup, JSON,
    // encoders supplied by application subclasses, or arbitrary render helpers.
    private static bool HtmlShape(SemanticModel model, SyntaxNode operand, SyntaxNode? action,
        Query query, SortedDictionary<string, Source> sources, List<Fact> facts, Diagnostic[] errors)
    {
        bool HasError(SyntaxNode node) => errors.Any(d => d.Location.IsInSource
            && d.Location.SourceTree == node.SyntaxTree && d.Location.SourceSpan.IntersectsWith(node.Span));
        if (action == null || !HtmlSink(Target(model.GetOperation(action))) || HasError(action)
            || operand is not ExpressionSyntax selected) return false;
        var owner = operand.Ancestors().FirstOrDefault(IsCallable);
        var visiting = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
        bool DefaultEncoder(IOperation? instance)
        {
            while (instance is IConversionOperation conversion) instance = conversion.Operand;
            return instance is IPropertyReferenceOperation encoder && encoder.Property.Name == "Default" && encoder.Property.IsStatic
                && encoder.Property.ContainingType.ToDisplayString() == "System.Text.Encodings.Web.HtmlEncoder";
        }
        bool Safe(ExpressionSyntax value, int depth)
        {
            if (depth > 6 || HasError(value)) return false;
            if (value is ParenthesizedExpressionSyntax parenthesized) return Safe(parenthesized.Expression, depth + 1);
            if (model.GetConstantValue(value) is { HasValue: true, Value: string }) return true;
            if (model.GetOperation(value) is IInvocationOperation encoded && FrameworkMethod(encoded.TargetMethod)
                && encoded.TargetMethod.ContainingType.ToDisplayString() is "System.Text.Encodings.Web.HtmlEncoder" or "System.Text.Encodings.Web.TextEncoder"
                && encoded.TargetMethod.Name == "Encode" && encoded.Arguments.Length == 1
                && encoded.TargetMethod.ReturnType.SpecialType == SpecialType.System_String
                && DefaultEncoder(encoded.Instance)) return true;
            if (owner == null || owner.Span.Length > 32768
                || value is not IdentifierNameSyntax name
                || model.GetSymbolInfo(name).Symbol is not ILocalSymbol local || !visiting.Add(local)) return false;
            try
            {
                var declaration = local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
                if (declaration?.Initializer?.Value is not ExpressionSyntax initial
                    || initial.Ancestors().FirstOrDefault(IsCallable) != owner
                    || initial.Span.End > value.SpanStart) return false;
                var uses = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
                    .Where(n => n.Identifier.ValueText == name.Identifier.ValueText
                        && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local)).ToArray();
                if (uses.Length > 128 || uses.Any(n => n.Ancestors().FirstOrDefault(IsCallable) != owner
                    || n.Parent is RefExpressionSyntax
                    || n.Parent is ArgumentSyntax a && !a.RefKindKeyword.IsKind(SyntaxKind.None)
                    || n.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => a.Left == n))) return false;
                if (model.GetOperation(initial) is not IObjectCreationOperation builder
                    || builder.Constructor == null || !AspNetApi(builder.Constructor, "Microsoft.AspNetCore.Mvc.Rendering.TagBuilder"))
                    return uses.All(n => n == value || n.Parent is ArgumentSyntax argument
                        && argument.Parent?.Parent is ExpressionSyntax consumer && HtmlSink(Target(model.GetOperation(consumer))))
                        && Safe(initial, depth + 1);
                if (builder.Initializer != null || builder.Arguments.Length != 1
                    || builder.Arguments[0].Value.ConstantValue is not { HasValue: true, Value: string tag }
                    || !new[] { "div", "span", "p", "ul", "ol", "li", "a", "button", "i", "b", "strong", "h1", "h2", "h3", "h4", "h5", "h6" }.Contains(tag)) return false;
                foreach (var use in uses)
                {
                    if (HasError(use)) return false;
                    if (use == value) continue;
                    if (use.Parent is ArgumentSyntax argument && argument.Parent?.Parent is ExpressionSyntax consumer
                        && HtmlSink(Target(model.GetOperation(consumer)))) continue;
                    if (use.Parent is not MemberAccessExpressionSyntax member || member.Expression != use) return false;
                    if (member.Name.Identifier.ValueText == "Attributes" && member.Parent is ElementAccessExpressionSyntax attribute
                        && attribute.Parent is AssignmentExpressionSyntax assignment && assignment.Left == attribute
                        && assignment.IsKind(SyntaxKind.SimpleAssignmentExpression)
                        && attribute.ArgumentList.Arguments.Count == 1
                        && model.GetConstantValue(attribute.ArgumentList.Arguments[0].Expression) is { HasValue: true, Value: string key })
                    {
                        if (HasError(assignment)) return false;
                        key = key.ToLowerInvariant();
                        if (key == "href") { if (!Fragment(assignment.Right)) return false; }
                        else if (!new[] { "class", "id", "title", "role", "name", "value", "type", "disabled", "selected", "tabindex" }.Contains(key)
                            && !key.StartsWith("aria-", StringComparison.Ordinal)
                            && !key.StartsWith("data-", StringComparison.Ordinal)) return false;
                        continue; // TagBuilder encodes ordinary attribute values.
                    }
                    var invocation = member.AncestorsAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
                    if (invocation == null || model.GetOperation(invocation) is not IInvocationOperation call) return false;
                    if (call.TargetMethod.Name == "AddCssClass" && AspNetApi(call.TargetMethod, "Microsoft.AspNetCore.Mvc.Rendering.TagBuilder")) continue;
                    if (member.Name.Identifier.ValueText != "InnerHtml" || call.Arguments.Length != 1) return false;
                    if (call.TargetMethod.Name == "Append" && (
                        AspNetApi(call.TargetMethod, "Microsoft.AspNetCore.Html.IHtmlContentBuilder")
                        || AspNetApi(call.TargetMethod, "Microsoft.AspNetCore.Html.HtmlContentBuilder"))) continue;
                    if (!HtmlSink(call.TargetMethod) || call.Arguments[0].Syntax is not ArgumentSyntax child
                        || !Safe(child.Expression, depth + 1)) return false;
                }
                return true;
            }
            finally { visiting.Remove(local); }
        }
        bool Fragment(ExpressionSyntax expression)
        {
            if (model.GetConstantValue(expression) is { HasValue: true, Value: string text })
                return text.StartsWith('#');
            return expression is BinaryExpressionSyntax binary && binary.IsKind(SyntaxKind.AddExpression)
                && model.GetConstantValue(binary.Left) is { HasValue: true } prefix
                && (prefix.Value is char c && c == '#' || prefix.Value is string s && s.StartsWith('#'));
        }
        if (!Safe(selected, 0)) return false;
        facts.Add(new("content", "encoded_html_operand", query.Operand, selected.ToString(),
            ["html_text_context_only"]));
        return true;
    }
}
